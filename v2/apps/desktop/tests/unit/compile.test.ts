// The build-time template compiler (scripts/dc/compile.mjs): grammar, structure, refusals, includes and error locations.
// The generated module is evaluated here with `new Function`; that is test-only code and never ships.
import { Fragment, createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { CompileError, compile, compileFile, cssToObj, encode, expandIncludes, importantify } from "../../scripts/dc/compile.mjs";
import { F, L, cx, css, h, interp } from "../../src/dc/runtime";

function run(template: string, vals: Record<string, unknown> = {}) {
  const { code, css: pseudo, bindings } = compile(template, { file: "t.html", runtimeImport: "x" });
  const body = code.replace(/^import .*$/m, "").replace("export const bindings", "const bindings").replace("export default function render", "function render");
  const render = new Function("h", "F", "L", "interp", "css", "cx", `${body}\nreturn render;`)(h, F, L, interp, css, cx);
  return { html: renderToStaticMarkup(createElement(Fragment, null, render(vals))), pseudo, bindings };
}

describe("expressions", () => {
  it("reads dotted paths, null-safe", () => {
    expect(run("<b>{{a.b.c}}</b>", { a: { b: { c: "x" } } }).html).toBe('<b><span class="sc-interp">x</span></b>');
    expect(run("<b>{{a.b.c}}</b>", { a: null }).html).toBe("<b></b>");
  });
  it("supports comparison, negation, parentheses, literals and brackets", () => {
    const t = '<sc-if value="{{(a === \'x\') }}">A</sc-if><sc-if value="{{!b}}">B</sc-if><sc-if value="{{o[k] !== 3}}">C</sc-if><sc-if value="{{n == 2}}">D</sc-if>';
    expect(run(t, { a: "x", b: 0, o: { q: 4 }, k: "q", n: 2 }).html).toBe("ABCD");
    expect(run(t, { a: "y", b: 1, o: { q: 3 }, k: "q", n: 5 }).html).toBe("");
  });
  it("renders nothing for null, undefined and booleans, an element as itself", () => {
    expect(run("<i>[{{a}}|{{b}}|{{c}}]</i>", { a: null, b: true, c: undefined }).html).toBe("<i>[||]</i>");
    expect(run("<i>{{a}}</i>", { a: createElement("u", null, "k") }).html).toBe("<i><u>k</u></i>");
  });
  it("refuses anything that is not the template grammar", () => {
    expect(() => compile("<b>{{a + b}}</b>")).toThrow(CompileError);
    expect(() => compile("<b>{{a()}}</b>")).toThrow(/unsupported syntax/);
    expect(() => compile("<b>{{ }}</b>")).toThrow(/empty expression/);
    expect(() => compile('<b title="{{alert(1)}}">x</b>')).toThrow(CompileError);
  });
});

describe("structure", () => {
  it("sc-for exposes the item and $index and copies the outer scope", () => {
    const t = '<ul><sc-for list="{{rows}}" as="r"><li>{{$index}}:{{r.n}}:{{pre}}</li></sc-for></ul>';
    const { html } = run(t, { rows: [{ n: "a" }, { n: "b" }], pre: "!" });
    expect(html.replace(/<span class="sc-interp">|<\/span>/g, "")).toBe("<ul><li>0:a:!</li><li>1:b:!</li></ul>");
  });
  it("sc-for over a non-array renders nothing; nesting works", () => {
    expect(run('<sc-for list="{{x}}" as="i"><b>1</b></sc-for>', { x: "no" }).html).toBe("");
    const t = '<sc-for list="{{a}}" as="p"><sc-for list="{{p}}" as="q"><i>{{q}}</i></sc-for></sc-for>';
    expect(run(t, { a: [[1, 2], [3]] }).html.replace(/<span class="sc-interp">|<\/span>/g, "")).toBe("<i>1</i><i>2</i><i>3</i>");
  });
  it("maps attributes: class, for, whole-value bindings, mixed strings, camelCase SVG attributes, events", () => {
    const { html } = run('<label for="f" class="a {{k}}"><svg viewBox="0 0 4 4"></svg><input id="f" value="{{v}}" onChange="{{go}}"></label>', { k: "b", v: "z", go: () => {} });
    expect(html).toBe(
      '<label for="f" class="a b"><svg viewBox="0 0 4 4"></svg><input id="f" autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck="false" value="z"/></label>',
    );
  });
  it("switches the system's autocorrect, autocapitalisation, autofill and spellcheck off on every input and textarea", () => {
    // Found in the real-app pass: macOS rewrote a typed node name ("beta" -> "Beta") so the seal confirmation never matched,
    // turned a search for "mfa" into "Mea", and offered to capitalise secret values.
    const { html } = run('<input type="password" value="{{a}}"><input><textarea value="{{b}}"></textarea><select><option>x</option></select>', { a: "", b: "" });
    const off = 'autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck="false"';
    expect(html).toContain(`<input type="password" ${off} value=""/>`);
    expect(html).toContain(`<input ${off}/>`);
    expect(html).toContain(`<textarea ${off}></textarea>`);
    expect(html).toContain("<select><option>x</option></select>");
  });
  it("keeps a value the template sets itself instead of adding a second one", () => {
    const { html } = run('<input autoComplete="one-time-code" spellcheck="true">');
    expect(html).toBe('<input autoComplete="one-time-code" spellcheck="true" autoCorrect="off" autoCapitalize="off"/>');
  });
  it("turns static style strings into objects and keeps interpolated ones dynamic", () => {
    const { html } = run('<p style="color:red;--x:1;margin-top:2px;filter:{{f}}">t</p>', { f: "none" });
    expect(html).toContain("color:red");
    expect(html).toContain("margin-top:2px");
    expect(html).toContain("filter:none");
    expect(cssToObj("a-b:c;--k-l:m")).toEqual({ aB: "c", "--k-l": "m" });
  });
  it("keeps select / table children (the HTML parser would otherwise move or drop them)", () => {
    const { html } = run('<select><sc-for list="{{o}}" as="x"><option value="{{x}}">{{x}}</option></sc-for></select><table><tbody><tr><td>c</td></tr></tbody></table>', { o: ["p", "q"] });
    expect(html).toContain("<option");
    expect(html).toContain("<td>c</td>");
    expect(encode("<select>")).toContain("sc-raw-select");
  });
  it("compiles style-hover to a class and a build-time rule with !important", () => {
    const { html, pseudo } = run('<button style-hover="background:red;color:blue">x</button>');
    expect(html).toBe('<button class="dch0">x</button>');
    expect(pseudo).toBe(".dch0:hover{background:red !important;color:blue !important}\n");
    expect(importantify("a:b !important;c:d")).toBe("a:b !important;c:d !important");
  });
  it("reports every top-level binding", () => {
    expect(run('<sc-if value="{{a}}"><sc-for list="{{b}}" as="i">{{i.c}}{{d}}</sc-for></sc-if>').bindings).toEqual(["a", "b", "d"]);
  });
});

describe("refusals (the production CSP and the no-network posture)", () => {
  for (const [what, tpl, re] of [
    ["a script element", "<script>1</script>", /not allowed/],
    ["a style element", "<style>a{}</style>", /not allowed/],
    ["a link element", '<link rel="stylesheet" href="x.css">', /not allowed/],
    ["an iframe", '<iframe src="x"></iframe>', /not allowed/],
    ["x-import", '<x-import src="a.jsx"></x-import>', /not allowed/],
    ["an image source", '<img src="https://example.com/a.png">', /would load a resource/],
    ["an external link", '<a href="https://example.com">x</a>', /only href="#"/],
    ["an event handler that is not one binding", '<b onClick="doIt()">x</b>', /exactly one/],
    ["a dynamic pseudo-class style", '<b style-hover="color:{{c}}">x</b>', /must be static/],
    ["an unknown sc- element", "<sc-wat></sc-wat>", /unknown template element/],
    ["sc-if without value", "<sc-if>x</sc-if>", /needs a value/],
  ] as const) {
    it(`refuses ${what}`, () => {
      expect(() => compile(tpl, { file: "t.html" })).toThrow(re);
    });
  }
  it("names file and line", () => {
    try {
      compile("<b>\n<i>{{a + b}}</i>\n</b>", { file: "t.html" });
      throw new Error("did not throw");
    } catch (e) {
      expect((e as Error).message).toMatch(/^t\.html:2: /);
    }
  });
});

describe("includes", () => {
  const dir = mkdtempSync(join(tmpdir(), "dc-inc-"));
  mkdirSync(join(dir, "screens"));
  writeFileSync(join(dir, "root.html"), '<div>\n<sc-include src="./screens/a.html"></sc-include>\n</div>\n');
  writeFileSync(join(dir, "screens", "a.html"), "<p>{{x}}</p>\n<p>{{y + 1}}</p>\n");

  it("inlines line for line and maps errors to the included file and its own line", () => {
    const { lines, map } = expandIncludes('<div>\n<sc-include src="./screens/a.html"></sc-include>\n</div>\n', join(dir, "root.html"));
    expect(lines.join("\n")).toBe("<div>\n<p>{{x}}</p>\n<p>{{y + 1}}</p>\n</div>\n");
    expect(map.map((m) => m.line)).toEqual([1, 1, 2, 3, 4]);
    expect(() => compileFile(join(dir, "root.html"))).toThrow(/screens\/a\.html:2: .*y \+ 1/);
  });
  it("refuses an include that is not alone on its line, a missing file and a cycle", () => {
    expect(() => expandIncludes('<b><sc-include src="./x.html"></sc-include></b>', join(dir, "root.html"))).toThrow(/line of its own/);
    expect(() => expandIncludes('<sc-include src="./nope.html"></sc-include>', join(dir, "root.html"))).toThrow(/include not found/);
    writeFileSync(join(dir, "c1.html"), '<sc-include src="./c2.html"></sc-include>');
    writeFileSync(join(dir, "c2.html"), '<sc-include src="./c1.html"></sc-include>');
    expect(() => expandIncludes('<sc-include src="./c1.html"></sc-include>', join(dir, "root.html"))).toThrow(/include cycle/);
  });
});

describe("the real design", () => {
  it("compiles to exactly 630 bindings and one build-time hover rule, from the split template", () => {
    // PINNED, measured on the merged tree (the hosting baseline was 348; the five wiring lanes moved it).  A change that adds or removes a
    // binding changes this number on purpose, in the same commit; "more than 300" let a lane drop bindings unnoticed.
    const r = compileFile("src/design/app.template.html");
    expect(new Set(r.bindings).size).toBe(r.bindings.length);
    expect(r.bindings.length).toBe(630);
    expect(r.css.split("\n").filter(Boolean).length).toBe(1);
    expect(r.files.length).toBeGreaterThan(15);
  });
});
