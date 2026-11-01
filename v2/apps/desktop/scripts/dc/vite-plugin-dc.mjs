/**
 * vite-plugin-dc - hosts the precompiled design inside Vite.
 *
 *   import render from "./design/app.template.html?dc";   // an ES module: export default function render(v)
 *   import "virtual:dc-pseudo.css";                         // the :hover rules generated from style-hover attributes
 *
 * Both are produced by compile.mjs.  The compiled template and the pseudo-class stylesheet come from the same
 * compilation, which is cached by the contents of every file that contributed (the root template and its
 * <sc-include>s), so the two virtual modules agree no matter which Vite loads first.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { compileFile, CompileError } from "./compile.mjs";
import { bannedModule } from "./release-bans.mjs";

const CSS_ID = "virtual:dc-pseudo.css";
const RESOLVED_CSS = "\0" + CSS_ID;
// The virtual id must NOT end in ".html" (Vite would treat it as an HTML entry), hence the ".js" suffix.
const TEMPLATE_PREFIX = "\0dc:";
const TEMPLATE_SUFFIX = ".js";

/**
 * @param {{ template: string, runtime: string }} options
 *   template - the root template (relative to the project root); the pseudo-class stylesheet is built from it
 *   runtime  - the module the generated code imports its helpers from (root-relative, e.g. "/src/dc/runtime.ts")
 */
export default function dc(options) {
  let root = process.cwd();
  let mode = "production";
  const cache = new Map(); // abs path -> { key, result }

  function compileCached(abs) {
    const fresh = compileFile(abs, { runtimeImport: options.runtime });
    const key = createHash("sha1")
      .update(fresh.files.map((f) => readFileSync(f, "utf8")).join("\0"))
      .digest("hex");
    const hit = cache.get(abs);
    if (hit && hit.key === key) return hit.result;
    cache.set(abs, { key, result: fresh });
    return fresh;
  }

  return {
    name: "credmgr-dc",
    enforce: "pre",
    configResolved(config) {
      root = config.root;
      mode = config.mode;
    },
    /**
     * A RELEASE bundle (every mode but "test") must not contain the demo vault or anything from tests/fixtures: fail the build, naming the
     * module, rather than ship it.  The test build carries the demo vault on purpose (the specs run on it).  `DC_ENFORCE_RELEASE_BANS=1`
     * turns the check on in any mode - the unit test uses it to prove the check can fail.
     */
    generateBundle(_outputOptions, bundle) {
      if (mode === "test" && process.env.DC_ENFORCE_RELEASE_BANS !== "1") return;
      const leaked = [];
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== "chunk") continue;
        for (const id of chunk.moduleIds || []) {
          const what = bannedModule(id);
          if (what) leaked.push(`${id} (${what})`);
        }
      }
      if (leaked.length) this.error(`a release bundle must not contain: ${leaked.join("; ")}`);
    },
    resolveId(id, importer) {
      if (id === CSS_ID) return RESOLVED_CSS;
      if (id.endsWith("?dc")) {
        const bare = id.slice(0, -3);
        const abs = bare.startsWith("/") && !bare.startsWith(root) ? resolve(root, "." + bare) : importer ? resolve(dirname(importer.replace(/^\0dc:/, "")), bare) : resolve(bare);
        return TEMPLATE_PREFIX + abs + TEMPLATE_SUFFIX;
      }
      return null;
    },
    load(id) {
      try {
        if (id === RESOLVED_CSS) {
          const r = compileCached(resolve(root, options.template));
          for (const f of r.files) this.addWatchFile(f);
          return r.css;
        }
        if (id.startsWith(TEMPLATE_PREFIX)) {
          const r = compileCached(id.slice(TEMPLATE_PREFIX.length, -TEMPLATE_SUFFIX.length));
          for (const f of r.files) this.addWatchFile(f);
          return r.code;
        }
      } catch (e) {
        if (e instanceof CompileError) this.error(e.message);
        throw e;
      }
      return null;
    },
    handleHotUpdate({ file, server }) {
      if (!/\.html$/.test(file) || !file.includes("/design/")) return;
      for (const id of [RESOLVED_CSS, ...[...server.moduleGraph.idToModuleMap.keys()].filter((k) => k.startsWith(TEMPLATE_PREFIX))]) {
        const mod = server.moduleGraph.getModuleById(id);
        if (mod) server.moduleGraph.invalidateModule(mod);
      }
      server.ws.send({ type: "full-reload" });
      return [];
    },
  };
}
