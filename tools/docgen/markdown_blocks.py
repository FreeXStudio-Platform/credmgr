"""Block + inline Markdown rendering for CredMgr documents.

Why this module exists
----------------------
``generator._render_markdown_body`` originally recognised exactly four constructs — ``#``/``##``
headings, GitHub pipe tables, ``<!-- figure:ID -->`` directives, and single-line paragraphs — and
passed *everything else through as escaped paragraph text*. That is fail-closed and was the right
default for the engine's first documents, but the ``v2/docs/`` corpus this project actually has to
publish uses 87 ``###``+ headings, 257 bullets, 140 ordered items, 62 fenced code blocks and 167
blockquote lines. Building it through the old renderer produced 24 documents whose structure was
visible as escaped source, and **every gate still passed** — the exact failure mode recorded as
Session 19's trap 1 ("a green gate is not a correct artifact").

So this module widens the recognised subset. It does not widen the trust model:

* **Nothing is ever emitted unescaped.** Every run of document text goes through ``escape()``.
  Tags appear in the output only where *this module* decides a construct was recognised; a
  document can never inject markup, because its own angle brackets are entities by then.
* **Raw HTML stays unsupported.** An HTML comment is dropped (it is metadata — the
  ``artifact-hardened`` stamp lives in one), and any other raw-HTML line is escaped as text.
* **Link schemes are allowlisted**, not filtered — ``https:``, ``mailto:``, in-page anchors and
  relative paths render as links; anything else (``javascript:``, ``data:``, ``file:``) renders as
  plain text with its URL shown, so a hostile link degrades to something visible rather than
  something clickable.
* **Deterministic.** No clock, no randomness, no dict ordering dependence — the engine's
  build-twice determinism contract holds.

Stdlib only, to match the rest of ``tools/docgen``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from html import escape

__all__ = ["is_fence_line", "render_blocks", "render_inline"]

# --------------------------------------------------------------------------------------
# Inline
# --------------------------------------------------------------------------------------

_CODE_SPAN_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
_STRONG_RE = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.DOTALL)
_EM_RE = re.compile(r"(?<![\w*])\*(?=[^\s*])([^*\n]+?)(?<=\S)\*(?![\w*])")

# An allowlist, deliberately. Anything not matched here is rendered as text, never as an href.
_SAFE_ABSOLUTE_URL_RE = re.compile(r"^(?:https://|mailto:|#)", re.IGNORECASE)
# A relative path/fragment: no scheme at all (no "word:" before the first slash).
_RELATIVE_URL_RE = re.compile(r"^(?![A-Za-z][A-Za-z0-9+.-]*:)[^\s]+$")


def _is_safe_url(url: str) -> bool:
    """True when ``url`` may become an ``href``. Fail-closed: unknown shapes are not safe."""
    if _SAFE_ABSOLUTE_URL_RE.match(url):
        return True
    return bool(_RELATIVE_URL_RE.match(url))


def _inline_markup(escaped: str) -> str:
    """Apply link/strong/em markup to already-escaped text.

    Runs on escaped text on purpose: ``escape()`` rewrites ``& < > "`` into entities and leaves
    ``[ ] ( ) * _ `` untouched, so the patterns below still match the author's markup while any
    markup the *author* wrote is already inert.
    """

    def _link(match: re.Match[str]) -> str:
        label, url = match.group(1), match.group(2)
        # The URL arrives escaped (e.g. "&amp;"); unescape only for the safety decision, then
        # emit the escaped form — never the raw one — as the attribute value.
        probe = url.replace("&amp;", "&")
        if not _is_safe_url(probe):
            return f"{label} ({url})"
        return f'<a class="doc-link" href="{escape(probe, quote=True)}">{label}</a>'

    out = _LINK_RE.sub(_link, escaped)
    out = _STRONG_RE.sub(r"<strong>\1</strong>", out)
    return _EM_RE.sub(r"<em>\1</em>", out)


def render_inline(text: str) -> str:
    """Escape ``text`` and render inline Markdown: code spans, links, bold, emphasis.

    Code spans are extracted *first* and their contents are only ever escaped — never scanned
    for further markup — so ``` `**not bold**` ``` stays literal, and a code span can never
    smuggle a tag.
    """
    parts: list[str] = []
    cursor = 0
    for match in _CODE_SPAN_RE.finditer(text):
        parts.append(_inline_markup(escape(text[cursor : match.start()])))
        parts.append(f'<code class="t-code-inline">{escape(match.group(1))}</code>')
        cursor = match.end()
    parts.append(_inline_markup(escape(text[cursor:])))
    return "".join(parts)


# --------------------------------------------------------------------------------------
# Blocks
# --------------------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{3,6})\s+(.*)$")
_FENCE_RE = re.compile(r"^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)\s*$")
_UL_RE = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_OL_RE = re.compile(r"^(\s*)(\d+)[.)]\s+(.*)$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
_HR_RE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")
_TABLE_DIVIDER_RE = re.compile(r"^\|[\s:|-]+\|\s*$")
_COMMENT_OPEN_RE = re.compile(r"^\s*<!--")

_HEADING_CLASS = {3: "t-h3", 4: "t-h4", 5: "t-h4", 6: "t-h4"}


def is_fence_line(line: str) -> bool:
    """True when ``line`` opens or closes a fenced code block.

    Public because ``generator``'s section splitter must track fence state too — the two must
    agree on what a fence is, or a ``##`` inside a code block splits a section that the block
    renderer then never sees the end of.
    """
    return _FENCE_RE.match(line) is not None or _fence_close(line, "```")


def _fence_close(line: str, marker: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(marker[0] * 3) and set(stripped) == {marker[0]}


def _list_item_indent(line: str) -> int:
    match = _UL_RE.match(line) or _OL_RE.match(line)
    return len(match.group(1)) if match else 0


def _render_list(lines: list[str], start: int, base_indent: int) -> tuple[str, int]:
    """Render one list (and any deeper nested lists) starting at ``lines[start]``.

    Returns the HTML and the index of the first line after the list. Nesting is by indentation:
    a following item indented further than ``base_indent`` opens a child list, which is rendered
    by recursing and is placed *inside* the current ``<li>`` — so a nested list never orphans
    itself into a sibling block.
    """
    first = lines[start]
    ordered = _OL_RE.match(first) is not None
    tag = "ol" if ordered else "ul"
    items: list[str] = []
    i = start

    while i < len(lines):
        line = lines[i]
        match = _OL_RE.match(line) if ordered else _UL_RE.match(line)
        other = _UL_RE.match(line) if ordered else _OL_RE.match(line)
        if match is None:
            if other is not None:
                # A differently-marked list at the same indent is a NEW list and ends this one;
                # one indented deeper is a child of the item just opened, and must recurse rather
                # than fall through to the break below (which rendered it as a wrongly-levelled
                # sibling — found by review 2026-08-18).
                if len(other.group(1)) > base_indent:
                    child_html, i = _render_list(lines, i, len(other.group(1)))
                    if items and items[-1].endswith("</li>"):
                        items[-1] = items[-1][: -len("</li>")] + child_html + "</li>"
                    else:
                        items.append(f"<li>{child_html}</li>")
                    continue
                break
            # A blank line only ends the list if the next content line is not a deeper item.
            if not line.strip():
                nxt = i + 1
                while nxt < len(lines) and not lines[nxt].strip():
                    nxt += 1
                if nxt < len(lines) and (_UL_RE.match(lines[nxt]) or _OL_RE.match(lines[nxt])):
                    if _list_item_indent(lines[nxt]) >= base_indent:
                        i = nxt
                        continue
                break
            break
        indent = len(match.group(1))
        if indent < base_indent:
            break
        if indent > base_indent:
            child_html, i = _render_list(lines, i, indent)
            if items and items[-1].endswith("</li>"):
                # The child list belongs INSIDE the item that opened it, not after it — an
                # `</li>`-suffixed append produces `<ul><li>a</li><ul>…</ul></ul>`, which is
                # invalid nesting and reads as a sibling list at the wrong depth.
                items[-1] = items[-1][: -len("</li>")] + child_html + "</li>"
            else:
                items.append(f"<li>{child_html}</li>")
            continue

        body = match.group(3) if ordered else match.group(2)
        continuation: list[str] = [body]
        i += 1
        # Lazy continuation: an indented, non-item line belongs to the item just opened.
        while i < len(lines):
            nxt = lines[i]
            if not nxt.strip() or _UL_RE.match(nxt) or _OL_RE.match(nxt):
                break
            if len(nxt) - len(nxt.lstrip()) <= base_indent:
                break
            continuation.append(nxt.strip())
            i += 1
        items.append(f"<li>{render_inline(' '.join(continuation))}</li>")

    return f'<{tag} class="doc-list">{"".join(items)}</{tag}>', i


def render_blocks(
    lines: list[str],
    *,
    on_figure: Callable[[str], str | None],
    on_table: Callable[[list[str]], str],
) -> list[str]:
    """Render ``lines`` (one document section's Markdown) into a list of HTML blocks.

    ``on_figure`` receives a figure id from a ``<!-- figure:ID -->`` directive and returns its
    rendered HTML, or ``None`` when no such figure is defined (the directive then vanishes rather
    than printing itself). ``on_table`` receives the raw pipe-table lines and returns HTML — both
    are injected so this module stays free of the figure/spec machinery in ``generator``.
    """
    blocks: list[str] = []
    paragraph: list[str] = []
    i = 0

    def _flush_paragraph() -> None:
        if paragraph:
            blocks.append(f'<p class="t-body">{render_inline(" ".join(paragraph))}</p>')
            paragraph.clear()

    while i < len(lines):
        line = lines[i]

        if not line.strip():
            _flush_paragraph()
            i += 1
            continue

        fence = _FENCE_RE.match(line)
        if fence:
            _flush_paragraph()
            marker, lang = fence.group(1), fence.group(2)
            body: list[str] = []
            i += 1
            while i < len(lines) and not _fence_close(lines[i], marker):
                body.append(lines[i])
                i += 1
            i += 1  # consume the closing fence (or run off the end — an unclosed fence still ends)
            lang_attr = f' data-lang="{escape(lang, quote=True)}"' if lang else ""
            code = escape("\n".join(body))
            blocks.append(f'<pre class="doc-code"{lang_attr}><code>{code}</code></pre>')
            continue

        if _COMMENT_OPEN_RE.match(line):
            _flush_paragraph()
            comment: list[str] = []
            while i < len(lines):
                comment.append(lines[i])
                if "-->" in lines[i]:
                    i += 1
                    break
                i += 1
            directive = re.search(r"<!--\s*figure:([A-Za-z0-9_-]+)\s*-->", "\n".join(comment))
            if directive:
                rendered = on_figure(directive.group(1))
                if rendered:
                    blocks.append(rendered)
            # Every other comment is document metadata (the artifact-hardened stamp lives in one)
            # and is deliberately dropped rather than printed as escaped text.
            continue

        heading = _HEADING_RE.match(line)
        if heading:
            _flush_paragraph()
            level = len(heading.group(1))
            css = _HEADING_CLASS.get(level, "t-h4")
            blocks.append(f'<h{level} class="{css}">{render_inline(heading.group(2).strip())}</h{level}>')
            i += 1
            continue

        if _HR_RE.match(line):
            _flush_paragraph()
            blocks.append('<hr class="doc-rule">')
            i += 1
            continue

        if line.strip().startswith("|") and i + 1 < len(lines) and _TABLE_DIVIDER_RE.match(lines[i + 1].strip()):
            _flush_paragraph()
            table_lines = [line]
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("|"):
                table_lines.append(lines[j])
                j += 1
            blocks.append(on_table(table_lines))
            i = j
            continue

        if _QUOTE_RE.match(line):
            _flush_paragraph()
            inner: list[str] = []
            while i < len(lines) and (_QUOTE_RE.match(lines[i]) or (inner and lines[i].strip() and not _is_block_start(lines[i]))):
                match = _QUOTE_RE.match(lines[i])
                inner.append(match.group(1) if match else lines[i].strip())
                i += 1
            nested = render_blocks(inner, on_figure=on_figure, on_table=on_table)
            blocks.append(f'<blockquote class="doc-quote">{"".join(nested)}</blockquote>')
            continue

        if _UL_RE.match(line) or _OL_RE.match(line):
            _flush_paragraph()
            html, i = _render_list(lines, i, _list_item_indent(line))
            blocks.append(html)
            continue

        paragraph.append(line.strip())
        i += 1

    _flush_paragraph()
    return blocks


def _is_block_start(line: str) -> bool:
    """True when ``line`` opens a construct that must not be swallowed by a lazy blockquote."""
    return bool(
        _HEADING_RE.match(line)
        or _FENCE_RE.match(line)
        or _HR_RE.match(line)
        or _UL_RE.match(line)
        or _OL_RE.match(line)
        or _COMMENT_OPEN_RE.match(line)
        or line.strip().startswith("|")
    )
