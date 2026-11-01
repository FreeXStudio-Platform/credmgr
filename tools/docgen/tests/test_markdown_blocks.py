"""Block/inline Markdown renderer — escaping, structure, and the fail-closed properties."""

from __future__ import annotations

import unittest

from tools.docgen import markdown_blocks


def _render(md: str) -> str:
    return "".join(
        markdown_blocks.render_blocks(
            md.splitlines(), on_figure=lambda _id: None, on_table=lambda _lines: "<TABLE>"
        )
    )


class TestInlineEscaping(unittest.TestCase):
    def test_document_text_can_never_emit_a_tag(self) -> None:
        out = markdown_blocks.render_inline('<script>alert("x")</script>')
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_a_code_span_is_escaped_and_not_re_scanned_for_markup(self) -> None:
        out = markdown_blocks.render_inline("`**not bold** <b>`")
        self.assertIn('<code class="t-code-inline">', out)
        self.assertNotIn("<strong>", out)
        self.assertIn("&lt;b&gt;", out)

    def test_bold_and_emphasis(self) -> None:
        self.assertIn("<strong>x</strong>", markdown_blocks.render_inline("**x**"))
        self.assertIn("<em>x</em>", markdown_blocks.render_inline("*x*"))

    def test_emphasis_does_not_fire_inside_snake_case_or_bare_asterisks(self) -> None:
        self.assertNotIn("<em>", markdown_blocks.render_inline("vault.gate_verify and entry_id"))
        self.assertNotIn("<em>", markdown_blocks.render_inline("a * b * c"))


class TestLinkAllowlist(unittest.TestCase):
    def test_https_and_relative_links_render(self) -> None:
        self.assertIn('href="https://example.com"', markdown_blocks.render_inline("[a](https://example.com)"))
        self.assertIn('href="06_ACCESS_GRAPH.md"', markdown_blocks.render_inline("[a](06_ACCESS_GRAPH.md)"))
        self.assertIn('href="#s1"', markdown_blocks.render_inline("[a](#s1)"))

    def test_dangerous_schemes_degrade_to_text_rather_than_to_a_link(self) -> None:
        for url in ("javascript:alert(1)", "data:text/html;base64,PHN2Zz4=", "file:///etc/passwd"):
            out = markdown_blocks.render_inline(f"[click]({url})")
            self.assertNotIn("<a ", out, url)
            self.assertNotIn("href", out, url)

    def test_plain_http_is_not_allowlisted(self) -> None:
        self.assertNotIn("<a ", markdown_blocks.render_inline("[a](http://example.com)"))


class TestBlocks(unittest.TestCase):
    def test_headings_h3_to_h6(self) -> None:
        out = _render("### Three\n\n#### Four\n\n##### Five\n\n###### Six")
        for level in (3, 4, 5, 6):
            self.assertIn(f"<h{level} ", out)

    def test_fenced_code_is_escaped_and_keeps_its_language(self) -> None:
        out = _render("```rust\nlet x = &y;\n```")
        self.assertIn('<pre class="doc-code" data-lang="rust">', out)
        self.assertIn("&amp;y", out)

    def test_an_unclosed_fence_still_terminates(self) -> None:
        out = _render("```\nunclosed")
        self.assertIn("doc-code", out)

    def test_unordered_and_ordered_lists(self) -> None:
        self.assertIn('<ul class="doc-list"><li>a</li><li>b</li></ul>', _render("- a\n- b"))
        self.assertIn('<ol class="doc-list"><li>a</li><li>b</li></ol>', _render("1. a\n2. b"))

    def test_nested_list_is_placed_inside_its_parent_item(self) -> None:
        out = _render("- outer\n  - inner")
        self.assertIn("<li>outer<ul", out)
        self.assertEqual(out.count("</ul>"), 2)

    def test_blockquote_wraps_rendered_blocks(self) -> None:
        out = _render("> quoted **text**")
        self.assertIn('<blockquote class="doc-quote">', out)
        self.assertIn("<strong>text</strong>", out)

    def test_horizontal_rule(self) -> None:
        self.assertIn('<hr class="doc-rule">', _render("---"))

    def test_consecutive_lines_join_into_one_paragraph(self) -> None:
        out = _render("one\ntwo\n\nthree")
        self.assertEqual(out.count('<p class="t-body">'), 2)
        self.assertIn("one two", out)

    def test_pipe_table_is_delegated_to_the_table_renderer(self) -> None:
        self.assertIn("<TABLE>", _render("| a | b |\n|---|---|\n| 1 | 2 |"))


class TestComments(unittest.TestCase):
    def test_a_metadata_comment_is_dropped_not_printed(self) -> None:
        out = _render("<!-- artifact-hardened: Approved @ abc123 -->\n\nbody")
        self.assertNotIn("artifact-hardened", out)
        self.assertIn("body", out)

    def test_a_multi_line_comment_is_fully_consumed(self) -> None:
        out = _render("<!-- line one\n     line two -->\n\nbody")
        self.assertNotIn("line two", out)
        self.assertIn("body", out)

    def test_a_figure_directive_renders_through_the_callback(self) -> None:
        blocks = markdown_blocks.render_blocks(
            ["<!-- figure:demo -->"], on_figure=lambda i: f"<FIG:{i}>", on_table=lambda _l: ""
        )
        self.assertEqual(blocks, ["<FIG:demo>"])

    def test_an_undefined_figure_directive_vanishes_rather_than_printing_itself(self) -> None:
        self.assertEqual(_render("<!-- figure:missing -->"), "")


class TestDeterminism(unittest.TestCase):
    def test_rendering_twice_is_byte_identical(self) -> None:
        md = "## S\n\n### H\n\n- a\n  - b\n\n> q\n\n```py\nx=1\n```\n\ntext `c` [l](#a)"
        self.assertEqual(_render(md), _render(md))


if __name__ == "__main__":
    unittest.main()
