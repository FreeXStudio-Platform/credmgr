"""End-to-end build behaviour: the properties a green gate does NOT prove.

Session 19 shipped a document whose figure rendered as visible escaped SVG source while every gate
reported ``ok: true`` — because no gate asserts that a figure appeared. These tests assert the
artifact, not the gate.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.docgen import components, generator, markdown_blocks

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKED_EXAMPLE = _REPO_ROOT / "docs" / "blueprints" / "session-login-mechanism.md"


@unittest.skipUnless(_WORKED_EXAMPLE.exists(), "worked example document not present")
class TestWorkedExampleBuild(unittest.TestCase):
    """Builds must go somewhere inside the repo (``_canonicalize_inside_repo``), so the temp
    directory is created under the repo root and removed again."""

    def setUp(self) -> None:
        self.out_dir = Path(tempfile.mkdtemp(prefix=".docgen-test-", dir=_REPO_ROOT))
        self.addCleanup(shutil.rmtree, self.out_dir, True)
        self.result = generator.build(_WORKED_EXAMPLE, formats=("html", "json"), out_dir=self.out_dir)

    def test_build_passes_its_gates(self) -> None:
        blocking = [f.message for f in self.result.gate.findings if f.blocking]
        self.assertEqual(blocking, [], f"unexpected blocking findings: {blocking}")

    def test_the_figure_actually_rendered_and_did_not_ship_as_escaped_source(self) -> None:
        html = self.result.outputs["html"].read_text(encoding="utf-8")
        self.assertGreaterEqual(html.count("<figure"), 1, "no figure in the rendered HTML")
        self.assertEqual(html.count("&lt;svg"), 0, "figure shipped as escaped SVG source")

    def test_json_sibling_carries_document_structure_not_just_a_build_receipt(self) -> None:
        payload = json.loads(self.result.outputs["json"].read_text(encoding="utf-8"))
        self.assertIn("document", payload)
        self.assertGreater(payload["document"]["counts"]["sections"], 0)
        self.assertIn("references", payload["document"])

    def test_building_twice_is_byte_identical(self) -> None:
        second = Path(tempfile.mkdtemp(prefix=".docgen-test-", dir=_REPO_ROOT))
        self.addCleanup(shutil.rmtree, second, True)
        again = generator.build(_WORKED_EXAMPLE, formats=("html", "json"), out_dir=second)
        for fmt in ("html", "json"):
            self.assertEqual(
                self.result.outputs[fmt].read_bytes(),
                again.outputs[fmt].read_bytes(),
                f"{fmt} build is not deterministic",
            )


class TestBodyRenderer(unittest.TestCase):
    def test_h1_is_skipped_because_the_masthead_owns_the_title(self) -> None:
        html = generator._render_markdown_body("# Title\n\n## S\n\nbody", figures={})
        self.assertNotIn("Title", html)

    def test_each_h2_opens_its_own_section(self) -> None:
        html = generator._render_markdown_body("## One\n\na\n\n## Two\n\nb", figures={})
        self.assertEqual(html.count('<section class="doc-section">'), 2)

    def test_document_text_is_never_emitted_as_live_markup(self) -> None:
        html = generator._render_markdown_body("## S\n\n<img src=x onerror=alert(1)>", figures={})
        self.assertNotIn("<img", html)


class TestDataTableBackCompat(unittest.TestCase):
    def test_default_behaviour_is_escape_only_and_unchanged(self) -> None:
        html = components.data_table(["h"], [["`x` <b>"]])
        self.assertIn("`x` &lt;b&gt;", html)
        self.assertNotIn("<code", html)

    def test_render_cell_opts_a_caller_into_inline_markup(self) -> None:
        html = components.data_table(["h"], [["`x`"]], render_cell=markdown_blocks.render_inline)
        self.assertIn('<code class="t-code-inline">x</code>', html)


if __name__ == "__main__":
    unittest.main()


class TestFenceAwareSectioning(unittest.TestCase):
    """A ``#``/``##`` line INSIDE a fenced block is code, not document structure.

    Found by a second session reviewing this renderer in flight (2026-08-18). Latent before
    fenced code existed; live the moment it did, and the corpus has 62 fences, many of them shell.
    """

    def test_a_hash_comment_inside_a_fence_survives(self) -> None:
        html = generator._render_markdown_body(
            "## S\n\n```bash\n# install the hook\nnode guard.mjs --install\n```", figures={}
        )
        self.assertIn("# install the hook", html)

    def test_a_double_hash_line_inside_a_fence_does_not_split_the_section(self) -> None:
        html = generator._render_markdown_body(
            "## Only\n\n```\n## not a heading\n```\n\nafter", figures={}
        )
        self.assertEqual(html.count('<section class="doc-section">'), 1)
        self.assertIn("## not a heading", html)
        self.assertIn("doc-code", html)

    def test_headings_outside_fences_still_split(self) -> None:
        html = generator._render_markdown_body("## A\n\n```\nx\n```\n\n## B\n\ny", figures={})
        self.assertEqual(html.count('<section class="doc-section">'), 2)


class TestMixedListNesting(unittest.TestCase):
    def test_an_ordered_child_nests_inside_an_unordered_parent(self) -> None:
        html = generator._render_markdown_body("## S\n\n- outer\n  1. inner", figures={})
        self.assertIn("<li>outer<ol", html)

    def test_an_unordered_child_nests_inside_an_ordered_parent(self) -> None:
        html = generator._render_markdown_body("## S\n\n1. outer\n   - inner", figures={})
        self.assertIn("<li>outer<ul", html)

    def test_a_same_indent_marker_change_still_starts_a_new_list(self) -> None:
        html = generator._render_markdown_body("## S\n\n- a\n\n1. b", figures={})
        self.assertIn('<ul class="doc-list">', html)
        self.assertIn('<ol class="doc-list">', html)


class TestRawSourceIsScanned(unittest.TestCase):
    """Anything the renderer DROPS must still reach the leak gates.

    `markdown_blocks` drops HTML comments as metadata. Before the raw-source scan was added, a
    secret or a real hostname inside a comment vanished before any gate saw it — it would have
    passed every gate by never being looked at. This is the regression test for that hole.
    """

    def _findings(self, md_body: str) -> list[str]:
        from tools.docgen import export_sanitizer

        normalized = export_sanitizer.normalize(md_body)
        merged = export_sanitizer.gate_secret_value(normalized).merge(
            export_sanitizer.gate_pii_path_internal(normalized)
        )
        return [f.gate for f in merged.findings if f.blocking]

    def test_a_dropped_comment_is_invisible_to_the_rendered_output(self) -> None:
        html = generator._render_markdown_body("## S\n\n<!-- 10.1.2.3 -->\n\nbody", figures={})
        self.assertNotIn("10.1.2.3", html, "precondition: the comment really is dropped")

    def test_but_the_raw_source_scan_still_catches_it(self) -> None:
        self.assertIn("pii_path_internal", self._findings("<!-- host 10.1.2.3 -->"))

    def test_a_secret_shaped_string_in_a_comment_is_caught(self) -> None:
        # Assembled at runtime on purpose: written as a literal, this exact header is what
        # `guard-no-secrets.mjs` blocks, so the test asserting the gate works would itself fail
        # the commit guard. Splitting it keeps both checks honest.
        pem = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
        self.assertTrue(self._findings(f"<!-- {pem} -->"))

    def test_clean_source_produces_no_findings(self) -> None:
        self.assertEqual(self._findings("## S\n\nordinary prose, 203.0.113.4 is documentation"), [])
