"""Structural outline extraction — the data the JSON sibling and the link checker both rest on."""

from __future__ import annotations

import unittest

from tools.docgen import doc_outline

SAMPLE = """\
## 1. First section

Prose citing 06_ACCESS_GRAPH.md §4.2 and ADR-056, implemented in crates/brokerd/src/ops.rs.

### 1a. A subheading

<!-- figure:flow-a -->

| a | b |
|---|---|
| 1 | 2 |

## 2. Second section

More prose citing 05_THREAT_MODEL.md and ADR-056 again.

```rust
// A reference inside a fence must NOT be extracted: 99_NOT_A_DOC.md, ADR-999
let x = 1;
```
"""


class TestSections(unittest.TestCase):
    def setUp(self) -> None:
        self.out = doc_outline.extract(SAMPLE)

    def test_one_section_per_h2_in_document_order(self) -> None:
        self.assertEqual([s["title"] for s in self.out["sections"]], ["1. First section", "2. Second section"])

    def test_section_ids_are_stable_slugs(self) -> None:
        self.assertEqual(self.out["sections"][0]["id"], "1-first-section")

    def test_subheadings_attach_to_their_own_section(self) -> None:
        self.assertEqual([h["title"] for h in self.out["sections"][0]["headings"]], ["1a. A subheading"])
        self.assertEqual(self.out["sections"][1]["headings"], [])

    def test_figures_attach_to_their_own_section_and_to_the_document(self) -> None:
        self.assertEqual(self.out["sections"][0]["figures"], ["flow-a"])
        self.assertEqual(self.out["figures"], ["flow-a"])


class TestReferences(unittest.TestCase):
    def setUp(self) -> None:
        self.refs = doc_outline.extract(SAMPLE)["references"]

    def test_document_reference_captures_its_section_locator(self) -> None:
        self.assertIn({"doc": "06_ACCESS_GRAPH.md", "section": "4.2"}, self.refs["documents"])

    def test_document_reference_without_a_locator_has_no_section_key(self) -> None:
        self.assertIn({"doc": "05_THREAT_MODEL.md"}, self.refs["documents"])

    def test_adrs_are_deduped_in_document_order(self) -> None:
        self.assertEqual(self.refs["adrs"], ["ADR-056"])

    def test_code_paths_are_extracted(self) -> None:
        self.assertIn("crates/brokerd/src/ops.rs", self.refs["code"])

    def test_references_inside_a_fence_are_not_extracted(self) -> None:
        self.assertNotIn("ADR-999", self.refs["adrs"])
        self.assertNotIn({"doc": "99_NOT_A_DOC.md"}, self.refs["documents"])


class TestCounts(unittest.TestCase):
    def test_counts(self) -> None:
        counts = doc_outline.extract(SAMPLE)["counts"]
        self.assertEqual(counts, {"sections": 2, "tables": 1, "code_blocks": 1, "figures": 1})


class TestDeterminism(unittest.TestCase):
    def test_extracting_twice_is_equal(self) -> None:
        self.assertEqual(doc_outline.extract(SAMPLE), doc_outline.extract(SAMPLE))

    def test_empty_body_does_not_raise(self) -> None:
        self.assertEqual(doc_outline.extract("")["counts"]["sections"], 0)


if __name__ == "__main__":
    unittest.main()
