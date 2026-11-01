"""Test suite for ``tools/docgen``.

Run: ``python3 -m unittest discover -s tools/docgen/tests -t .`` from the repo root.

Stdlib ``unittest`` on purpose — ``tools/docgen`` is stdlib-only by design and no test runner is
installed in this project's environment; a suite that needs a dependency the repo does not have is
a suite nobody runs. Recorded as open work in ``tools/PROVENANCE.md`` and ``PROJECT_MAP.md §5.9``
until this directory existed: docgen's correctness rested entirely on real documents happening to
build clean, which is exactly how a renderer can mangle every document while every gate stays green
(``BUILD_LOG.md`` Session 19, trap 1).
"""
