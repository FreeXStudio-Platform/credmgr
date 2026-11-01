"""Git hooks for the CredMgr doc-system engine (pre-commit / pre-push).

These are importable, testable helpers — the shell hook is a thin wrapper that calls
``python -m tools.docgen.hooks.staged_content_scanner``. See ``staged_content_scanner`` for
the confidential/secret-header placement guard.
"""

from __future__ import annotations
