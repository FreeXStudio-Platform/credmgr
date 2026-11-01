"""The generated help and the LLM manifest must match the source and the code.

Run from the repository root:  python3 -m unittest discover -s tools/tests

`gen_help.py --check` regenerates v2/HELP.md, v2/docs/llm/credmgr-capabilities.json and
v2/apps/desktop/src/design/logic/help-data.js in memory and fails if any differs from the file on disk, or if
features.json / ops.json disagree with the code (broker operations, MCP tools, error codes, CLI commands). Asking
`credmgr mcp` for its tool list needs the CLI binary: the generator builds it with cargo when cargo is on the PATH
(GEN_HELP_NO_BUILD=1 skips that and uses an existing binary), so the first run can take a minute.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
import gen_help  # noqa: E402

CAN_RUN = bool(shutil.which("cargo")) or any(
    (REPO / "v2" / "target" / d / "credmgr").is_file() for d in ("debug", "release")
) or bool(os.environ.get("GEN_HELP_CREDMGR_BIN"))


@unittest.skipUnless(CAN_RUN, "needs cargo or a built credmgr binary to ask `credmgr mcp` for its tools")
class GeneratedHelpIsCurrent(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.facts = gen_help.Facts()
        cls.features = gen_help.load_features()
        cls.ops = gen_help.load_ops_meta()

    def test_check_passes(self) -> None:
        r = subprocess.run([sys.executable, str(REPO / "tools" / "gen_help.py"), "--check"], cwd=REPO, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

    def test_the_rules_hold_for_the_committed_source(self) -> None:
        self.assertEqual(gen_help.validate(self.features, self.ops, self.facts), [])

    def test_a_new_broker_operation_without_a_row_is_caught(self) -> None:
        ops = copy.deepcopy(self.ops)
        ops.pop("whoami")
        self.assertTrue(any("whoami" in p for p in gen_help.validate(self.features, ops, self.facts)))

    def test_an_unknown_operation_tool_or_command_in_a_feature_is_caught(self) -> None:
        for key, bad in (("broker_op", "vault.made_up"), ("mcp_tool", "credmgr_made_up"), ("cli", "credmgr madeup --x")):
            features = copy.deepcopy(self.features)
            features[0][key] = bad
            self.assertTrue(gen_help.validate(features, self.ops, self.facts), key)

    def test_agent_access_cannot_be_guessed(self) -> None:
        features = copy.deepcopy(self.features)
        row = next(f for f in features if f["mcp_tool"] == "credmgr_get")
        row["agent_access"] = "read-write within its node"  # credmgr_get needs reveal, which waits for a human
        self.assertTrue(any("agent_access" in p for p in gen_help.validate(features, self.ops, self.facts)))
        features = copy.deepcopy(self.features)
        row = next(f for f in features if f["broker_op"] == "node.policy")
        row["agent_access"] = "none"  # node.policy is on FORBIDDEN_OPS
        self.assertTrue(any("human" in p for p in gen_help.validate(features, self.ops, self.facts)))

    def test_every_forbidden_op_is_human_only_in_the_manifest(self) -> None:
        manifest = json.loads((REPO / "v2" / "docs" / "llm" / "credmgr-capabilities.json").read_text(encoding="utf-8"))
        reach = {o["op"]: o["agent_reach"] for o in manifest["broker_ops"]}
        for op in manifest["forbidden_for_agents"]["operations"]:
            if op in reach:
                self.assertEqual(reach[op], "human_only", op)
        self.assertEqual(set(manifest["agent_reachable_broker_ops"]), {t["broker_op"] for t in manifest["mcp_tools"]})
        for tool in manifest["mcp_tools"]:
            self.assertNotIn(tool["broker_op"], manifest["forbidden_for_agents"]["operations"])

    def test_the_app_bundle_data_has_nothing_the_release_build_refuses(self) -> None:
        text = (REPO / "v2" / "apps" / "desktop" / "src" / "design" / "logic" / "help-data.js").read_text(encoding="utf-8")
        for rx, label in gen_help.BUNDLE_BANNED:
            self.assertIsNone(rx.search(text), label)


if __name__ == "__main__":
    unittest.main()
