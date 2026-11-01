#!/usr/bin/env python3
"""Generate the CredMgr help from one source.

Source of truth (hand-written):

    v2/docs/help/features.json   every feature: what it is, where it is, how to use it, who may use it
    v2/docs/help/ops.json        one row per broker operation (capability, how an agent can reach it)

Outputs (generated, never edited by hand):

    v2/HELP.md                                          the readable help, one section per area
    v2/docs/llm/credmgr-capabilities.json               the manifest an AI agent reads
    v2/apps/desktop/src/design/logic/help-data.js       the data the in-app, searchable Help ships with

Everything that can be read from the code is read from the code, so a drift is a failure of ``--check``
rather than a stale sentence: the broker operations (``corpus_check.broker_ops``), the MCP tools and their
input schemas (asked of ``credmgr mcp`` itself), the forbidden operations, the error codes, the CLI
commands and the agent capabilities. Prose that cannot be read from code (what each error asks a caller to
do, what a feature is) is checked against the code for coverage: a new operation, tool, error code or CLI
command with no row fails the generator.

Run from the repository root::

    python3 tools/gen_help.py            write the three outputs
    python3 tools/gen_help.py --check    exit 1 if any output is stale or any rule below is broken

Environment: ``GEN_HELP_NO_BUILD=1`` skips ``cargo build`` and uses the newest existing ``credmgr`` binary;
``GEN_HELP_CREDMGR_BIN`` names one explicitly. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
V2 = REPO / "v2"
sys.path.insert(0, str(REPO / "tools"))
import corpus_check  # noqa: E402  (the authoritative broker-op list lives there)

FEATURES_JSON = V2 / "docs" / "help" / "features.json"
OPS_JSON = V2 / "docs" / "help" / "ops.json"
HELP_MD = V2 / "HELP.md"
MANIFEST_JSON = V2 / "docs" / "llm" / "credmgr-capabilities.json"
HELP_DATA_JS = V2 / "apps" / "desktop" / "src" / "design" / "logic" / "help-data.js"

TOOLS_RS = V2 / "crates" / "mcp" / "src" / "tools.rs"
PROTOCOL_RS = V2 / "crates" / "brokerd" / "src" / "protocol.rs"
SCOPE_RS = V2 / "crates" / "brokerd" / "src" / "scope.rs"
REGISTRY_RS = V2 / "crates" / "core" / "src" / "registry.rs"
CLI_MAIN_RS = V2 / "crates" / "cli" / "src" / "main.rs"
CARGO_TOML = V2 / "Cargo.toml"

SCHEMA_VERSION = "1.0"

AREAS = [
    ("first-run", "First run and recovery"),
    ("unlock", "Unlocking, locking and the menu-bar icon"),
    ("navigation", "Graph, tree and search"),
    ("nodes", "Projects and nodes"),
    ("entries", "Entries and notes"),
    ("fields", "Fields, reveal and copy"),
    ("totp", "Authenticator codes you store"),
    ("two-factor", "The vault's second factor"),
    ("approvals", "Agent requests while locked"),
    ("pending", "Writes made while locked"),
    ("grants", "Grants"),
    ("sealing", "Sealing and restoring"),
    ("audit", "Audit"),
    ("backup", "Backup, checks and maintenance"),
    ("import", "Importing"),
    ("settings", "Settings"),
    ("extras", "Cosmetics, games and donations"),
    ("agents", "AI agents and the MCP server"),
    ("cli", "Command line and broker"),
    ("shortcuts", "Keyboard shortcuts"),
    ("about", "About, privacy and licence"),
    ("not-built", "Planned, not in this build"),
]
AREA_IDS = [a for a, _ in AREAS]
AREA_TITLE = dict(AREAS)

STATUSES = ("built", "partial", "planned")
AGENT_ACCESS = ("none", "read-only metadata", "read with approval", "read-write within its node", "human only")
FEATURE_KEYS = ("id", "title", "area", "summary", "where", "steps", "keywords", "status", "cli", "broker_op", "mcp_tool", "agent_access")
AGENT_REACH = ("mcp", "capability_only", "human_only", "bootstrap")

# What an agent_access value means, spelled out in the manifest.
AGENT_ACCESS_MEANING = {
    "none": "No agent path. The feature is part of the app or the command line and an agent has no tool for it, or it is not relevant to an agent.",
    "read-only metadata": "An agent can use it through an MCP tool to learn names, ids, labels, types, counts or its own boundary. No secret value is returned.",
    "read with approval": "An agent can ask for secret values through an MCP tool. The broker answers at once only when the vault and node are unlocked and the node asks for no second factor; otherwise the request waits for a human (approval_pending or two_factor_required).",
    "read-write within its node": "An agent can create or change data through an MCP tool, only inside the node it is scoped to, subject to that node's agent-access policy. Changes are audited, generation-checked and undoable.",
    "human only": "Only a person can do this. An agent has no tool for it and the broker refuses an agent-origin caller.",
}
# The capability an MCP tool needs decides the agent_access a feature that names it may claim.
CAPABILITY_TO_AGENT_ACCESS = {
    "none": "read-only metadata",
    "list": "read-only metadata",
    "read": "read-only metadata",
    "reveal": "read with approval",
    "create": "read-write within its node",
    "update": "read-write within its node",
}

# Words the release build refuses anywhere in its bundle (scripts/dc/release-bans.mjs, verify-build.mjs).
BUNDLE_BANNED = [
    (re.compile(r"mock", re.I), "the word 'mock'"),
    (re.compile(r"not built", re.I), "the phrase 'not built' (tests/unit/architecture.test.ts bans it under src/)"),
    (re.compile(r"\bnot\s+(?:wired|implemented|available yet)\b|\bnot\s+yet\s+(?:built|wired|implemented)\b|\bplaceholder data\b|\bTODO\b|\bstub(?:bed)?\b", re.I), "wording tests/e2e/no-mock-badges.spec.ts reads as 'not real'"),
    (re.compile(r"fixture", re.I), "the word 'fixture'"),
    (re.compile(r"browser preview|preview has no broker", re.I), "browser-preview wording"),
    (re.compile(r"https?://"), "an http(s) URL"),
    (re.compile(r"(^|[^A-Za-z0-9_$.])eval\s*\("), "eval("),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function("),
]

DISCLAIMER_MD = "<!-- artifact-hardened: NEEDS RE-HARDENING — generated 2026-10-31 -->"


class GenError(Exception):
    pass


# --------------------------------------------------------------------------------------------- code readers


def _read(path: Path) -> str:
    if not path.is_file():
        raise GenError(f"{path.relative_to(REPO)} not found")
    return path.read_text(encoding="utf-8")


def product_version() -> str:
    m = re.search(r"^\[workspace\.package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", _read(CARGO_TOML), re.M | re.S)
    if not m:
        raise GenError("workspace version not found in v2/Cargo.toml")
    return m.group(1)


def mcp_registry_source() -> list[dict]:
    """[{name, op}] in registry order, read from tools.rs."""
    text = _read(TOOLS_RS)
    start = text.index("pub fn registry()")
    end = text.index("pub const FORBIDDEN_OPS")
    pairs = re.findall(r'name:\s*"(credmgr_[a-z_]+)".*?op:\s*"([a-z_.]+)"', text[start:end], re.S)
    if not pairs:
        raise GenError("no MCP tools found in tools.rs")
    return [{"name": n, "op": o} for n, o in pairs]


def forbidden_ops() -> list[str]:
    text = _read(TOOLS_RS)
    m = re.search(r"pub const FORBIDDEN_OPS: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not m:
        raise GenError("FORBIDDEN_OPS not found in tools.rs")
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return re.findall(r'"([a-z_.]+)"', body)


def tools_consts() -> dict[str, list[str]]:
    text = _read(TOOLS_RS)
    out = {}
    for const in ("FIELD_TYPE_NAMES", "ENTRY_TYPE_NAMES", "SENSITIVITY_NAMES"):
        m = re.search(rf"pub const {const}: &\[&str\] = &\[(.*?)\];", text, re.S)
        if not m:
            raise GenError(f"{const} not found in tools.rs")
        out[const] = re.findall(r'"([a-z-]+)"', m.group(1))
    return out


def error_codes() -> list[str]:
    codes = re.findall(r'"ok":\s*false,\s*"error":\s*"([a-z_]+)"', _read(PROTOCOL_RS))
    seen: list[str] = []
    for c in codes:
        if c not in seen:
            seen.append(c)
    if not seen:
        raise GenError("no error codes found in protocol.rs")
    return seen


def capabilities() -> list[str]:
    m = re.search(r"pub enum Capability \{(.*?)\}", _read(REGISTRY_RS), re.S)
    if not m:
        raise GenError("Capability enum not found")
    return [v.lower() for v in re.findall(r"^\s*([A-Z][A-Za-z]+),", m.group(1), re.M)]


def agent_access_capabilities() -> dict[str, list[str]]:
    text = _read(SCOPE_RS)
    m = re.search(r"fn capabilities_for_agent_access\(.*?\n\}\n", text, re.S)
    if not m:
        raise GenError("capabilities_for_agent_access not found")
    body = m.group(0)
    out = {}
    for variant, key in (("ReadWrite", "read-write"), ("ReadOnly", "read-only"), ("None", "none")):
        am = re.search(rf"AgentAccess::{variant}\s*=>\s*(?:vec!\[(.*?)\]|vec!\[\])", body, re.S)
        out[key] = [c.lower() for c in re.findall(r"Capability::([A-Za-z]+)", am.group(1) or "")] if am else []
    return out


def cli_top_level() -> list[str]:
    text = _read(CLI_MAIN_RS)
    start = text.index("fn run(")
    end = text.index("\nfn ", start + 5)
    names = re.findall(r'^\s{8}"([a-z]+)"\s*=>', text[start:end], re.M)
    return [n for n in names if n != "help"]


def _rust_unescape(lit: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        n = lit[i + 1]
        if n == "\n":
            i += 2
            while i < len(lit) and lit[i] in " \t":
                i += 1
        elif n == "n":
            out.append("\n")
            i += 2
        elif n == "x":
            out.append(chr(int(lit[i + 2 : i + 4], 16)))
            i += 4
        else:
            out.append(n)
            i += 2
    return "".join(out)


def cli_usage_lines() -> list[str]:
    """One usage string per command form, from the help text compiled into the CLI."""
    text = _read(CLI_MAIN_RS)
    start = text.index("fn print_usage()")
    q = text.index('"', text.index("println!(", start))
    j = q + 1
    while text[j] != '"' or text[j - 1] == "\\":
        j += 1
    help_text = _rust_unescape(text[q + 1 : j])
    cmds: list[str] = []
    for line in help_text.split("\n"):
        if line.startswith("  credmgr "):
            cmds.append(re.split(r"\s{2,}\(", line.strip())[0].strip())
        elif cmds and line.startswith(" " * 20) and line.strip().startswith("["):
            cmds[-1] += " " + re.split(r"\s{2,}\(", line.strip())[0].strip()
    if not cmds:
        raise GenError("no usage lines found in the CLI help text")
    return cmds


def find_cli_binary() -> Path:
    explicit = os.environ.get("GEN_HELP_CREDMGR_BIN")
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise GenError(f"GEN_HELP_CREDMGR_BIN={explicit} is not a file")
        return p
    if shutil.which("cargo") and os.environ.get("GEN_HELP_NO_BUILD") != "1":
        base = ["cargo", "build", "-q", "-p", "credmgr-cli", "--locked"]
        r = subprocess.run(base + ["--offline"], cwd=V2, capture_output=True, text=True)
        if r.returncode != 0:
            r = subprocess.run(base, cwd=V2, capture_output=True, text=True)
        if r.returncode != 0:
            raise GenError("cargo build -p credmgr-cli failed:\n" + r.stderr[-1500:])
        return V2 / "target" / "debug" / "credmgr"
    found = [p for p in (V2 / "target" / "debug" / "credmgr", V2 / "target" / "release" / "credmgr") if p.is_file()]
    if not found:
        raise GenError("no credmgr binary and no cargo: set GEN_HELP_CREDMGR_BIN or build v2/crates/cli")
    return max(found, key=lambda p: p.stat().st_mtime)


def mcp_tools_from_binary() -> list[dict]:
    """tools/list as answered by `credmgr mcp` itself. It needs no broker."""
    binary = find_cli_binary()
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    r = subprocess.run(
        [str(binary), "mcp"],
        input="\n".join(json.dumps(x) for x in requests) + "\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    for line in r.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == 2 and "result" in msg:
            return msg["result"]["tools"]
    raise GenError("credmgr mcp did not answer tools/list:\n" + (r.stderr or r.stdout)[-800:])


# --------------------------------------------------------------------------------------------- the model


class Facts:
    """Everything read from the code, gathered once."""

    def __init__(self) -> None:
        self.version = product_version()
        self.broker_ops = sorted(corpus_check.broker_ops())
        self.registry = mcp_registry_source()
        self.tool_names = [t["name"] for t in self.registry]
        self.tool_op = {t["name"]: t["op"] for t in self.registry}
        self.op_tool = {t["op"]: t["name"] for t in self.registry}
        self.forbidden = forbidden_ops()
        self.consts = tools_consts()
        self.error_codes = error_codes()
        self.capabilities = capabilities()
        self.agent_caps = agent_access_capabilities()
        self.cli_top = cli_top_level()
        self.cli_usage = cli_usage_lines()
        listed = mcp_tools_from_binary()
        if [t["name"] for t in listed] != self.tool_names:
            raise GenError(
                "the credmgr binary lists different MCP tools than tools.rs: "
                f"binary {[t['name'] for t in listed]} vs source {self.tool_names}. Rebuild it."
            )
        self.tools = listed


def load_features() -> list[dict]:
    try:
        data = json.loads(_read(FEATURES_JSON))
    except ValueError as e:
        raise GenError(f"features.json is not valid JSON: {e}")
    if not isinstance(data, list):
        raise GenError("features.json must be an array")
    return data


def load_ops_meta() -> dict:
    try:
        data = json.loads(_read(OPS_JSON))
    except ValueError as e:
        raise GenError(f"ops.json is not valid JSON: {e}")
    return data["ops"]


# --------------------------------------------------------------------------------------------- validation

ERROR_ADVICE = {
    "node_access_denied": ("Authorisation", "Stop. The remedy field names the human action that would allow it (usually a grant). Tell the operator what you need and why in one sentence, and carry on with other work. Do not retry or rephrase."),
    "capability_not_held": ("Authorisation", "Your scope does not carry this capability. Stop and ask the operator; no argument changes it."),
    "two_factor_required": ("Authentication in progress", "The node asks for a second factor and none is in force. A person must give a code (an elevation lasts five minutes for the whole vault). Ask the operator, then retry once after they confirm. Do not ask for the code yourself."),
    "approval_pending": ("Authentication in progress", "The vault is locked and the operator has been asked. The request id and the seconds left are in the answer. Wait or do other work; a person decides with the passphrase. Retry the identical request after they say they decided, within 120 seconds. Do not poll in a loop."),
    "wrong_passphrase": ("Authentication failed", "Not an agent concern: unlock is a human step. Tell the operator."),
    "gate_verification_failed": ("Authentication failed", "A code was wrong, replayed, expired or already used; the broker does not say which. Stop and tell the operator."),
    "gate_not_enrolling": ("Authentication failed", "No second-factor enrolment is in progress. A human step; tell the operator."),
    "approval_denied": ("Authentication failed", "The operator denied the request, it expired after 120 seconds, or the vault locked after it was approved. Do not retry unprompted; ask the operator whether to ask again."),
    "rate_limited": ("Authentication failed", "Too many wrong attempts. retryAfterSeconds says how long to wait. Do not retry in a loop."),
    "vault_locked": ("Lock state", "The whole vault is locked. Only entry creation (held for review) is allowed. Do other work or ask the operator to unlock; do not retry in a loop."),
    "node_locked": ("Lock state", "The vault is unlocked but this one node is locked. Ask the operator to unlock the node; the remedy field says how."),
    "session_expired": ("Session ended", "The token presented is not a live login. Do not retry with it. An agent using MCP should not hold a token; tell the operator."),
    "presence_required": ("Transport not capable", "This needs a live presence check that no client of this build can give. Nothing can be done here; tell the operator it is a human, native-app action."),
    "conflict": ("Concurrency", "Someone changed the entry first. Read it again (credmgr_get_metadata for the new generation), re-apply the change and retry once."),
    "not_found": ("Data state", "No such node, entry, field or request. Check ids with credmgr_list and credmgr_get_metadata."),
    "entry_exists": ("Data state", "That name is already used on the node, or is a look-alike of one that is. Choose another name or update the existing entry."),
    "archive_expired": ("Data state", "The seven-day restore window of a sealed node has passed. Terminal; tell the operator."),
    "entry_removal_expired": ("Data state", "The seven-day recovery window of a removed entry has passed. Terminal."),
    "not_undoable": ("Data state", "That audit record cannot be undone (wrong action, denied, or too old). Nothing to do."),
    "vault_already_initialized": ("Vault bootstrap", "A vault already exists. Not an agent concern."),
    "vault_inside_git_working_tree": ("Vault bootstrap", "The vault folder is inside a git working tree and is refused. Not an agent concern."),
    "vault_init_not_pending": ("Vault bootstrap", "No vault creation is in progress. Not an agent concern."),
    "recovery_code_mismatch": ("Vault bootstrap", "The retyped recovery code did not match. Not an agent concern."),
    "malformed_request": ("Caller error", "Fix the request. The message names the problem (an index or field id, never a value). Check the tool's input schema."),
    "internal": ("Broker fault", "A local failure outside the documented errors. Do not retry in a loop; tell the operator."),
}

# Plain-language forbidden list, restated from docs/10_API_AND_MCP.md section 3.2 (the op names come from code).
FORBIDDEN_PLAIN = [
    "Create or change a grant (a grant is how a human lets one node see into another).",
    "Read the Orphaned node (sealed data). It is absent from the tools, not merely gated.",
    "Read a TOTP seed. credmgr_totp_code gives the current six digits only.",
    "Change a node's policy or agent access, rename a node, re-parent a node, or change its work folders. An agent may not widen its own scope.",
    "List nodes outside its scope. credmgr_whoami names only reachable nodes.",
    "Purge or shorten the audit log, or shorten the seven-day recovery windows.",
    "Read across nodes by any parameter: there is no node override, no 'all', no 'include inherited'.",
    "Reach raw envelopes, keys or file paths.",
    "Run vault-wide maintenance: verify, doctor, backup.",
    "Rotate the root key.",
    "Enrol, replace or recover the vault's second factor.",
]

HOW_TO_READ = [
    ("Learn your own boundary before anything else", "credmgr_whoami", "Returns your node, capabilities and the nodes you can reach. It names nothing else."),
    ("List the entries of a node", "credmgr_list", "Names and ids only. 'node' is required: use the one credmgr_whoami returned."),
    ("Find an entry by name", "credmgr_search", "Substring match over entry names in your scope. A term that only matches outside your scope looks identical to no match."),
    ("See an entry's fields without any value", "credmgr_get_metadata", "Field ids, labels, types and masking, plus the entry's generation. Needs the vault and node unlocked. Use the ids with the tools below."),
    ("Read a secret value", "credmgr_get", "Pass fieldIds to read only some fields. The answer has 'fields' and, when exactly one field is returned, 'value'. A stored authenticator seed comes back with its value removed; use credmgr_totp_code. May answer approval_pending or two_factor_required: wait for the human."),
    ("Get the current authenticator code for a stored seed", "credmgr_totp_code", "Six digits valid for about thirty seconds. Pass 'field' when the entry holds several fields."),
    ("See what changed recently", "credmgr_recent_changes", "A redacted feed of id, action, time and actor. The ids are what credmgr_undo takes."),
]
HOW_TO_WRITE = [
    ("Create a new entry", "credmgr_create", "Send either 'value' (with an optional 'label') or a 'fields' array of {label, value}. Send structure: the broker does not parse 'label: value' text. On a locked vault the entry is held in a review tray for the human; tell the operator it is waiting."),
    ("Replace one field's value or the whole field list", "credmgr_update", "Needs the entry's current 'generation' (from credmgr_get_metadata). With several fields, name the field with 'field'. Keeps no history."),
    ("Replace a secret and keep the old one", "credmgr_rotate", "Same body as credmgr_update; the previous value is kept as history."),
    ("Add fields to an entry", "credmgr_field_add", "Appended, or inserted at 'position'. Never replaces."),
    ("Change one field's label, value, type or masking", "credmgr_field_update", "Pass a 'patch' with at least one key. 'auto' goes back to inferring a type or masking."),
    ("Remove one field", "credmgr_field_remove", "The last field cannot be removed; remove the entry instead."),
    ("Remove an entry", "credmgr_remove", "Soft delete into a seven-day recovery window."),
    ("Undo a rotation, field change or removal", "credmgr_undo", "Address it by the audit record id from credmgr_recent_changes. Itself an audited action."),
]


def validate(features: list[dict], ops_meta: dict, facts: Facts) -> list[str]:
    problems: list[str] = []
    ids: set[str] = set()
    titles: set[str] = set()
    tools_used: set[str] = set()
    ops_used: set[str] = set()
    cli_used: set[str] = set()
    forbidden = set(facts.forbidden)

    broker = set(facts.broker_ops)
    meta_keys = set(ops_meta)
    for op in sorted(broker - meta_keys):
        problems.append(f"ops.json has no row for broker operation {op}")
    for op in sorted(meta_keys - broker):
        problems.append(f"ops.json names {op}, which the broker does not dispatch")
    for op, row in ops_meta.items():
        if row.get("agent_reach") not in AGENT_REACH:
            problems.append(f"ops.json {op}: agent_reach must be one of {AGENT_REACH}")
        for k in ("capability", "summary"):
            if not row.get(k):
                problems.append(f"ops.json {op}: missing {k}")
    for op, tool in facts.op_tool.items():
        row = ops_meta.get(op)
        if row and row.get("agent_reach") != "mcp":
            problems.append(f"ops.json {op}: has MCP tool {tool}, so agent_reach must be 'mcp'")
    for op, row in ops_meta.items():
        if row.get("agent_reach") == "mcp" and op not in facts.op_tool:
            problems.append(f"ops.json {op}: says mcp but no MCP tool maps to it")
    for op in forbidden:
        row = ops_meta.get(op)
        if row and row.get("agent_reach") not in ("human_only",):
            problems.append(f"ops.json {op}: it is on FORBIDDEN_OPS, so agent_reach must be human_only")

    for n, f in enumerate(features):
        where = f"features.json #{n} ({f.get('id', '?')})"
        extra = set(f) - set(FEATURE_KEYS)
        missing = [k for k in FEATURE_KEYS if k not in f]
        if extra or missing:
            problems.append(f"{where}: keys differ (missing {missing}, extra {sorted(extra)})")
            continue
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", f["id"]):
            problems.append(f"{where}: id must be kebab-case")
        if f["id"] in ids:
            problems.append(f"{where}: duplicate id")
        ids.add(f["id"])
        if f["title"] in titles:
            problems.append(f"{where}: duplicate title {f['title']!r}")
        titles.add(f["title"])
        if f["area"] not in AREA_IDS:
            problems.append(f"{where}: unknown area {f['area']!r}")
        if f["status"] not in STATUSES:
            problems.append(f"{where}: status must be one of {STATUSES}")
        if f["agent_access"] not in AGENT_ACCESS:
            problems.append(f"{where}: agent_access must be one of {AGENT_ACCESS}")
        for k in ("title", "summary", "where"):
            if not isinstance(f[k], str) or not f[k].strip():
                problems.append(f"{where}: {k} must be a non-empty string")
        if not (isinstance(f["steps"], list) and f["steps"] and all(isinstance(s, str) and s for s in f["steps"])):
            problems.append(f"{where}: steps must be a non-empty list of strings")
        if not (isinstance(f["keywords"], list) and f["keywords"] and all(isinstance(s, str) and s for s in f["keywords"])):
            problems.append(f"{where}: keywords must be a non-empty list of strings")
        if f["area"] == "not-built" and f["status"] != "planned":
            problems.append(f"{where}: everything in 'not-built' is status planned")
        if f["status"] == "planned" and f["area"] != "not-built" and "Not available" not in f["steps"][0] and "Not available" not in f["where"] and "refused" not in f["where"]:
            problems.append(f"{where}: a planned feature must say in steps or where that it is not available")

        if f["cli"] is not None:
            parts = f["cli"].split()
            if len(parts) < 2 or parts[0] != "credmgr":
                problems.append(f"{where}: cli must start with 'credmgr <command>'")
            else:
                cmd = parts[1]
                if cmd not in facts.cli_top and cmd not in ("help", "--version"):
                    problems.append(f"{where}: cli command {cmd!r} is not a command in crates/cli/src/main.rs")
                cli_used.add(cmd)
        op = f["broker_op"]
        if op is not None:
            if op not in broker:
                problems.append(f"{where}: broker_op {op!r} is not dispatched by ops.rs")
            ops_used.add(op)
        tool = f["mcp_tool"]
        if tool is not None:
            if tool not in facts.tool_names:
                problems.append(f"{where}: mcp_tool {tool!r} is not registered in tools.rs")
            tools_used.add(tool)

        # agent_access is derived from code and policy, not guessed
        if tool in facts.tool_op:
            cap = ops_meta.get(facts.tool_op[tool], {}).get("capability", "none")
            expected = CAPABILITY_TO_AGENT_ACCESS.get(cap)
            if expected and f["agent_access"] != expected:
                problems.append(f"{where}: uses {tool} (needs {cap}), so agent_access must be {expected!r}, not {f['agent_access']!r}")
        elif op is not None:
            reach = ops_meta.get(op, {}).get("agent_reach")
            if (op in forbidden or reach == "human_only") and f["agent_access"] != "human only":
                problems.append(f"{where}: {op} is human-only for agents, so agent_access must be 'human only'")
        if tool is None and f["agent_access"] in ("read-only metadata", "read with approval", "read-write within its node") and op is None:
            problems.append(f"{where}: claims agent access {f['agent_access']!r} with no mcp_tool or broker_op to back it")

    for tool in facts.tool_names:
        if tool not in tools_used:
            problems.append(f"MCP tool {tool} is named by no feature")
    for op in facts.broker_ops:
        if op not in ops_used and ops_meta.get(op, {}).get("agent_reach") != "bootstrap" and op not in ("graph.snapshot", "node.list", "entry.restore", "vault.pending_discard"):
            problems.append(f"broker operation {op} is named by no feature")
    for cmd in facts.cli_top:
        if cmd not in cli_used:
            problems.append(f"CLI command {cmd} is named by no feature")

    # error-code prose covers the code, exactly
    for code in facts.error_codes:
        if code not in ERROR_ADVICE:
            problems.append(f"error code {code} (protocol.rs) has no entry in ERROR_ADVICE")
    for code in ERROR_ADVICE:
        if code not in facts.error_codes:
            problems.append(f"ERROR_ADVICE names {code}, which protocol.rs no longer returns")
    for _, tool, _ in HOW_TO_READ + HOW_TO_WRITE:
        if tool not in facts.tool_names:
            problems.append(f"how_to names {tool}, which is not a registered tool")
    for tool in facts.tool_names:
        if tool not in {t for _, t, _ in HOW_TO_READ + HOW_TO_WRITE}:
            problems.append(f"MCP tool {tool} is in neither HOW_TO_READ nor HOW_TO_WRITE")

    # counts quoted in prose must match the code
    for f in features:
        for m in re.finditer(r"\b(\d+) (?:MCP )?tools\b", f["summary"] + " " + f["where"]):
            if int(m.group(1)) != len(facts.tool_names):
                problems.append(f"features.json {f['id']}: says {m.group(0)!r} but tools.rs registers {len(facts.tool_names)}")

    for f in features:
        blob = json.dumps(f)
        for rx, label in BUNDLE_BANNED:
            if rx.search(blob):
                problems.append(f"features.json {f.get('id', '?')}: contains {label}, which the release bundle refuses")
        if re.search(r"[\U0001F000-\U0001FFFF☀-➿]", blob):
            problems.append(f"features.json {f.get('id', '?')}: contains an emoji")
    return problems


# --------------------------------------------------------------------------------------------- outputs


def slug(title: str, seen: dict[str, int]) -> str:
    s = re.sub(r"[^a-z0-9 \-]", "", title.lower()).strip().replace(" ", "-")
    n = seen.get(s, 0)
    seen[s] = n + 1
    return s if n == 0 else f"{s}-{n}"


AGENT_SENTENCE = {
    "none": None,
    "read-only metadata": "An AI agent can use this through MCP to read names, ids and labels, never a value.",
    "read with approval": "An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.",
    "read-write within its node": "An AI agent can do this through MCP, only inside the node it is scoped to.",
    "human only": "Only you can do this. An AI agent cannot.",
}
STATUS_LABEL = {"built": None, "partial": "Partly working", "planned": "Planned"}


def render_help_md(features: list[dict], facts: Facts) -> str:
    by_area: dict[str, list[dict]] = {a: [] for a in AREA_IDS}
    for f in features:
        by_area[f["area"]].append(f)
    seen: dict[str, int] = {}
    out: list[str] = []
    out.append(DISCLAIMER_MD)
    out.append("")
    out.append("# CredMgr help")
    out.append("")
    out.append(f"What CredMgr {facts.version} can do, and where to find each thing: which screen, button, menu, shortcut or command.")
    out.append("")
    out.append(
        "This file is generated from `docs/help/features.json` by `tools/gen_help.py`; edit that file, never this one. "
        "The desktop app's Help (the **?** button in the header) holds the same list with a search box. "
        "An AI agent should read `docs/llm/credmgr-capabilities.json` instead."
    )
    out.append("")
    out.append(
        "Topics marked **Partly working** work in some places and not others; **Planned** ones are listed so you know they are missing, "
        "and nothing here describes them as working."
    )
    out.append("")
    out.append("## Contents")
    out.append("")
    out.append("| Section | Topics |")
    out.append("|---|---|")
    area_slugs = {}
    for a, t in AREAS:
        area_slugs[a] = slug(t, seen)
        out.append(f"| [{t}](#{area_slugs[a]}) | {len(by_area[a])} |")
    out.append("")
    out.append(f"{len(features)} topics in {len(AREAS)} sections.")
    out.append("")
    for a, t in AREAS:
        out.append(f"## {t}")
        out.append("")
        for f in by_area[a]:
            slug(f["title"], seen)
            out.append(f"### {f['title']}")
            out.append("")
            lab = STATUS_LABEL[f["status"]]
            if lab:
                out.append(f"*{lab}.*")
                out.append("")
            out.append(f["summary"])
            out.append("")
            out.append(f"- **Where:** {f['where']}")
            if len(f["steps"]) == 1:
                out.append(f"- **How:** {f['steps'][0]}")
            else:
                out.append("- **How:**")
                for i, s in enumerate(f["steps"], 1):
                    out.append(f"  {i}. {s}")
            if f["cli"]:
                out.append(f"- **Command line:** `{f['cli']}`")
            sentence = AGENT_SENTENCE[f["agent_access"]]
            if sentence:
                out.append(f"- **AI agents:** {sentence}")
            out.append(f"- **Also searched as:** {', '.join(f['keywords'])}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_help_data(features: list[dict]) -> str:
    lines = [
        "/* GENERATED by tools/gen_help.py from v2/docs/help/features.json. Do not edit by hand; run `python3 tools/gen_help.py`.",
        "   The in-app Help (help.js) searches this data. It ships with the app: nothing is fetched, nothing is sent anywhere.",
        "   `tools/gen_help.py --check` fails if this file is out of date. */",
        "",
        "export const HELP_AREAS = [",
    ]
    for i, (a, t) in enumerate(AREAS):
        lines.append("  " + json.dumps({"id": a, "title": t}, ensure_ascii=True) + ("," if i < len(AREAS) - 1 else ""))
    lines.append("];")
    lines.append("")
    lines.append("export const HELP_FEATURES = [")
    for i, f in enumerate(features):
        rec = {k: f[k] for k in ("id", "title", "area", "summary", "where", "steps", "keywords", "status", "cli")}
        lines.append("  " + json.dumps(rec, ensure_ascii=True) + ("," if i < len(features) - 1 else ""))
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def build_manifest(features: list[dict], ops_meta: dict, facts: Facts) -> dict:
    tools = {t["name"]: t for t in facts.tools}
    read_tools = {t for _, t, _ in HOW_TO_READ}

    def tool_entry(name: str) -> dict:
        op = facts.tool_op[name]
        cap = ops_meta[op]["capability"]
        return {
            "name": name,
            "broker_op": op,
            "capability_needed": cap,
            "agent_access": CAPABILITY_TO_AGENT_ACCESS.get(cap, "read-only metadata"),
            "description": tools[name]["description"],
            "input_schema": f"see {'how_to_read' if name in read_tools else 'how_to_write'}: the schema is given once, beside the task",
        }

    def how(rows):
        return [
            {"task": task, "use_tool": tool, "notes": note, "input_schema": tools[tool]["inputSchema"]}
            for task, tool, note in rows
        ]

    broker_ops = []
    for op in facts.broker_ops:
        row = ops_meta[op]
        entry = {
            "op": op,
            "capability_needed": row["capability"],
            "agent_reach": row["agent_reach"],
            "mcp_tool": facts.op_tool.get(op),
            "summary": row["summary"],
        }
        broker_ops.append(entry)
    reachable = [o["op"] for o in broker_ops if o["agent_reach"] == "mcp"]

    errors = [
        {"code": c, "class": ERROR_ADVICE[c][0], "what_to_do": ERROR_ADVICE[c][1]} for c in facts.error_codes
    ]
    feats = []
    for f in features:
        feats.append({k: f[k] for k in FEATURE_KEYS} | {"area_title": AREA_TITLE[f["area"]]})

    counts = {a: sum(1 for f in features if f["area"] == a) for a in AREA_IDS}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "tools/gen_help.py from v2/docs/help/features.json and v2/docs/help/ops.json; checked against the code with `python3 tools/gen_help.py --check`. Do not edit by hand.",
        "product": {
            "name": "CredMgr",
            "summary": "A local, offline credential vault for macOS. Secrets are organised into nodes (projects); every access decision is made by one local process, the broker (credmgrd). The desktop app, the command line and the MCP server are all clients of it.",
            "publisher": "FreexStudio",
            "platform": "macOS on Apple Silicon only",
            "network": "No network listener and no outbound connection.",
        },
        "version": facts.version,
        "status": f"{facts.version} pre-release",
        "release_state": "No release has been published. Unsigned, not notarised, Software keystore tier (the passphrase is the key; no Secure Enclave, no Touch ID).",
        "licence": {
            "name": "FreexStudio Source-Available Licence",
            "pointer": "v2/LICENSE",
            "summary": "Source-available, not open source: you may run the current stable release and read and audit the source; you may not fork, modify or redistribute it.",
        },
        "how_to_use_this_file": [
            "You are an AI agent (or you are configuring one) that works with a CredMgr vault. Read safety_model and never first.",
            "Use only the MCP tools in mcp_tools. Do not talk to the broker socket, read the vault folder, run credmgr unlock, or ask the user for their passphrase, recovery code or authenticator code.",
            "Start with credmgr_whoami, then use how_to_read and how_to_write for the task.",
            "When a result is an error, find its code in error_codes and do what it says. Refusals are explicit: tell the operator what you need, in one sentence, and carry on with other work.",
            "features describes everything the product can do for a human, where it is, and (agent_access) what an agent may do with it. Anything with status 'planned' does not exist yet; do not rely on it.",
        ],
        "safety_model": {
            "values_stay_in_the_broker": "Secret values are encrypted at rest and decrypted only inside the broker. A value leaves the broker only as the answer to one identified, authorised, logged request. The product makes no outbound network connection, so a value cannot be sent anywhere by CredMgr itself.",
            "one_enforcement_point": "The broker (credmgrd) decides every access. The desktop app, the CLI and the MCP server are thin clients; none holds a key and none can widen what the broker allows. An MCP tool forwards its arguments to one broker operation unchanged.",
            "agent_scope": "An agent token is scoped to exactly one node, resolved from the folder the agent was started in (the node's work folders) or from an explicit token fixed when it was issued. The agent reads that node, its ancestors and Global. It reads its descendants only if the node's policy sets descendant-read, and a sibling only for sub-nodes whose parent shares them; both widenings need a human and, in this build, a presence check that cannot be given. Projects never read each other. No tool argument changes any of this.",
            "agent_access_levels": {
                "read-write": facts.agent_caps["read-write"],
                "read-only": facts.agent_caps["read-only"],
                "none": facts.agent_caps["none"],
                "note": "Set per node by a human (node policy). The notes and admin capabilities are never part of an agent's scope.",
            },
            "sensitive_reveals_wait_for_a_human": [
                "If the whole vault is locked, a request for a value is recorded and answered approval_pending. A person decides it with the passphrase (and the authenticator code when two-factor is on) on the Lock screen or with `credmgr approve`; approval covers one request, one entry, once, and expires after 120 seconds. The vault stays locked.",
                "If the node's policy requires a second factor (reveal or always) and the vault has one enrolled, an agent gets two_factor_required until a person proves the factor. One code opens a vault-wide window of five minutes. The owner's own login is not asked.",
                "A value is never staged for one caller and handed to another: an approval is one slot per (node, entry, requester) and releases only the fields that request asked for.",
            ],
            "writes": {
                "create_while_locked": "credmgr_create works on a locked vault. The entry is not written to the manifest: it is held in a review tray and a person accepts or discards it. Say so to the operator.",
                "update_needs_unlocked": "credmgr_update, credmgr_rotate, credmgr_remove, credmgr_undo and the three field tools need the vault and node unlocked, because overwriting a credential you cannot read would be credential substitution.",
                "generation_check": "Every change to an existing entry carries its current generation. A concurrent change answers conflict; re-read and retry once.",
                "undo": "Rotations, field changes and removals are undoable by audit record id. A removal and a field change can be undone for seven days; a rotation has no time limit. Undo is itself audited.",
            },
            "audit": "Every decision, allowed or denied, is recorded in a hash-chained log. An agent can read only a redacted feed (id, action, time, actor), never values or before/after content.",
            "denials_are_explicit": "A refusal names the rule and a remedy that is a human action. The correct response is to ask the human, never to retry, rephrase or look for another route.",
            "values_in_your_context": "Anything you read with credmgr_get is now in your context. Do not print it into chat, logs, commit messages, files or command arguments; pass it to the program that needs it and nowhere else.",
            "known_limits": [
                "Software keystore tier: a copy of the vault folder can be attacked offline with the passphrase; two-factor guards the door (the broker), not the encryption.",
                "A login exported into a shell that an agent also runs in gives that agent every project (known risk K-6). Agents should use the MCP server, never a token.",
                "No presence check exists in this build; everything that needs one is refused for every caller.",
            ],
        },
        "human_in_the_loop": [
            "Unlocking the vault, approving a waiting request, giving a second-factor code, creating grants, changing node policy or work folders, sealing and restoring nodes, backup, verify and doctor are human actions.",
            "Entries an agent creates while the vault is locked wait for human review before they exist.",
            "A human decides every approval_pending and every two_factor_required.",
            "Anything marked human only in features.agent_access, and every operation with agent_reach 'human_only' in broker_ops, has no agent path.",
        ],
        "forbidden_for_agents": {
            "in_plain_terms": FORBIDDEN_PLAIN,
            "operations": facts.forbidden,
            "source": "docs/10_API_AND_MCP.md section 3.2; restated in code as FORBIDDEN_OPS in crates/mcp/src/tools.rs and enforced by test I-13, which fails if a tool maps to any of these or a tool name contains one of their fragments.",
        },
        "never": [
            "Never create, change or request a grant on your own; ask the operator.",
            "Never try to read another node, the Orphaned node, a node's notes, a TOTP seed, or the vault folder on disk.",
            "Never change a node's policy, agent access, name, parent or work folders, or try to widen your own scope.",
            "Never run backup, verify, doctor, root-key rotation or any second-factor enrolment or recovery.",
            "Never purge or shorten the audit log or a recovery window.",
            "Never call the broker socket or the credmgr command line to get around a refusal; the MCP tools are your whole interface.",
            "Never ask the user for their passphrase, recovery code, recovery codes or authenticator code, and never put them in a command.",
            "Never export or reuse a CREDMGR_TOKEN login.",
            "Never retry a refused or approval_pending request in a loop, rephrase it, or look for another route.",
            "Never print a secret into chat, a log, a commit, a comment or a file, and never pass one as a command-line argument.",
            "Never invent a secret or put a placeholder in code; say exactly which credential is missing and what it is for.",
            "Never describe a feature with status 'planned' or 'partial' as working.",
        ],
        "how_to_read": how(HOW_TO_READ),
        "how_to_write": how(HOW_TO_WRITE),
        "mcp_tools": [tool_entry(n) for n in facts.tool_names],
        "agent_reachable_broker_ops": reachable,
        "field_types": facts.consts["FIELD_TYPE_NAMES"],
        "entry_types": facts.consts["ENTRY_TYPE_NAMES"],
        "sensitivity_levels": facts.consts["SENSITIVITY_NAMES"],
        "capabilities": facts.capabilities,
        "error_codes": errors,
        "broker_ops": broker_ops,
        "broker_op_reach_meaning": {
            "mcp": "Exposed as an MCP tool. This is the agent's whole interface.",
            "capability_only": "No MCP tool. The broker would accept the call from an agent-origin client that holds the capability, so an agent must not use it: several are the human's review or maintenance steps.",
            "human_only": "Needs Admin, the owner's login, the notes capability or presence, which an agent scope never carries.",
            "bootstrap": "Vault creation, unlock and lock operations that any local process may send and an agent never needs.",
        },
        "agent_access_meaning": AGENT_ACCESS_MEANING,
        "cli": {
            "top_level_commands": facts.cli_top,
            "usage": facts.cli_usage,
            "notes": [
                "A secret value is read from stdin and never travels as an argument.",
                "credmgr mcp starts the MCP server; credmgr help lists every flag.",
                "`credmgr unlock` prints a login token for a human's shell. It is not for agents.",
            ],
        },
        "area_titles": AREA_TITLE,
        "feature_counts": {"total": len(features), "by_area": counts, "by_status": {s: sum(1 for f in features if f["status"] == s) for s in STATUSES}},
        "features": feats,
        "not_built": [{"id": f["id"], "title": f["title"], "summary": f["summary"]} for f in features if f["status"] == "planned"],
    }


COMPACT_LISTS = ("error_codes", "broker_ops", "features", "not_built")


def render_manifest(manifest: dict) -> str:
    """Indented JSON; the four long lists put one record per line so the file stays readable and small."""
    parts = []
    keys = list(manifest)
    for i, k in enumerate(keys):
        v = manifest[k]
        if k in COMPACT_LISTS:
            body = "[\n" + ",\n".join("    " + json.dumps(x, ensure_ascii=False) for x in v) + "\n  ]"
        else:
            body = json.dumps(v, indent=2, ensure_ascii=False).replace("\n", "\n  ")
        parts.append(f"  {json.dumps(k)}: {body}" + ("," if i < len(keys) - 1 else ""))
    return "{\n" + "\n".join(parts) + "\n}\n"


def outputs() -> tuple[dict[Path, str], list[str]]:
    facts = Facts()
    features = load_features()
    ops_meta = load_ops_meta()
    problems = validate(features, ops_meta, facts)
    if problems:
        return {}, problems
    data_js = render_help_data(features)
    for rx, label in BUNDLE_BANNED:
        m = rx.search(data_js)
        if m:
            return {}, [f"the generated help-data.js contains {label}: {m.group(0)!r}"]
    return {
        HELP_MD: render_help_md(features, facts),
        MANIFEST_JSON: render_manifest(build_manifest(features, ops_meta, facts)),
        HELP_DATA_JS: data_js,
    }, []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if any generated file is stale or a rule is broken; write nothing")
    args = ap.parse_args(argv)
    try:
        files, problems = outputs()
    except GenError as e:
        sys.stderr.write(f"gen_help: {e}\n")
        return 2
    if problems:
        for p in problems:
            sys.stderr.write(f"gen_help: {p}\n")
        sys.stderr.write(f"gen_help: {len(problems)} problem(s); nothing written\n")
        return 1
    stale = [p for p, text in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != text]
    if args.check:
        if stale:
            for p in stale:
                sys.stderr.write(f"gen_help: stale: {p.relative_to(REPO)} (run python3 tools/gen_help.py)\n")
            return 1
        print(f"gen_help: up to date ({len(files)} files)")
        return 0
    for p, text in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        if p in stale:
            p.write_text(text, encoding="utf-8")
            print(f"gen_help: wrote {p.relative_to(REPO)}")
    if not stale:
        print("gen_help: nothing to change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
