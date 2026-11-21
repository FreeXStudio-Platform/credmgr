#!/usr/bin/env python3
"""CredMgr V2 - the endpoint matrix.

Starts the REAL `credmgrd` binary against a throwaway vault in a private temp directory and calls
EVERY broker op over the real Unix-socket protocol (docs/10_API_AND_MCP.md section 1: newline
delimited JSON). For each op it asserts the documented success shape, or - where the op cannot
succeed on this transport - the documented refusal (for example `presence_required` for
grant.create / node.reparent / audit.get / totp.seed and for a node.policy patch that widens reach,
`malformed_request` for renaming Global).

    python3 scripts/endpoint-matrix.py              uses target/debug (cargo build -p credmgr-brokerd first)
    python3 scripts/endpoint-matrix.py --bin target/release
    python3 scripts/endpoint-matrix.py --check-coverage     op-set check only, no daemon (fast)
    python3 scripts/endpoint-matrix.py --json out.json      also write the per-op table as JSON
    python3 scripts/endpoint-matrix.py -v                   show the raw response of every step
    python3 scripts/endpoint-matrix.py --strict             known gaps (below) count as failures

Exit status: 0 every expectation held and every op is covered; 1 a mismatch or a coverage failure;
2 the matrix could not run (binary missing, op list unreadable, unsupported platform).

The op list is NOT trusted to this file. The covered set is derived from the step table below and
compared with `corpus_check.broker_ops()` (tools/corpus_check.py - the ops.rs dispatch arms). An op
that the broker dispatches but the table does not cover FAILS the matrix; so does a table op the
broker does not dispatch; so does an op with no passing row, or with no / more than one `primary`
row. Adding an op to ops.rs therefore breaks this script until a row is added.

Known gaps. A row may carry `gap=KnownGap(...)`: the DOCUMENTED expectation is still stated, but the
broker is known not to deliver it yet and the exact broken behaviour is pinned. While the break is
exactly as pinned the row is XFAIL (printed loudly, exit 0; `--strict` makes it exit 1). If the
documented behaviour starts to hold the row is XPASS and FAILS the run until the marker is deleted;
if the broker does anything else the row FAILS. A gap can be neither ignored nor forgotten.

A row that passes only BECAUSE a gap holds (for example a "reads back unchanged after the round trip"
row while the step before it never happened) carries `blocked_by="<gap id>"`: while that gap
is XFAIL the row is reported BLOCKED - loud, not counted as a pass, a failure under --strict - instead
of a PASS that claims evidence nobody gathered.

Proving the matrix can fail (demonstrations; see v2/scripts/RUNNING.md):
    --check-coverage --drop-op audit.get      removes every audit.get row -> UNCOVERED, exit 1
    --mutate-op grant.create                  swaps grant.create's expectations for impossible ones -> exit 1

Isolation. The daemon and every child get an environment built from scratch: HOME, XDG_*, APPDATA,
CREDMGR_VAULT_DIR and CREDMGR_STATE_DIR all point inside one mktemp directory, and nothing from the
caller's environment is inherited except PATH. The script refuses to run if the resolved vault or
state directory is not inside that directory, and it snapshots the metadata (never contents) of the
real default vault locations before and after the run and fails if anything there changed.

All passphrases and values are generated per run. Stdlib only. Needs Unix sockets (macOS / Linux).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

sys.dont_write_bytecode = True  # importing tools/corpus_check.py must not litter the repo

V2 = Path(__file__).resolve().parent.parent
REPO = V2.parent
CORPUS_CHECK = REPO / "tools" / "corpus_check.py"

EXIT_OK, EXIT_FAIL, EXIT_CANNOT_RUN = 0, 1, 2


# --------------------------------------------------------------------------------------------
# expectations
# --------------------------------------------------------------------------------------------


class Mismatch(Exception):
    """An expectation did not hold. The message says what was expected and what was seen."""


class _Any:
    def __repr__(self) -> str:
        return "<present>"


ANY = _Any()  # "this response field must exist"; its value is not asserted


def _kind_ok(want: Any, got: Any) -> bool:
    if want is bool:
        return isinstance(got, bool)
    if want is int:
        return isinstance(got, int) and not isinstance(got, bool)
    if isinstance(want, type):
        return isinstance(got, want)
    return False


def shape(**spec: Any) -> Callable[[Any, "Ctx"], None]:
    """A check for an ok `value`: every key present, and each typed / equal / predicate-true."""

    def check(value: Any, ctx: "Ctx") -> None:
        if not isinstance(value, dict):
            raise Mismatch(f"value is {type(value).__name__}, expected an object")
        for key, want in spec.items():
            if key not in value:
                raise Mismatch(f"value has no `{key}` (keys: {sorted(value)})")
            got = value[key]
            if want is ANY:
                continue
            if isinstance(want, type):
                if not _kind_ok(want, got):
                    raise Mismatch(f"value.{key} is {type(got).__name__}, expected {want.__name__}")
            elif callable(want):
                if not want(got):
                    raise Mismatch(f"value.{key} = {_clip(got)} failed its predicate")
            elif got != want:
                raise Mismatch(f"value.{key} = {_clip(got)}, expected {_clip(want)}")

    return check


def _clip(x: Any, n: int = 160) -> str:
    s = json.dumps(x, sort_keys=True, default=str)
    return s if len(s) <= n else s[: n - 3] + "..."


@dataclass
class Expect:
    kind: str  # "ok" | "err" | "answers" | "dropped"
    desc: str  # the short text shown in the table's expectation column
    check: Optional[Callable[[Any, "Ctx"], None]] = None  # ok: run on response["value"]
    tag: str = ""  # err: the wire `error` string
    fields: dict = field(default_factory=dict)  # err: extra wire fields that must match
    audit: bool = False  # ok: the response must carry an `audit` record id


def ok(desc: str, check: Optional[Callable[[Any, "Ctx"], None]] = None, audit: bool = False) -> Expect:
    return Expect("ok", "ok " + desc, check, audit=audit)


def refuse(tag: str, desc: str = "", **fields: Any) -> Expect:
    extra = (" " + desc) if desc else ""
    return Expect("err", f"refuse {tag}{extra}", tag=tag, fields=fields)


def answers(desc: str) -> Expect:
    """Any well-formed envelope - a success or a typed refusal - but never a dropped connection."""
    return Expect("answers", "answers " + desc)


def dropped(desc: str) -> Expect:
    """The broker closes the connection without a response (only ever used to pin a known gap)."""
    return Expect("dropped", "dropped " + desc)


class Dropped(Exception):
    """credmgrd closed the connection without sending a response line."""


@dataclass
class KnownGap:
    """A documented behaviour the broker does not yet deliver, pinned so it cannot hide or drift.

    The row still states the DOCUMENTED expectation. While the broker is broken exactly as `observed`
    describes, the row is XFAIL (reported loudly, exit 0 unless --strict). If the documented behaviour
    starts to hold the row is XPASS and FAILS the run - delete the gap marker. If the broker does
    something that is neither, the row FAILS. A gap can therefore be neither ignored nor forgotten."""
    id: str  # tracker id, e.g. "K-7"
    text: str  # one line: what is broken and where it is tracked
    observed: Expect  # the broken behaviour, pinned
    panics: int = 0  # daemon panics (in the log) this row is expected to cause


def _envelope_problem(resp: Any, sent_id: Optional[str]) -> Optional[str]:
    if not isinstance(resp, dict):
        return f"response is {type(resp).__name__}, expected an object"
    if sent_id is not None and resp.get("id") != sent_id:
        return f"response id {resp.get('id')!r} does not echo request id {sent_id!r}"
    if not isinstance(resp.get("ok"), bool):
        return "response has no boolean `ok`"
    return None


def evaluate(expect: Expect, resp: Any, ctx: "Ctx", sent_id: Optional[str]) -> None:
    """Raise Mismatch unless `resp` (a parsed response, or the Dropped class) is exactly what
    `expect` describes. No I/O - unit-testable."""
    if resp is Dropped:
        if expect.kind == "dropped":
            return
        raise Mismatch("credmgrd dropped the connection with no response (a panic in the connection thread?)")
    if expect.kind == "dropped":
        raise Mismatch(f"expected a dropped connection, got a response: {_clip(resp)}")
    problem = _envelope_problem(resp, sent_id)
    if problem:
        raise Mismatch(problem)
    if expect.kind == "answers":
        return
    if expect.kind == "ok":
        if not resp["ok"]:
            raise Mismatch(f"expected success, got error {resp.get('error')!r}: {_clip(resp)}")
        if "value" not in resp:
            raise Mismatch("ok response has no `value`")
        if expect.audit and not isinstance(resp.get("audit"), str):
            raise Mismatch("ok response carries no `audit` record id")
        if expect.check:
            expect.check(resp["value"], ctx)
        return
    if resp["ok"]:
        raise Mismatch(f"expected refusal `{expect.tag}`, but the op succeeded: {_clip(resp.get('value'))}")
    if resp.get("error") != expect.tag:
        raise Mismatch(f"expected refusal `{expect.tag}`, got `{resp.get('error')}`: {_clip(resp)}")
    for key, want in expect.fields.items():
        if key not in resp:
            raise Mismatch(f"refusal has no `{key}` (keys: {sorted(resp)})")
        if want is ANY:
            continue
        got = resp[key]
        if isinstance(want, type):
            if not _kind_ok(want, got):
                raise Mismatch(f"refusal.{key} is {type(got).__name__}, expected {want.__name__}")
        elif callable(want):
            if not want(got):
                raise Mismatch(f"refusal.{key} = {_clip(got)} failed its predicate")
        elif got != want:
            raise Mismatch(f"refusal.{key} = {_clip(got)}, expected {_clip(want)}")


# --------------------------------------------------------------------------------------------
# the step table
# --------------------------------------------------------------------------------------------


@dataclass
class Step:
    op: str
    note: str  # what this row shows, in a few words
    params: Any  # dict, or callable(ctx) -> dict
    expect: Expect
    who: str = "owner"  # owner | anon | agent:acme | agent:beta | stale
    save: Optional[Callable[["Ctx", Any, dict], None]] = None  # save(ctx, value, whole_response)
    primary: bool = False  # the row the per-op summary shows (exactly one per covered op)
    fatal: bool = False  # a failure here stops the run (everything after depends on it)
    probe: bool = False  # a negative control: not an op, not counted toward coverage
    raw: Optional[bytes] = None  # send these bytes instead of a request frame (probe only)
    gap: Optional[KnownGap] = None  # the documented behaviour is not delivered yet - see KnownGap
    blocked_by: Optional[str] = None  # a KnownGap id this row's evidence depends on - see apply_block


def S(op: str, note: str, params: Any, expect: Expect, who: str = "owner", **kw: Any) -> Step:
    return Step(op, note, params, expect, who, **kw)


def _is_str(min_len: int = 1) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and len(v) >= min_len


def _list_of(n: Optional[int] = None) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, list) and (n is None or len(v) == n)


def _contains(*items: Any) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, list) and all(i in v for i in items)


def _set_eq(*items: Any) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, list) and set(v) == set(items)


def _no_value(v: Any, marker: str) -> None:
    """An answer that must carry names and counts only: the marker (part of a value that was sent) must not come back."""
    if marker in json.dumps(v):
        raise Mismatch(f"a value reached the answer: {_clip(v)}")


def _positive(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def _six_digits(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 6 and v.isdigit()


ENTRY_META_KEYS = {"id", "name", "type", "sensitivity", "fieldCount", "modified", "rotatedAt", "expiresAt", "hasTotp"}


def _entry_rows(n: int) -> Callable[[Any], bool]:
    """entry.list `entries` (ADR-077): exactly the nine manifest fields (ADR-080 added hasTotp), nothing else, n rows."""

    def check(rows: Any) -> bool:
        def row_ok(r: Any) -> bool:
            return (isinstance(r, dict) and set(r) == ENTRY_META_KEYS
                    and isinstance(r["id"], str) and isinstance(r["name"], str) and isinstance(r["type"], str)
                    and r["sensitivity"] in ("low", "medium", "high", "critical")
                    and isinstance(r["hasTotp"], bool) and r["hasTotp"] == (r["name"] in ("OTP_SEED", "OTP_SHORT"))
                    and _kind_ok(int, r["fieldCount"]) and _kind_ok(int, r["modified"])
                    and (r["rotatedAt"] is None or _kind_ok(int, r["rotatedAt"]))
                    and (r["expiresAt"] is None or _kind_ok(int, r["expiresAt"])))

        return isinstance(rows, list) and len(rows) == n and all(row_ok(r) for r in rows)

    return check


def _entries_match_ids(value: Any, ctx: "Ctx") -> None:
    """`entries` lists exactly the entries `ids` names, in the same order (same gate, same filter)."""
    if [r["id"] for r in value["entries"]] != value["ids"] or [r["name"] for r in value["entries"]] != value["names"]:
        raise Mismatch("entry.list `entries` does not list the same entries, in the same order, as `ids`/`names`")


def _no_entries_metadata(value: Any, ctx: "Ctx") -> None:
    """An agent's `entry.list` is the response it had before ADR-077: node, ids, names, generation - and no
    `entries` key at all (the metadata is for human sessions only)."""
    if set(value) != {"node", "ids", "names", "generation"}:
        raise Mismatch(f"an agent's entry.list has keys {sorted(value)}, expected exactly "
                       "['generation', 'ids', 'names', 'node'] (no `entries`)")


def _no_values(*names: str) -> Callable[[Any, "Ctx"], None]:
    """ADR-078: `entry.get` is metadata - labels, types, masking - and never a value. None of the generated
    values named here may appear anywhere in the answer."""

    def check(value: Any, ctx: "Ctx") -> None:
        text = json.dumps(value)
        for name in names:
            if ctx[name] in text:
                raise Mismatch(f"the answer carries the value `{name}` (entry.get must never return a value)")

    return check


def _absent(key: str) -> Callable[[Any, "Ctx"], None]:
    """The answer must NOT carry `key` (for example `value` beside several fields)."""

    def check(value: Any, ctx: "Ctx") -> None:
        if isinstance(value, dict) and key in value:
            raise Mismatch(f"the answer carries `{key}`, which it must not here")

    return check


def _field_labels(*labels: str) -> Callable[[Any], bool]:
    """A `fields` array whose labels are exactly these, in this order."""
    return lambda fields: isinstance(fields, list) and [f.get("label") for f in fields] == list(labels)


def _generation_is_current(node: str) -> Callable[[Any, "Ctx"], None]:
    """`notes.read` returns the manifest generation a `notes.write` must be based on: it must be the one
    `entry.list` reports right now."""

    def check(value: Any, ctx: "Ctx") -> None:
        if value.get("generation") != ctx.gen(node):
            raise Mismatch(f"notes.read generation {value.get('generation')!r} is not the node's current "
                           f"generation {ctx.gen(node)!r}")

    return check


def _audit_feed_is_clean(value: Any, ctx: "Ctx") -> None:
    """ADR-077: no session token - live, dead, or merely shaped like one - in an audit feed, and every
    actor is a non-secret name (`Origin` or `Origin:s_<16 hex>`)."""
    ctx.expect_no_bearer(value)


def _save(**getters: Callable[[Any], Any]) -> Callable[["Ctx", Any, dict], None]:
    """save(ctx, value, response): store each getter's result under its name."""

    def save(ctx: "Ctx", value: Any, resp: dict) -> None:
        for name, get in getters.items():
            ctx[name] = get(value)

    return save


def _save_secret(name: str, get: Callable[[Any], str]) -> Callable[["Ctx", Any, dict], None]:
    def save(ctx: "Ctx", value: Any, resp: dict) -> None:
        ctx.set_secret(name, get(value))

    return save


def _save_audit(name: str) -> Callable[["Ctx", Any, dict], None]:
    def save(ctx: "Ctx", value: Any, resp: dict) -> None:
        ctx[name] = resp["audit"]

    return save


def _save_batch_ids(ctx: "Ctx", value: Any, resp: dict) -> None:
    for item in value["created"]:
        ctx["e_" + item["name"].lower()] = item["entry"]


def _chain(*saves: Callable[["Ctx", Any, dict], None]) -> Callable[["Ctx", Any, dict], None]:
    def save(ctx: "Ctx", value: Any, resp: dict) -> None:
        for s in saves:
            s(ctx, value, resp)

    return save



def build_steps() -> list[Step]:
    """Every row of the matrix, in execution order. Params are lazy (callables) so the table can be
    built, listed and coverage-checked with no daemon and no temp directory."""
    NOTE = "# notes\nmatrix note, generated"  # not a secret; the note body is a fixture
    s: list[Step] = []
    add = s.append

    # ---- 0. wire-protocol probes: not ops, so they are negative controls and never count --------
    add(S("(frame)", "a line that is not JSON", {}, refuse("malformed_request"), "anon",
          probe=True, raw=b"this is not json\n"))
    add(S("no.such_op", "an op the broker does not dispatch", {}, refuse("malformed_request", message=_is_str()),
          "anon", probe=True))

    # ---- 1. bootstrap: a vault that does not exist yet ----------------------------------------
    add(S("vault.status", "before any vault exists: locked, and not initialised (the first-run signal)", {},
          ok("{locked:true, initialized:false}", shape(locked=True, initialized=False)), "anon", primary=True))
    add(S("vault.init_confirm", "nothing in flight", lambda c: {"recoveryCode": "0000-0000"},
          refuse("vault_init_not_pending"), "anon"))
    add(S("vault.init_begin", "passphrase missing", {}, refuse("malformed_request"), "anon"))
    add(S("vault.init_begin", "start init; the recovery code is shown once",
          lambda c: {"passphrase": c["pw"]},
          ok("{recoveryCode}", shape(recoveryCode=_is_str(20))), "anon", primary=True, fatal=True,
          save=_save_secret("rc", lambda v: v["recoveryCode"])))
    add(S("vault.status", "an init in flight is still no vault (nothing is on disk until it is confirmed)", {},
          ok("{locked:true, initialized:false}", shape(locked=True, initialized=False)), "anon"))
    add(S("vault.init_confirm", "a wrong retyped code leaves init pending", {"recoveryCode": "0000-0000-0000"},
          refuse("recovery_code_mismatch"), "anon"))
    add(S("vault.init_confirm", "the right code writes the vault", lambda c: {"recoveryCode": c["rc"]},
          ok("{initialized:true}", shape(initialized=True)), "anon", primary=True, fatal=True))
    add(S("vault.status", "the confirmed vault exists and is locked", {},
          ok("{locked:true, initialized:true}", shape(locked=True, initialized=True)), "anon"))
    add(S("vault.init_begin", "a vault already exists", lambda c: {"passphrase": c["pw"]},
          refuse("vault_already_initialized"), "anon"))
    add(S("vault.unlock", "wrong passphrase", {"passphrase": "definitely-not-the-passphrase"},
          refuse("wrong_passphrase"), "anon"))
    add(S("vault.unlock", "right passphrase mints the owner session", lambda c: {"passphrase": c["pw"]},
          ok("{locked:false, token}", shape(locked=False, token=_is_str(8))), "anon", primary=True, fatal=True,
          save=_save_secret("tok", lambda v: v["token"])))
    add(S("vault.status", "unlocked", {}, ok("{locked:false, initialized:true}", shape(locked=False, initialized=True))))
    add(S("entry.list", "a token the broker does not hold is refused, not demoted", {"node": "global"},
          refuse("session_expired"), "stale"))

    # ---- 2. identity and the graph -----------------------------------------------------------
    add(S("whoami", "the owner session is global with every capability", {},
          ok("{node:global, 7 capabilities}", shape(
              node="global",
              capabilities=_set_eq("list", "read", "reveal", "create", "update", "notes", "admin"),
              reachable=_contains("global"))), primary=True))
    add(S("node.list", "global is listed", {}, ok("{nodes ∋ global}", shape(nodes=_contains("global"))),
          primary=True))
    add(S("graph.snapshot", "one-request graph for the canvas", {},
          ok("{nodes, links, meta.vaultLocked:false, meta.sealed:[]}", shape(
              nodes=lambda n: isinstance(n, list) and any(x.get("id") == "global" for x in n),
              links=list, meta=lambda m: isinstance(m, dict) and m.get("vaultLocked") is False and m.get("sealed") == [])),
          primary=True))
    add(S("node.create", "label missing", {"id": "acme", "parentId": "global"}, refuse("malformed_request")))
    add(S("node.create", "`global` is a reserved id", {"id": "global", "label": "G", "parentId": "global"},
          refuse("malformed_request")))
    add(S("node.create", "project acme bound to a workdir",
          lambda c: {"id": "acme", "label": "Acme", "parentId": "global", "workdirs": [c.dir("wd_acme")]},
          ok("{node:acme, created:true}", shape(node="acme", created=True)), primary=True, fatal=True))
    add(S("node.create", "project beta bound to a workdir",
          lambda c: {"id": "beta", "label": "Beta", "parentId": "global", "workdirs": [c.dir("wd_beta")]},
          ok("{node:beta, created:true}", shape(node="beta", created=True)), fatal=True))
    add(S("node.create", "sub-node acme-api under acme",
          {"id": "acme-api", "label": "Acme API", "parentId": "acme"},
          ok("{node:acme-api, created:true}", shape(node="acme-api", created=True)), fatal=True))
    add(S("node.create", "an existing id", {"id": "acme", "label": "again", "parentId": "global"},
          refuse("malformed_request")))
    add(S("node.create", "the depth cap (a sub-node cannot parent)",
          {"id": "too-deep", "label": "x", "parentId": "acme-api"}, refuse("malformed_request")))
    add(S("node.set_workdirs", "rebind acme to two directories",
          lambda c: {"node": "acme", "workdirs": [c.dir("wd_acme"), c.dir("wd_acme2")]},
          ok("{node:acme, 2 workdirs}", shape(node="acme", workdirs=_list_of(2))), primary=True))
    add(S("node.set_workdirs", "a relative path", {"node": "acme", "workdirs": ["relative/dir"]},
          refuse("malformed_request")))
    add(S("node.set_workdirs", "the home directory would scope everything to one node",
          lambda c: {"node": "acme", "workdirs": [c.dir("home")]}, refuse("malformed_request")))
    add(S("node.update", "rename acme (the id never changes)", {"node": "acme", "label": "Acme Corp"},
          ok("{node:acme, label}", shape(node="acme", label="Acme Corp")), primary=True))
    add(S("node.update", "Global cannot be renamed", {"node": "global", "label": "Everything"},
          refuse("malformed_request")))
    add(S("node.policy", "a narrowing patch applies and records its reason",
          {"node": "acme", "reason": "matrix: narrowing patch", "policy": {"privateNames": True}},
          ok("{changed:[privateNames], notEnforced:[]}", shape(
              node="acme", changed=_set_eq("privateNames"), notEnforced=[])),
          primary=True))
    # ADR-083: privateNames is enforced. An agent sees an opaque node and the owner sees a badge; it is switched
    # off again right away because the rows that follow count acme's entries as an agent would.
    add(S("entry.list", "the owner of a privateNames node is not blinded: no nameHidden flag, a normal list",
          {"node": "acme"}, ok("{ids, names; no nameHidden}", lambda v, c: (
              shape(ids=list, names=list)(v, c),
              (_ for _ in ()).throw(Mismatch("the owner got nameHidden")) if "nameHidden" in v else None))))
    add(S("entry.list", "an agent in a privateNames node sees an opaque node: no ids, no names, a count",
          {"node": "acme"},
          ok("{entries:[], nameHidden:true, count}", shape(
              entries=[], ids=[], names=[], nameHidden=True, count=lambda n: n is None or _positive(n))), "agent:acme"))
    add(S("node.policy", "and the policy goes back to open names",
          {"node": "acme", "reason": "matrix: names visible again", "policy": {"privateNames": False}},
          ok("{changed:[privateNames]}", shape(changed=_set_eq("privateNames")))))
    add(S("node.policy", "widening reach (descendantRead) needs presence",
          {"node": "acme", "reason": "matrix: widening patch", "policy": {"descendantRead": True}},
          refuse("presence_required", operation="node.policy")))
    add(S("node.policy", "a reason is mandatory", {"node": "acme", "policy": {"privateNames": False}},
          refuse("malformed_request")))
    add(S("node.policy", "an empty patch changes nothing", {"node": "acme", "reason": "matrix: empty", "policy": {}},
          refuse("malformed_request")))
    add(S("node.policy", "an unknown field is refused, never ignored",
          {"node": "acme", "reason": "matrix: typo", "policy": {"privateNmaes": True}},
          refuse("malformed_request")))

    # ---- 3. entries --------------------------------------------------------------------------
    add(S("entry.create", "owner creates API_KEY on acme",
          lambda c: {"node": "acme", "name": "API_KEY", "value": c["v_api1"]},
          ok("{pending:false, entry, generation}", shape(node="acme", entry=_is_str(3), pending=False,
                                                          generation=int), audit=True),
          primary=True, fatal=True,
          save=_chain(_save(e_api=lambda v: v["entry"]), _save_audit("a_create"))))
    add(S("entry.create", "the name is taken", lambda c: {"node": "acme", "name": "API_KEY", "value": "x"},
          refuse("entry_exists", node="acme", name="API_KEY")))
    add(S("entry.create", "value missing", {"node": "acme", "name": "NO_VALUE"}, refuse("malformed_request")))
    add(S("entry.create_batch", "five entries in one call (two are TOTP seeds)",
          lambda c: {"node": "acme", "entries": [
              {"name": "DB_URL", "value": c["v_db"]},
              {"name": "OTP_SEED", "value": c["otp_seed"]},
              {"name": "OTP_SHORT", "value": c["otp_short"]},
              {"name": "SPARE_A", "value": c["v_spare_a"]},
              {"name": "SPARE_B", "value": c["v_spare_b"]}]},
          ok("{created:5, complete:true}", shape(
              node="acme", complete=True, total=5,
              created=lambda x: isinstance(x, list) and len(x) == 5 and all(i["pending"] is False for i in x))),
          primary=True, fatal=True, save=_save_batch_ids))
    add(S("entry.create_batch", "a name twice in one batch",
          {"node": "acme", "entries": [{"name": "DUP", "value": "a"}, {"name": "DUP", "value": "b"}]},
          refuse("malformed_request")))
    add(S("entry.create_batch", "an empty batch", {"node": "acme", "entries": []}, refuse("malformed_request")))
    add(S("entry.list", "acme holds the six entries and a generation, each with its manifest metadata",
          {"node": "acme"},
          ok("{ids:6, names, entries:6 x 9 manifest fields (OTP_* hasTotp), generation}", lambda v, c: (
              shape(node="acme", ids=_list_of(6), generation=_positive, entries=_entry_rows(6),
                    names=_set_eq("API_KEY", "DB_URL", "OTP_SEED", "OTP_SHORT", "SPARE_A", "SPARE_B"))(v, c),
              _entries_match_ids(v, c))), primary=True))
    add(S("entry.list", "node missing", {}, refuse("malformed_request")))
    add(S("search", "a name fragment finds the entry", {"term": "api"},
          ok("{results ∋ acme/API_KEY}", shape(
              results=lambda r: any(x.get("node") == "acme" and x.get("name") == "API_KEY" for x in r))),
          primary=True))
    add(S("search", "no match is an empty list", {"term": "zzz-no-such-entry"}, ok("{results:[]}", shape(results=[]))))
    add(S("util.generate", "the broker makes a 20-character password with a strength estimate",
          {}, ok("{value:20, length:20, symbols, entropyBits:124}", shape(
              value=lambda v: isinstance(v, str) and len(v) == 20 and not any(ch.isspace() for ch in v),
              length=20, symbols=True, pronounceable=False, entropyBits=124)), primary=True))
    add(S("util.generate", "options are honoured", {"length": 32, "symbols": False},
          ok("{length:32, alphanumeric}", shape(
              value=lambda v: isinstance(v, str) and len(v) == 32 and v.isalnum(), length=32, symbols=False))))
    add(S("util.generate", "a length below 8 is refused", {"length": 7}, refuse("malformed_request")))
    add(S("util.generate", "an option the generator does not have is refused, not ignored", {"colour": "red"},
          refuse("malformed_request")))
    add(S("search", "term missing", {}, refuse("malformed_request")))
    # ADR-121: near-duplicate names and aliases. The node is back to its six entries by the last row of this group.
    add(S("entry.similar", "a name that differs only in separators is listed, and says why", {"node": "acme", "name": "api-key"},
          ok("{taken:false, similar ∋ API_KEY (separators)}", shape(
              node="acme", taken=False,
              similar=lambda s: any(x.get("name") == "API_KEY" and x.get("reason") == "separators" for x in s))),
          primary=True))
    add(S("entry.similar", "the same name once folded is taken, not 'similar to itself'", {"node": "acme", "name": "api_key"},
          ok("{taken:true, similar:[]}", shape(taken=True, similar=[]))))
    add(S("entry.similar", "a name with nothing alike is an empty list", {"node": "acme", "name": "wholly-unrelated"},
          ok("{taken:false, similar:[]}", shape(taken=False, similar=[]))))
    add(S("entry.similar", "name missing", {"node": "acme"}, refuse("malformed_request")))
    add(S("entry.alias", "give an entry another name (generation-checked)",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "aliases": ["legacy-api", "payments key"]},
          ok("{aliases:2, generation}", shape(node="acme", aliases=["legacy-api", "payments key"], generation=_positive)),
          primary=True))
    add(S("search", "an alias finds the entry and says which alias matched", {"term": "payments"},
          ok("{results ∋ acme/API_KEY via alias}", shape(
              results=lambda r: any(x.get("name") == "API_KEY" and x.get("alias") == "payments key" for x in r)))))
    add(S("entry.alias", "a name another entry has is refused, in any case",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "aliases": ["db_url"]},
          refuse("entry_exists")))
    add(S("entry.create", "a new entry cannot take a name an alias already holds",
          {"node": "acme", "name": "LEGACY-API", "value": "x"}, refuse("entry_exists")))
    add(S("entry.alias", "a stale generation is a conflict",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": 0, "aliases": []},
          refuse("conflict", expectedGeneration=0, currentGeneration=_positive)))
    add(S("entry.alias", "more than eight aliases are refused",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"),
                     "aliases": [f"alias-number-{i}" for i in range(9)]},
          refuse("malformed_request")))
    add(S("entry.alias", "an empty list clears them",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "aliases": []},
          ok("{aliases:[]}", shape(aliases=[], generation=_positive))))
    # ADR-122: the .env import. Values never appear in an answer; the entry it makes is removed again.
    add(S("entry.import_env", "a dry run names each pair's status and writes nothing",
          {"node": "acme", "dryRun": True,
           "entries": [{"name": "MATRIX_IMPORT", "value": "matrix-import-value-1"},
                       {"name": "api_key", "value": "matrix-import-value-2"}]},
          ok("{items: new, exists; counts}", lambda v, c: (
              shape(node="acme", dryRun=True, total=2,
                    items=lambda i: [x.get("status") for x in i] == ["new", "exists"],
                    counts=lambda k: k.get("new") == 1 and k.get("exists") == 1)(v, c),
              _no_value(v, "matrix-import-value"))), primary=True))
    add(S("entry.import_env", "a conflict refuses the whole import by default",
          {"node": "acme", "entries": [{"name": "MATRIX_IMPORT", "value": "matrix-import-value-1"},
                                       {"name": "api_key", "value": "matrix-import-value-2"}]},
          refuse("entry_exists")))
    add(S("entry.import_env", "with onConflict skip the new pair is written, the conflict is reported",
          {"node": "acme", "onConflict": "skip",
           "entries": [{"name": "MATRIX_IMPORT", "value": "matrix-import-value-1"},
                       {"name": "api_key", "value": "matrix-import-value-2"}]},
          ok("{created:1, skipped:1, complete}", lambda v, c: (
              shape(node="acme", complete=True, total=2,
                    created=lambda cr: len(cr) == 1 and cr[0].get("name") == "MATRIX_IMPORT",
                    skipped=lambda sk: [(x.get("name"), x.get("status")) for x in sk] == [("api_key", "exists")])(v, c),
              _no_value(v, "matrix-import-value")), audit=True),
          save=_save(e_import=lambda v: v["created"][0]["entry"])))
    add(S("entry.import_env", "an empty list of pairs is refused", {"node": "acme", "entries": []}, refuse("malformed_request")))
    add(S("entry.remove", "remove the imported entry again (the later rows count six entries)",
          lambda c: {"node": "acme", "entry": c["e_import"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(removed=True))))
    add(S("entry.reveal", "the owner reads back the value it sealed",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{value == sealed value}",
             lambda v, c: shape(node="acme", entry=c["e_api"], value=c["v_api1"])(v, c)), primary=True))
    add(S("entry.reveal", "no such entry", {"node": "acme", "entry": "e_000000000000"}, refuse("not_found")))
    add(S("totp.code", "the code, never the seed (a 160-bit seed)",
          lambda c: {"node": "acme", "entry": c["e_otp_seed"]},
          ok("{code: 6 digits == RFC 6238}", lambda v, c: (
              shape(node="acme", code=_six_digits)(v, c),
              c.expect_totp(v["code"], c["otp_seed"]))), primary=True))
    add(S("totp.code", "an 80-bit seed (16 base32 characters - what many sites issue) yields its RFC 6238 code",
          lambda c: {"node": "acme", "entry": c["e_otp_short"]},
          ok("{code: 6 digits == RFC 6238}", lambda v, c: (
              shape(node="acme", code=_six_digits)(v, c),
              c.expect_totp(v["code"], c["otp_short"])))))
    add(S("entry.create", "store a 72-bit seed (below the 80-bit floor)",
          lambda c: {"node": "acme", "name": "OTP_TINY",
                     "fields": [{"label": "2fa", "value": c["otp_tiny"], "type": "totp-seed"}]},
          ok("{pending:false}", shape(pending=False, entry=_is_str(3))), save=_save(e_otp_tiny=lambda v: v["entry"])))
    add(S("totp.code", "a seed under 80 bits is a typed refusal that names the reason, never a dropped connection",
          lambda c: {"node": "acme", "entry": c["e_otp_tiny"]},
          refuse("malformed_request", message=lambda m: isinstance(m, str) and "72 bits" in m and "80" in m)))
    add(S("entry.remove", "remove the 72-bit seed again (the later rows count six entries)",
          lambda c: {"node": "acme", "entry": c["e_otp_tiny"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(removed=True))))
    add(S("totp.seed", "no seed ever leaves on this transport", lambda c: {"node": "acme", "entry": c["e_otp_seed"]},
          refuse("presence_required", operation="totp.seed"), primary=True))
    add(S("entry.update", "replace the value (generation-checked)",
          lambda c: {"node": "acme", "entry": c["e_api"], "value": c["v_api2"], "generation": c.gen("acme")},
          ok("{generation}", shape(node="acme", generation=_positive)), primary=True))
    add(S("entry.update", "a stale generation is a conflict, not an overwrite",
          lambda c: {"node": "acme", "entry": c["e_api"], "value": "stale", "generation": 0},
          refuse("conflict", expectedGeneration=0, currentGeneration=_positive)))
    add(S("entry.update", "no such entry", lambda c: {"node": "acme", "entry": "e_000000000000", "value": "x",
                                                      "generation": c.gen("acme")}, refuse("not_found")))
    add(S("entry.reveal", "the update is what is read", lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{value == v2}", lambda v, c: shape(value=c["v_api2"])(v, c))))
    add(S("entry.rotate", "rotate keeps the previous ciphertext",
          lambda c: {"node": "acme", "entry": c["e_api"], "value": c["v_api3"], "generation": c.gen("acme")},
          ok("{generation, rotatedAt}", shape(node="acme", generation=_positive, rotatedAt=int), audit=True),
          primary=True, save=_save_audit("a_rotate")))
    add(S("entry.rotate", "a stale generation", lambda c: {"node": "acme", "entry": c["e_api"], "value": "x",
                                                           "generation": 0},
          refuse("conflict", expectedGeneration=0)))
    add(S("entry.list", "the rotation shows as rotatedAt on that entry and no other",
          {"node": "acme"},
          ok("{entries[API_KEY].rotatedAt: int}", shape(entries=lambda rows: (
              all(_kind_ok(int, r["rotatedAt"]) for r in rows if r["name"] == "API_KEY")
              and all(r["rotatedAt"] is None for r in rows if r["name"] != "API_KEY"))))))
    add(S("entry.undo", "undo the rotation by its audit id",
          lambda c: {"node": "acme", "id": c["a_rotate"], "generation": c.gen("acme")},
          ok("{undoneToGeneration}", shape(node="acme", undoneToGeneration=int, generation=_positive)),
          primary=True))
    add(S("entry.reveal", "the pre-rotate value is back", lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{value == v2}", lambda v, c: shape(value=c["v_api2"])(v, c))))
    add(S("entry.undo", "an entry.create cannot be undone",
          lambda c: {"node": "acme", "id": c["a_create"], "generation": c.gen("acme")}, refuse("not_undoable")))
    add(S("entry.undo", "an unknown audit id", lambda c: {"node": "acme", "id": "a_nope", "generation": c.gen("acme")},
          refuse("not_found")))
    # ---- ADR-156: expiry, lookup by reference, history, search within one project ------------
    # Rules per caller, restart and refusals in depth: brokerd/tests/quick_wins.rs. The expiry is cleared
    # again at the end so later rows see the entries as they were.
    add(S("entry.set_expiry", "API_KEY expires in thirty days (generation-checked)",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"),
                     "expiresAt": int(time.time()) + 30 * 86400},
          ok("{expiresAt, generation}", shape(node="acme", expiresAt=int, generation=_positive)), primary=True))
    add(S("entry.set_expiry", "neither expiresAt nor clear: a missing value never clears",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme")}, refuse("malformed_request")))
    add(S("entry.set_expiry", "a stale generation", lambda c: {"node": "acme", "entry": c["e_api"], "generation": 0,
                                                               "clear": True},
          refuse("conflict", expectedGeneration=0)))
    add(S("entry.expiring", "API_KEY is listed within sixty days, not yet expired, with its ref", {"days": 60},
          ok("{entries:[API_KEY]}", lambda v, c: (
              shape(days=60, entries=lambda rows: any(r["name"] == "API_KEY" and r["expired"] is False for r in rows))(v, c),
              c.__setitem__("r_api", next(r["ref"] for r in v["entries"] if r["name"] == "API_KEY")))),
          primary=True))
    add(S("entry.expiring", "an agent is not shown expiry dates", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    # ADR-161: vault.doctor_scan. Every finding kind, the move that applies a proposal and the audit record are in
    # brokerd/tests/doctor_scan.rs; here the owner's answer carries no value this run generated, and the refusals.
    add(S("vault.doctor_scan", "the owner gets a report naming entries, never a value this run generated", {},
          ok("{entriesScanned, counts, findings; no value}", lambda v, c: (
              shape(staleDays=365, expiringDays=30, entriesScanned=_positive, nodesScanned=_positive, truncated=False,
                    counts=lambda k: isinstance(k, dict) and "duplicate_value" in k, findings=list, skipped=list)(v, c),
              [_no_value(v, sv) for sv in c.secrets])), primary=True))
    add(S("vault.doctor_scan", "a window of zero days", {"staleDays": 0}, refuse("malformed_request")))
    add(S("vault.doctor_scan", "an agent never scans the vault", {}, refuse("capability_not_held"), "agent:acme"))
    # ADR-167: tags. Normalising, limits, agents and the cross-node rule in depth: brokerd/tests/tags.rs. Cleared again
    # at the end of the group so later rows see API_KEY as it was.
    add(S("entry.list", "acme's first two ids, for the merge rows", {"node": "acme"},
          ok("{ids}", shape(node="acme", ids=lambda i: len(i) >= 2)),
          save=_save(acme_two=lambda v: "+".join(sorted(v["ids"][:2])))))
    add(S("entry.tag_set", "tag API_KEY (normalised, generation-checked)",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "tags": ["Matrix Tag", "prod", "PROD"]},
          ok("{tags:[matrix-tag, prod], generation}", shape(node="acme", tags=["matrix-tag", "prod"], generation=_positive)),
          primary=True))
    add(S("entry.list", "a tag narrows one node's list", {"node": "acme", "tag": "Matrix Tag"},
          ok("{names:[API_KEY], tag}", shape(node="acme", tag="matrix-tag", names=["API_KEY"]))))
    add(S("entry.tag_set", "a tag with a comma is refused",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "tags": ["no,commas"]},
          refuse("malformed_request")))
    add(S("entry.tag_set", "a stale generation",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": 0, "tags": []}, refuse("conflict")))
    add(S("entry.tag_set", "an agent never tags",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "tags": ["x"]},
          refuse("capability_not_held"), "agent:acme"))
    add(S("entry.tag_set", "an empty list clears them",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "tags": []},
          ok("{tags:[]}", shape(tags=[], generation=_positive))))
    # ADR-168: merge.* inside one node. Every kind, apply and its undo, the sealed memory and the boundary are in
    # brokerd/tests/merge.rs and isolation.rs; here the shapes, the decision memory round trip and the refusals.
    add(S("merge.suggestions", "the owner's suggestions for acme name entries, never a value", {"node": "acme"},
          ok("{suggestions, valuesCompared; no value}", lambda v, c: (
              shape(node="acme", suggestions=list, truncated=bool, generation=_positive)(v, c),
              [_no_value(v, sv) for sv in c.secrets])), primary=True))
    add(S("merge.suggestions", "an agent never sees merge suggestions", {"node": "acme"},
          refuse("capability_not_held"), "agent:acme"))
    add(S("merge.dismiss", "dismiss a group of two acme entries", lambda c: {"node": "acme", "key": c["acme_two"]},
          ok("{dismissed:true, generation}", shape(node="acme", dismissed=True, generation=_positive)), primary=True))
    add(S("merge.dismissed_list", "the dismissed group is remembered, with its entries' names", {"node": "acme"},
          ok("{dismissed ∋ the key}", lambda v, c: shape(
              node="acme", dismissed=lambda d: any(x.get("key") == c["acme_two"] for x in d))(v, c)), primary=True))
    add(S("merge.undismiss", "undismiss it", lambda c: {"node": "acme", "key": c["acme_two"]},
          ok("{restored:true}", shape(restored=True)), primary=True))
    add(S("merge.dismiss", "a key that names one entry is refused", lambda c: {"node": "acme", "key": c["e_api"]},
          refuse("malformed_request")))
    add(S("merge.restore_all", "nothing left to restore", {"node": "acme"},
          ok("{restored:0}", shape(node="acme", restored=0)), primary=True))
    add(S("merge.auto_all", "a dry run plans and writes nothing", {"node": "acme"},
          ok("{dryRun:true, planned, skipped}", shape(node="acme", dryRun=True, planned=list, skipped=list)), primary=True))
    add(S("merge.auto", "a key that is not an open identical suggestion is refused",
          lambda c: {"node": "acme", "key": c["acme_two"], "generation": c.gen("acme")}, refuse("malformed_request"),
          primary=True))
    add(S("merge.apply", "a stale generation merges nothing",
          lambda c: {"node": "acme", "keep": c["e_api"], "drop": [c["acme_two"].split("+")[0]], "generation": 0},
          refuse("conflict"), primary=True))
    add(S("merge.apply", "the kept entry cannot also be dropped",
          lambda c: {"node": "acme", "keep": c["e_api"], "drop": [c["e_api"]], "generation": c.gen("acme")},
          refuse("malformed_request")))
    add(S("merge.apply", "an agent never merges",
          lambda c: {"node": "acme", "keep": c["e_api"], "drop": ["e_000000000000"], "generation": c.gen("acme")},
          refuse("capability_not_held"), "agent:acme"))
    add(S("entry.get_by_ref", "API_KEY's short reference resolves to it", lambda c: {"reference": c["r_api"]},
          ok("{node, entry, name}", lambda v, c: shape(node="acme", entry=c["e_api"], name="API_KEY")(v, c)),
          primary=True))
    add(S("entry.get_by_ref", "a number no entry holds", {"reference": 999999999}, refuse("not_found")))
    add(S("entry.get_by_ref", "a reference that is not a number", {"reference": "x"}, refuse("malformed_request")))
    add(S("entry.set_expiry", "clear it again (later rows read no expiry)",
          lambda c: {"node": "acme", "entry": c["e_api"], "generation": c.gen("acme"), "clear": True},
          ok("{expiresAt:null}", shape(node="acme", expiresAt=None))))
    add(S("entry.history", "API_KEY's decisions in order, and no value",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{records, truncated:false}", shape(node="acme", truncated=False, records=lambda rs: (
              isinstance(rs, list) and any(r.get("action") == "entry.rotate" for r in rs)
              and all("value" not in r for r in rs)))),
          primary=True))
    add(S("entry.history", "entry missing", {"node": "acme"}, refuse("malformed_request")))
    add(S("entry.history", "an agent is not shown history", lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("entry.search", "names and aliases on one project", {"node": "acme", "term": "api"},
          ok("{results:[API_KEY]}", shape(node="acme", results=lambda rs: any(r.get("name") == "API_KEY" for r in rs))),
          primary=True))
    add(S("entry.search", "an empty term", {"node": "acme", "term": ""}, refuse("malformed_request")))
    add(S("entry.remove", "soft-delete SPARE_A into the 7-day archive",
          lambda c: {"node": "acme", "entry": c["e_spare_a"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(node="acme", removed=True, generation=_positive), audit=True),
          primary=True, save=_save_audit("a_remove_a")))
    add(S("entry.remove", "a stale generation", lambda c: {"node": "acme", "entry": c["e_spare_b"], "generation": 0},
          refuse("conflict", expectedGeneration=0)))
    add(S("entry.restore", "restore SPARE_A within the window",
          lambda c: {"node": "acme", "entry": c["e_spare_a"], "generation": c.gen("acme")},
          ok("{restoredName:SPARE_A}", shape(node="acme", restoredName="SPARE_A", generation=_positive)),
          primary=True))
    add(S("entry.restore", "nothing was removed under that id",
          lambda c: {"node": "acme", "entry": "e_000000000000", "generation": c.gen("acme")}, refuse("not_found")))
    add(S("entry.remove", "remove SPARE_B, to be undone by audit id",
          lambda c: {"node": "acme", "entry": c["e_spare_b"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(removed=True), audit=True), save=_save_audit("a_remove_b")))
    add(S("entry.undo", "undo that removal by its audit id (keep-both)",
          lambda c: {"node": "acme", "id": c["a_remove_b"], "generation": c.gen("acme"), "mode": "keep-both"},
          ok("{restoredName:SPARE_B}", shape(node="acme", restoredName="SPARE_B"))))

    # ---- 3b. the field model (ADR-078): one entry, several fields -----------------------------
    # Everything below works on one entry and removes it again, because later rows count six entries.
    add(S("entry.create", "one paste, one entry: four fields, the user's labels and order",
          lambda c: {"node": "acme", "name": "FIELDS_DB", "entryType": "server", "fields": [
              {"label": "host", "value": c["v_fld_host"]}, {"label": "username", "value": c["v_fld_user"]},
              {"label": "password", "value": c["v_fld_pass"]}, {"label": "notes", "value": c["v_fld_note"]}]},
          ok("{fieldCount:4, fieldIds:4, pending:false}", shape(
              node="acme", pending=False, fieldCount=4, fieldIds=_list_of(4), generation=int), audit=True),
          fatal=True,
          save=_save(e_fld=lambda v: v["entry"], f_host=lambda v: v["fieldIds"][0], f_user=lambda v: v["fieldIds"][1],
                     f_pass=lambda v: v["fieldIds"][2], f_note=lambda v: v["fieldIds"][3])))
    add(S("entry.create", "`value` and `fields` are alternatives, never both",
          lambda c: {"node": "acme", "name": "BOTH", "value": "x", "fields": [{"label": "a", "value": "b"}]},
          refuse("malformed_request")))
    add(S("entry.create", "a label is one line: a control character is refused, and nothing is created",
          {"node": "acme", "name": "BAD_LABEL", "fields": [{"label": "two\nlines", "value": "x"}]},
          refuse("malformed_request")))
    add(S("entry.get", "labels, types, masking and ids in order - and not one value",
          lambda c: {"node": "acme", "entry": c["e_fld"]},
          ok("{fieldCount:4, labels, type:server (pinned), no value anywhere}", lambda v, c: (
              shape(node="acme", name="FIELDS_DB", fieldCount=4, type="server", typeOverridden=True,
                    hasTotp=False, generation=_positive,
                    fields=_field_labels("host", "username", "password", "notes"))(v, c),
              _no_values("v_fld_host", "v_fld_user", "v_fld_pass", "v_fld_note")(v, c))), primary=True))
    add(S("entry.get", "no such entry", {"node": "acme", "entry": "e_000000000000"}, refuse("not_found")))
    add(S("entry.get", "entry missing", {"node": "acme"}, refuse("malformed_request")))
    add(S("entry.reveal", "reveal every field: four values, no single `value`",
          lambda c: {"node": "acme", "entry": c["e_fld"]},
          ok("{fields:4, no `value`}", lambda v, c: (
              shape(fields=lambda f: [x["value"] for x in f] == [c["v_fld_host"], c["v_fld_user"], c["v_fld_pass"],
                                                                 c["v_fld_note"]])(v, c),
              _absent("value")(v, c)))))
    add(S("entry.reveal", "reveal one field by id: `value` is that field's value",
          lambda c: {"node": "acme", "entry": c["e_fld"], "fieldIds": [c["f_pass"]]},
          ok("{value == the password, fields:1}", lambda v, c: shape(value=c["v_fld_pass"], fields=_list_of(1))(v, c))))
    add(S("entry.reveal", "an unknown field id is not_found, with no partial answer",
          lambda c: {"node": "acme", "entry": c["e_fld"], "fieldIds": [c["f_pass"], "f_deadbeef"]},
          refuse("not_found")))
    add(S("field.add", "append a field (generation-checked)",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"),
                     "fields": [{"label": "region", "value": c["v_fld_extra"]}]},
          ok("{fieldCount:5, added:1}", shape(
              node="acme", fieldCount=5, added=_list_of(1), fieldIds=_list_of(5), generation=_positive), audit=True),
          primary=True, save=_chain(_save(f_region=lambda v: v["added"][0]), _save_audit("a_fld_add"))))
    add(S("field.add", "a stale generation is a conflict, not an overwrite",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": 0, "fields": [{"label": "x", "value": "y"}]},
          refuse("conflict", expectedGeneration=0, currentGeneration=_positive)))
    add(S("field.add", "nothing to add",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "fields": []},
          refuse("malformed_request")))
    add(S("field.update", "rename a field and pin its type",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "field": c["f_region"],
                     "patch": {"label": "location", "type": "text"}},
          ok("{fieldCount:5}", shape(node="acme", fieldCount=5, generation=_positive)), primary=True))
    add(S("entry.get", "the rename and the pin show, and the id did not change",
          lambda c: {"node": "acme", "entry": c["e_fld"]},
          ok("{the renamed field keeps its id and shows typeOverridden}", lambda v, c: shape(
              fields=lambda f: any(x["id"] == c["f_region"] and x["label"] == "location"
                                   and x["typeOverridden"] is True for x in f))(v, c))))
    add(S("field.update", "an unknown field", lambda c: {"node": "acme", "entry": c["e_fld"],
                                                         "generation": c.gen("acme"), "field": "f_deadbeef",
                                                         "patch": {"label": "x"}}, refuse("not_found")))
    add(S("field.update", "an empty patch changes nothing and is refused",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "field": c["f_region"],
                     "patch": {}}, refuse("malformed_request")))
    add(S("field.reorder", "move the new field first",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"),
                     "order": [c["f_region"], c["f_host"], c["f_user"], c["f_pass"], c["f_note"]]},
          ok("{fieldIds[0] == the new field}", lambda v, c: shape(
              fieldIds=lambda ids: isinstance(ids, list) and ids[0] == c["f_region"], generation=_positive)(v, c)),
          primary=True))
    add(S("field.reorder", "an order that is not an exact permutation is refused",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"),
                     "order": [c["f_region"], c["f_host"]]}, refuse("malformed_request")))
    add(S("entry.update", "one value of several: `field` says which (the old call shape needs it)",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "value": c["v_fld_edit"]},
          refuse("malformed_request", message=lambda m: isinstance(m, str) and "pass params.field" in m)))
    add(S("entry.update", "with `field` it replaces that one field's value",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "field": c["f_user"],
                     "value": c["v_fld_edit"]},
          ok("{fieldCount:5}", shape(node="acme", fieldCount=5, generation=_positive))))
    add(S("entry.reveal", "and only that value changed",
          lambda c: {"node": "acme", "entry": c["e_fld"], "fieldIds": [c["f_user"], c["f_host"]]},
          ok("{host unchanged, username edited}", lambda v, c: shape(
              fields=lambda f: [x["value"] for x in f] == [c["v_fld_host"], c["v_fld_edit"]])(v, c))))
    add(S("totp.code", "an entry with several fields and no TOTP seed needs `field`, and says so",
          lambda c: {"node": "acme", "entry": c["e_fld"]},
          refuse("malformed_request", message=lambda m: isinstance(m, str) and "pass params.field" in m)))
    add(S("field.remove", "remove the note field (undoable)",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme"), "field": c["f_note"]},
          ok("{fieldCount:4}", shape(node="acme", fieldCount=4, generation=_positive), audit=True),
          primary=True, save=_save_audit("a_fld_rm")))
    add(S("field.remove", "an unknown field", lambda c: {"node": "acme", "entry": c["e_fld"],
                                                         "generation": c.gen("acme"), "field": c["f_note"]},
          refuse("not_found")))
    add(S("entry.undo", "undo the field removal by its audit id (ADR-086: ok + what was restored)",
          lambda c: {"node": "acme", "id": c["a_fld_rm"], "generation": c.gen("acme")},
          ok("{ok:true, restored:{action:field.remove}}", shape(
              node="acme", undoneToGeneration=int, generation=_positive, ok=True,
              restored=lambda r: r.get("action") == "field.remove" and _kind_ok(int, r.get("fieldCount"))))))
    add(S("entry.reveal", "the removed field is back with its value (and fieldCount is 5 again)",
          lambda c: {"node": "acme", "entry": c["e_fld"], "fieldIds": [c["f_note"]]},
          ok("{value == the note}", lambda v, c: shape(value=c["v_fld_note"])(v, c))))
    add(S("entry.create_batch", "a batch item may carry fields too",
          lambda c: {"node": "acme", "entries": [
              {"name": "FIELDS_BATCH", "fields": [{"label": "token", "value": c["v_fld_batch"]},
                                                   {"label": "region", "value": "eu"}]}]},
          ok("{created:1 (2 fields)}", shape(
              node="acme", complete=True,
              created=lambda x: isinstance(x, list) and len(x) == 1 and x[0]["fieldCount"] == 2)),
          save=_save(e_fld_batch=lambda v: v["created"][0]["entry"])))
    add(S("entry.get", "an agent in a sibling project is denied by the graph (R8)",
          lambda c: {"node": "beta", "entry": c["e_fld"]},
          refuse("node_access_denied", rule="R8", subject="acme", target="beta", capability="read"), "agent:acme"))
    add(S("field.add", "and so is a field write there",
          lambda c: {"node": "beta", "entry": c["e_fld"], "generation": 1, "fields": [{"label": "x", "value": "y"}]},
          refuse("node_access_denied", rule="R8", target="beta", capability="update"), "agent:acme"))
    add(S("entry.get", "an unscoped process holds no `read` capability",
          lambda c: {"node": "acme", "entry": c["e_fld"]}, refuse("capability_not_held", capability="read"), "anon"))
    add(S("field.remove", "nor `update`",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": 1, "field": c["f_host"]},
          refuse("capability_not_held", capability="update"), "anon"))
    add(S("entry.remove", "remove the field-model entries again (later rows count six entries)",
          lambda c: {"node": "acme", "entry": c["e_fld"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(removed=True))))
    add(S("entry.remove", "and the batch one",
          lambda c: {"node": "acme", "entry": c["e_fld_batch"], "generation": c.gen("acme")},
          ok("{removed:true}", shape(removed=True))))

    add(S("notes.read", "no note yet - and the generation a write must be based on",
          {"node": "acme"},
          ok("{markdown:'', generation == entry.list's}", lambda v, c: (
              shape(node="acme", markdown="", generation=_positive)(v, c),
              _generation_is_current("acme")(v, c))), primary=True))
    add(S("notes.write", "write a note (generation-checked)",
          lambda c: {"node": "acme", "markdown": NOTE, "generation": c.gen("acme")},
          ok("{generation, cleared:false}", shape(node="acme", cleared=False, generation=_positive)),
          primary=True))
    add(S("notes.read", "the note reads back, with the generation the write left behind", {"node": "acme"},
          ok("{markdown == note, generation == entry.list's}", lambda v, c: (
              shape(node="acme", markdown=NOTE, generation=_positive)(v, c),
              _generation_is_current("acme")(v, c)))))
    add(S("notes.write", "a stale generation", {"node": "acme", "markdown": "x", "generation": 0},
          refuse("conflict", expectedGeneration=0)))
    add(S("notes.write", "an empty note clears it",
          lambda c: {"node": "acme", "markdown": "", "generation": c.gen("acme")},
          ok("{cleared:true}", shape(cleared=True))))
    add(S("notes.read", "an agent reads its own note only on an Open node: a note is high-sensitivity text (ADR-174), and acme is Guarded",
          {"node": "acme"}, refuse("node_access_denied", rule="L1", subject="acme", target="acme", capability="notes"), "agent:acme"))
    add(S("notes.read", "an agent never reads another node's note (ADR-174)", {"node": "beta"},
          refuse("node_access_denied", target="beta"), "agent:acme"))
    add(S("notes.write", "an agent never writes a note: it has no `notes` capability (ADR-174)",
          {"node": "acme", "markdown": "x", "generation": 0}, refuse("capability_not_held", capability="notes"), "agent:acme"))

    # ---- 4. audit, grants, presence-gated ops ------------------------------------------------
    add(S("audit.tail", "the owner sees full records, and no record names a session token", {"limit": 500},
          ok("{records: full shape, entry.remove allowed, actors are non-secret names}", lambda v, c: (
              shape(records=lambda r: (
                  isinstance(r, list) and len(r) > 10
                  and all({"id", "timestamp", "actor", "action", "node", "decision"} <= set(x) for x in r)
                  and any(x["action"] == "entry.remove" and x["decision"] == "allow" for x in r)
                  and any(x["action"] == "entry.update" and x["decision"] == "deny" for x in r)))(v, c),
              _audit_feed_is_clean(v, c),
              c.expect_session_named(v))),
          primary=True))
    add(S("audit.tail", "an agent gets the redacted feed (id, timestamp, actor, action) - and no bearer in it",
          {"limit": 50},
          ok("{records: 4 keys only, actors are non-secret names}", lambda v, c: (
              shape(records=lambda r: (
                  isinstance(r, list) and len(r) > 0
                  and all(set(x) == {"id", "timestamp", "actor", "action"} for x in r)))(v, c),
              _audit_feed_is_clean(v, c))), "agent:acme"))
    add(S("audit.tail", "an unscoped process (global, list-only) gets that feed too - and no bearer in it",
          {"limit": 500},
          ok("{records: 4 keys only, actors are non-secret names}", lambda v, c: (
              shape(records=lambda r: (
                  isinstance(r, list) and len(r) > 0
                  and all(set(x) == {"id", "timestamp", "actor", "action"} for x in r)))(v, c),
              _audit_feed_is_clean(v, c))), "anon"))
    add(S("audit.get", "a full record needs presence", lambda c: {"id": c["a_create"]},
          refuse("presence_required", operation="audit.get"), primary=True))
    add(S("audit.get", "an agent never holds admin", lambda c: {"id": c["a_create"]},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    # ---- the 2.0.0 broker batch (ADR-130...135): every one costs the owner's finger or is the owner's alone ----
    add(S("node.rekey", "the owner, after every check that needs no finger, is asked for presence",
          {"node": "acme"}, refuse("presence_required", operation="node.rekey"), primary=True))
    add(S("node.rekey", "an agent is not the owner", {"node": "acme"}, refuse("capability_not_held"), "agent:acme"))
    add(S("node.rekey", "the orphan node's cold key is not re-keyed", {"node": "orphan"}, refuse("malformed_request")))
    add(S("node.rekey", "node missing", {}, refuse("malformed_request")))
    # ADR-158: entry.move. The success path, the crash table, collisions and grants are in brokerd/tests/entry_move.rs
    # (it needs a presence proof, which this transport cannot give); here the refusals and the gate order.
    add(S("entry.move", "the owner, after every check that needs no finger, is asked for presence",
          lambda c: {"node": "acme", "entry": c["e_api"], "to": "beta", "generation": c.gen("acme")},
          refuse("presence_required", operation="entry.move"), primary=True))
    add(S("entry.move", "a stale generation costs no finger", lambda c: {"node": "acme", "entry": c["e_api"], "to": "beta",
                                                                          "generation": 0},
          refuse("conflict", expectedGeneration=0)))
    add(S("entry.move", "the node it is already in", lambda c: {"node": "acme", "entry": c["e_api"], "to": "acme",
                                                                 "generation": c.gen("acme")}, refuse("malformed_request")))
    add(S("entry.move", "an agent never moves an entry", lambda c: {"node": "acme", "entry": c["e_api"], "to": "beta",
                                                                     "generation": c.gen("acme")},
          refuse("capability_not_held"), "agent:acme"))
    # ADR-169: vault.doctor_apply. The applied plan, the generation chain, the stop-at-first-failure report and the
    # factors asked once are in brokerd/tests/doctor_apply.rs (a presence proof this transport cannot give); here the
    # refusals that come before any finger, and the gate order.
    add(S("vault.doctor_apply", "the owner, after every check that needs no finger, is asked for presence once for the plan",
          lambda c: {"moves": [{"node": "acme", "entry": c["e_api"], "to": "beta", "generation": c.gen("acme")}]},
          refuse("presence_required", operation="vault.doctor_apply"), primary=True))
    add(S("vault.doctor_apply", "a stale generation in the plan costs no finger",
          lambda c: {"moves": [{"node": "acme", "entry": c["e_api"], "to": "beta", "generation": 0}]},
          refuse("conflict", expectedGeneration=0)))
    add(S("vault.doctor_apply", "the same entry twice in one plan",
          lambda c: {"moves": [{"node": "acme", "entry": c["e_api"], "to": "beta", "generation": c.gen("acme")},
                               {"node": "acme", "entry": c["e_api"], "to": "global", "generation": c.gen("acme")}]},
          refuse("malformed_request")))
    add(S("vault.doctor_apply", "an empty plan", {"moves": []}, refuse("malformed_request")))
    add(S("vault.doctor_apply", "an agent never applies a plan",
          lambda c: {"moves": [{"node": "acme", "entry": c["e_api"], "to": "beta", "generation": c.gen("acme")}]},
          refuse("capability_not_held"), "agent:acme"))
    add(S("orphan.destroy", "with the word and the right count, presence is what is missing",
          {"confirm": "destroy-sealed-entries", "count": 0},
          refuse("presence_required", operation="orphan.destroy"), primary=True))
    add(S("orphan.destroy", "the confirmation word is exact", {"confirm": "yes", "count": 0}, refuse("malformed_request")))
    add(S("orphan.destroy", "an agent is not the owner", {"confirm": "destroy-sealed-entries", "count": 0},
          refuse("capability_not_held"), "agent:acme"))
    add(S("orphan.destroy", "count missing", {"confirm": "destroy-sealed-entries"}, refuse("malformed_request")))
    add(S("search.content", "a value nothing holds finds nothing", {"term": "zzz-no-such-value"},
          ok("{results:[], truncated:false}", shape(results=[], truncated=False)), primary=True))
    add(S("search.content", "a term under three characters is refused", {"term": "ab"}, refuse("malformed_request")))
    add(S("search.content", "term missing", {}, refuse("malformed_request")))
    add(S("search.content", "an unknown node", {"term": "abcdef", "node": "nowhere"}, refuse("not_found")))
    add(S("node.export", "a passphrase export needs presence", {"node": "acme", "passphrase": "a long export passphrase"},
          refuse("presence_required", operation="node.export"), primary=True))
    add(S("node.export", "an export is always encrypted", {"node": "acme"}, refuse("malformed_request")))
    add(S("node.export", "an agent is not the owner", {"node": "acme", "passphrase": "a long export passphrase"},
          refuse("capability_not_held"), "agent:acme"))
    add(S("audit.report", "an empty period reports zero records and an intact chain",
          {"from": 1700000000, "to": 1700864000},
          ok("{records:0, chain.verified}", shape(records=0, chain=lambda ch: ch.get("verified") is True)), primary=True))
    add(S("audit.report", "from must precede to", {"from": 10, "to": 5}, refuse("malformed_request")))
    add(S("audit.report", "an agent is not the owner", {"from": 1700000000, "to": 1700864000},
          refuse("capability_not_held"), "agent:acme"))
    add(S("node.gate_verify", "a node with no gate of its own has nothing to verify", {"node": "acme", "code": "000000"},
          refuse("malformed_request"), primary=True))
    add(S("node.gate_remove", "a node with no gate of its own has nothing to remove", {"node": "acme"},
          refuse("malformed_request"), primary=True))
    add(S("node.gate_enroll_confirm", "confirming without beginning enrols nothing", {"node": "acme", "code": "123456"},
          refuse("gate_not_enrolling"), primary=True))
    add(S("node.gate_enroll_begin", "the vault's own gate is not a node gate", {"node": "global"}, refuse("malformed_request")))
    add(S("node.gate_enroll_begin", "begin answers the secret's URI", {"node": "acme"},
          ok("{node, otpauthUri}", shape(node="acme", otpauthUri=_is_str(10))), primary=True))
    add(S("grant.list", "no grant can exist yet", {}, ok("{grants:[]}", shape(grants=[])), primary=True))
    add(S("grant.list", "an agent never holds admin", {}, refuse("capability_not_held", capability="admin"),
          "agent:acme"))
    add(S("grant.create", "creating a grant needs presence",
          {"from": "beta", "to": {"kind": "node", "nodeId": "acme"}, "scope": ["read"], "reason": "matrix: presence probe"},
          refuse("presence_required", operation="grant.create"), primary=True))
    add(S("grant.create", "`admin` is never grantable",
          {"from": "beta", "to": {"kind": "node", "nodeId": "acme"}, "scope": ["admin"], "reason": "matrix: bad scope"},
          refuse("malformed_request")))
    add(S("grant.create", "a reason under 8 characters",
          {"from": "beta", "to": {"kind": "node", "nodeId": "acme"}, "scope": ["read"], "reason": "short"},
          refuse("malformed_request")))
    add(S("grant.create", "orphan cannot be an endpoint",
          {"from": "orphan", "to": {"kind": "node", "nodeId": "acme"}, "scope": ["read"], "reason": "matrix: orphan"},
          refuse("malformed_request")))
    add(S("grant.create", "ADR-174: a single-entry grant must carry an expiry",
          lambda c: {"from": "beta", "to": {"kind": "entry", "nodeId": "acme", "entryId": c["e_api"]},
                     "scope": ["reveal"], "reason": "matrix: no expiry"},
          refuse("malformed_request")))
    add(S("grant.revoke", "no grant exists to revoke (create is presence-gated)", {"id": "g_000000000000"},
          refuse("not_found"), primary=True))
    add(S("grant.revoke", "id missing", {}, refuse("malformed_request")))
    add(S("node.reparent", "re-parenting widens reach, so it needs presence",
          {"node": "acme-api", "newParent": "beta", "reason": "matrix: presence probe"},
          refuse("presence_required", operation="node.reparent"), primary=True))
    add(S("node.reparent", "a reason under 8 characters", {"node": "acme-api", "newParent": "beta", "reason": "short"},
          refuse("malformed_request")))
    add(S("node.reparent", "Global cannot be re-parented",
          {"node": "global", "newParent": "acme", "reason": "matrix: global probe"}, refuse("malformed_request")))

    # ---- 5. agent scope and isolation --------------------------------------------------------
    add(S("whoami", "a process inside acme's workdir is scoped to acme, read-write, no admin", {},
          ok("{node:acme, 5 capabilities}", shape(
              node="acme", capabilities=_set_eq("list", "read", "reveal", "create", "update"),
              reachable=_contains("acme"))), "agent:acme"))
    add(S("entry.list", "an agent lists its own node - the pre-ADR-077 shape, no `entries` metadata (humans only)",
          {"node": "acme"},
          ok("{node, ids:6, names:6, generation}; no `entries`", lambda v, c: (
              shape(ids=_list_of(6), names=_list_of(6), generation=_positive)(v, c),
              _no_entries_metadata(v, c))), "agent:acme"))
    add(S("entry.list", "an agent cannot list a sibling project (R8)", {"node": "beta"},
          refuse("node_access_denied", rule="R8", subject="acme", target="beta", capability="list",
                 remedy=_is_str()), "agent:acme"))
    add(S("entry.reveal", "an agent cannot reveal in a sibling project (R8)",
          lambda c: {"node": "beta", "entry": c["e_api"]},
          refuse("node_access_denied", rule="R8", target="beta", capability="reveal"), "agent:acme"))
    add(S("node.create", "an agent never holds admin", {"id": "evil", "label": "x", "parentId": "acme"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("entry.list", "an unscoped process (cwd matches no workdir) is global, list-only", {"node": "acme"},
          refuse("node_access_denied", target="acme"), "anon"))
    add(S("entry.reveal", "an unscoped process holds no reveal capability",
          lambda c: {"node": "acme", "entry": c["e_api"]}, refuse("capability_not_held", capability="reveal"), "anon"))

    # ---- 6. node lock, the locked-write tray, approval-on-demand -----------------------------
    add(S("vault.node_lock", "lock acme alone", {"node": "acme"}, ok("{locked:true}", shape(node="acme", locked=True)),
          primary=True, fatal=True))
    add(S("vault.node_lock", "an agent never holds admin", {"node": "acme"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("entry.create", "a write into a locked node goes to the tray", lambda c: {
        "node": "acme", "name": "TRAY_ONE", "value": c["v_tray1"]},
          ok("{pending:true}", shape(node="acme", pending=True, entry=_is_str(3))), "agent:acme",
          save=_save(p1=lambda v: v["entry"])))
    add(S("entry.create", "and a second one", lambda c: {"node": "acme", "name": "TRAY_TWO", "value": c["v_tray2"]},
          ok("{pending:true}", shape(pending=True, entry=_is_str(3))), "agent:acme",
          save=_save(p2=lambda v: v["entry"])))
    add(S("vault.pending_list", "both are waiting for human review", {"node": "acme"},
          ok("{pending: TRAY_ONE, TRAY_TWO}", lambda v, c: shape(node="acme", pending=lambda p: (
              {x["name"] for x in p} == {"TRAY_ONE", "TRAY_TWO"}
              and {x["entry"] for x in p} == {c["p1"], c["p2"]}))(v, c)), primary=True))
    add(S("vault.pending_list", "node missing", {}, refuse("malformed_request")))
    add(S("vault.pending_accept", "accepting needs the node unlocked: node_locked, not vault_locked",
          lambda c: {"node": "acme", "entry": c["p1"]}, refuse("node_locked", node="acme", message=_is_str())))
    add(S("entry.update", "an owner write into a locked node is node_locked (the login is not over)",
          lambda c: {"node": "acme", "entry": c["e_api"], "value": "x", "generation": 0},
          refuse("node_locked", node="acme", remedy=lambda r: isinstance(r, str) and "vault.node_unlock" in r)))
    add(S("notes.read", "so is reading the note of a locked node", {"node": "acme"},
          refuse("node_locked", node="acme")))
    add(S("whoami", "and the owner session is still good afterwards", {},
          ok("{node:global}", shape(node="global", capabilities=_list_of(7)))))
    # (the two refusals come first: a refusal is remembered as ctx["last_error"], which the rows below read for the request id)
    add(S("vault.approval_get", "no such request", {"request": "rq_nope"}, refuse("not_found")))
    add(S("vault.approval_get", "an agent may not read the owner's prompts on an unlocked vault",
          {"request": "rq_nope"}, refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("entry.reveal", "an agent reveal on a locked node waits for a human (approval-on-demand)",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("approval_pending", request=_is_str(), expiresIn=_positive), "agent:acme"))
    # the request id rides on the error response, not in a value: run_step keeps the last refusal
    # as ctx["last_error"] for the decide rows below.
    # ADR-090: the person sees what is being asked before deciding it.
    add(S("vault.approval_get", "the owner sees what the waiting request asks for",
          lambda c: {"request": c["last_error"]["request"]},
          ok("{request, node:acme, command:entry.reveal, state:pending}", shape(
              node="acme", command="entry.reveal", state="pending", entry=ANY, request=_is_str(),
              nodeLabel=_is_str(), entryName=_is_str(), expiresIn=_positive)), primary=True))
    add(S("vault.approval_get", "with no request id it lists everything waiting", {},
          ok("{pending:[...]}", shape(pending=lambda p: isinstance(p, list) and len(p) >= 1))))
    add(S("vault.status", "and the status counts what is waiting, without naming it", {},
          ok("{pendingApprovals >= 1}", shape(pendingApprovals=_positive)), "anon"))
    add(S("vault.approval_decide", "the owner approves that single request", lambda c: {
        "request": c["last_error"]["request"], "approved": True},
          ok("{approved:true}", shape(approved=True, node="acme", entry=ANY, request=_is_str())), primary=True))
    add(S("entry.reveal", "the agent retries and gets the value, node still locked",
          lambda c: {"node": "acme", "entry": c["e_api"]}, ok("{value == v2}", lambda v, c: shape(value=c["v_api2"])(v, c)),
          "agent:acme"))
    add(S("entry.reveal", "a fresh request after the first was consumed",
          lambda c: {"node": "acme", "entry": c["e_api"]}, refuse("approval_pending", request=_is_str()), "agent:acme"))
    add(S("vault.approval_decide", "the owner denies this one", lambda c: {
        "request": c["last_error"]["request"], "approved": False}, ok("{approved:false}", shape(approved=False))))
    add(S("entry.reveal", "a denied request stays denied", lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("approval_denied", reason="denied"), "agent:acme"))
    add(S("vault.approval_decide", "no such request", {"request": "ar_nope", "approved": True}, refuse("not_found")))
    add(S("vault.approval_decide", "an agent never holds admin", {"request": "ar_nope", "approved": True},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("vault.approval_decide", "`approved` missing", {"request": "ar_nope"}, refuse("malformed_request")))
    # ADR-079 (K-7 4a). Approving STAGES the value - it is decrypted when the human decides, while a root
    # key is resident - and the retry only hands it over (the rows above show it: the value comes back with
    # the vault unlocked and no key derived). A lock drops whatever was staged; a wholly locked vault
    # answers vault_locked, because nobody can decide an approval then and nothing could complete one -
    # never an approval_pending that nothing could keep. Fail-closed throughout: no row below returns the
    # value, and the request id is 128-bit ("rq_" + 32 hex = 35 characters).
    add(S("entry.reveal", "a fresh request, for the staged-approval rows",
          lambda c: {"node": "acme", "entry": c["e_api"]}, refuse("approval_pending", request=_is_str()),
          "agent:acme"))
    add(S("vault.approval_decide", "the owner approves it - the value is staged now, at decide time",
          lambda c: {"request": c["last_error"]["request"], "approved": True},
          ok("{approved:true, request: 128-bit id}", shape(
              approved=True, request=lambda r: isinstance(r, str) and len(r) == 35 and r.startswith("rq_"))),
          save=_save(rq=lambda v: v["request"])))
    add(S("vault.lock", "the vault locks before the agent comes back: the staged value is dropped, not kept",
          {}, ok("{locked:true}", shape(locked=True))))
    add(S("entry.reveal", "the approval died with the lock - the answer says the lock did it, and no value comes",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("approval_denied", reason="locked", request=_is_str()), "agent:acme"))
    # ADR-088 (4b): a wholly locked vault records the request - a person can decide it with the unlock factors.
    add(S("entry.reveal", "locked as a whole, a reveal opens a request instead of a dead end",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("approval_pending", request=_is_str()), "agent:acme"))
    add(S("vault.approval_get", "locked, the request is still described - ids and names already in memory, nothing decrypted",
          lambda c: {"request": c["last_error"]["request"]},
          ok("{request, node:acme, state:pending}", shape(node="acme", state="pending", request=_is_str(),
                                                       entry=ANY, expiresIn=_positive)), "anon"))
    add(S("vault.approval_decide", "the passphrase decides it - no session, and the vault stays locked",
          lambda c: {"request": c["last_error"]["request"], "approved": True, "passphrase": c["pw"]},
          ok("{approved:true, authorisedBy:factors}", shape(approved=True, authorisedBy="factors")), "anon"))
    add(S("vault.status", "the vault is still locked after the release", {}, ok("{locked:true}", shape(locked=True)), "anon"))
    add(S("entry.reveal", "the agent gets exactly the approved value, once",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{value == v2}", lambda v, c: shape(value=c["v_api2"])(v, c)), "agent:acme"))
    add(S("vault.approval_decide", "nobody can decide while it is locked: the owner login ended with the lock",
          lambda c: {"request": c["rq"], "approved": True}, refuse("session_expired")))
    add(S("vault.approval_decide", "and an agent never holds admin, locked or not",
          lambda c: {"request": c["rq"], "approved": True}, refuse("capability_not_held", capability="admin"),
          "agent:acme"))
    add(S("vault.unlock", "the owner logs in again (acme is still locked on its own)",
          lambda c: {"passphrase": c["pw"]}, ok("{locked:false, token}", shape(locked=False, token=_is_str(8))),
          "anon", fatal=True, save=_save_secret("tok", lambda v: v["token"])))
    add(S("entry.reveal", "after the login the entry gets a fresh request - no value comes",
          lambda c: {"node": "acme", "entry": c["e_api"]},
          refuse("approval_pending", request=_is_str()), "agent:acme"))
    add(S("entry.reveal", "the next reveal is a new request, and needs a new human decision",
          lambda c: {"node": "acme", "entry": c["e_api"]}, refuse("approval_pending", request=_is_str()),
          "agent:acme"))
    add(S("vault.approval_decide", "deny it, so nothing is left waiting",
          lambda c: {"request": c["last_error"]["request"], "approved": False},
          ok("{approved:false}", shape(approved=False))))
    add(S("vault.node_unlock", "unlock acme", {"node": "acme"}, ok("{locked:false}", shape(node="acme", locked=False)),
          primary=True, fatal=True))
    add(S("vault.pending_accept", "accept TRAY_ONE into the node", lambda c: {"node": "acme", "entry": c["p1"]},
          ok("{accepted:true, generation}", shape(node="acme", accepted=True, generation=_positive)), primary=True))
    add(S("vault.pending_accept", "it is no longer in the tray", lambda c: {"node": "acme", "entry": c["p1"]},
          refuse("not_found")))
    add(S("vault.pending_discard", "discard TRAY_TWO", lambda c: {"node": "acme", "entry": c["p2"]},
          ok("{discarded:true}", shape(node="acme", discarded=True)), primary=True))
    add(S("vault.pending_discard", "it is gone", lambda c: {"node": "acme", "entry": c["p2"]}, refuse("not_found")))
    add(S("entry.list", "TRAY_ONE joined the node, TRAY_TWO did not", {"node": "acme"},
          ok("{names ∋ TRAY_ONE, ∌ TRAY_TWO}", shape(names=lambda n: "TRAY_ONE" in n and "TRAY_TWO" not in n))))

    # ---- 7. seal and restore -----------------------------------------------------------------
    add(S("entry.create", "put an entry in acme-api so the seal has something to carry",
          lambda c: {"node": "acme-api", "name": "SEALME", "value": c["v_seal"]},
          ok("{pending:false}", shape(pending=False, entry=_is_str(3))), save=_save(e_sealme=lambda v: v["entry"])))
    add(S("node.seal", "Global cannot be sealed", {"node": "global"}, refuse("malformed_request")))
    add(S("node.seal", "seal acme-api into orphan (7-day archive)", {"node": "acme-api"},
          ok("{sealed:true}", shape(node="acme-api", sealed=True)), primary=True))
    add(S("node.list", "acme-api left the graph", {}, ok("{nodes ∌ acme-api}", shape(
        nodes=lambda n: "acme-api" not in n and "acme" in n))))
    add(S("entry.list", "the orphan store is native-and-presence only (R0)", {"node": "orphan"},
          refuse("node_access_denied", rule="R0", target="orphan")))
    add(S("node.restore", "restore it inside the window", {"node": "acme-api"},
          ok("{restored:true}", shape(node="acme-api", restored=True)), primary=True))
    add(S("entry.reveal", "SEALME reads back unchanged after the seal/restore round trip",
          lambda c: {"node": "acme-api", "entry": c["e_sealme"]},
          ok("{value == sealed value}", lambda v, c: shape(value=c["v_seal"])(v, c))))
    add(S("node.restore", "node missing", {}, refuse("malformed_request")))
    add(S("node.restore", "nothing is sealed under that id", {"node": "acme-api"}, refuse("not_found")))

    # ---- 8. maintenance ----------------------------------------------------------------------
    add(S("maintenance.verify", "every node's manifest, binding and envelope digests hold", {},
          ok("{ok:true, errors:[]}", shape(ok=True, errors=[], nodesChecked=_positive, warnings=list)), primary=True))
    add(S("maintenance.doctor", "default apply on a healthy vault finds nothing to fix", {},
          ok("{applied:true, fixCount:0}", shape(applied=True, fixCount=0, fixes=[], unfixable=[])), primary=True))
    add(S("maintenance.doctor", "a dry run that asks about expired seals only lists them (none here)",
          {"apply": False, "purgeExpiredSeals": True},
          ok("{applied:false, no would-purge rows}", shape(applied=False, fixes=lambda f: not any(
              x["type"] == "would-purge-expired-seal" for x in f)))))
    add(S("maintenance.doctor", "purgeExpiredSeals must be a boolean", {"purgeExpiredSeals": "yes"},
          refuse("malformed_request")))
    add(S("maintenance.doctor", "dry run", {"apply": False}, ok("{applied:false, fixCount:0}", shape(
        applied=False, fixCount=0))))
    add(S("maintenance.doctor", "rebuildRegistry needs the passphrase param", {"rebuildRegistry": True},
          refuse("malformed_request")))
    add(S("maintenance.doctor", "rebuildRegistry itself needs presence", lambda c: {
        "rebuildRegistry": True, "passphrase": c["pw"]}, refuse("presence_required")))
    add(S("maintenance.backup", "an encrypted snapshot lands in the vault's backups directory",
          lambda c: {"passphrase": c["bpw"], "retain": 3},
          ok("{path under backups/, file exists}", lambda v, c: (
              shape(path=_is_str(), retain=3, pruned=ANY)(v, c), c.expect_backup(v["path"]))), primary=True))
    add(S("maintenance.backup", "an empty backup passphrase", {"passphrase": ""}, refuse("malformed_request")))
    add(S("maintenance.backup", "an agent never holds admin", {"passphrase": "x"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))

    add(S("maintenance.rotate_root", "after the human, admin and (no gate yet) checks, the documented presence "
                                     "refusal - no transport can attest presence yet (ADR-076)",
          lambda c: {"passphrase": c["pw"]}, refuse("presence_required", operation="maintenance.rotate_root"),
          primary=True))
    add(S("maintenance.rotate_root", "passphrase missing", {}, refuse("malformed_request")))
    add(S("maintenance.rotate_root", "an empty passphrase", {"passphrase": ""}, refuse("malformed_request")))
    add(S("maintenance.rotate_root", "an agent never holds admin", {"passphrase": "x"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("maintenance.rotate_root", "an unscoped process is never an admin", {"passphrase": "x"},
          refuse("capability_not_held", capability="admin"), "anon"))

    # ADR-156: changing the passphrase is a root rotation (brokerd/tests/set_passphrase.rs); these rows rotate
    # nothing, so the passphrase the later rows use still opens the vault.
    add(S("vault.set_passphrase", "newPassphrase missing", {"passphrase": "x"}, refuse("malformed_request"), primary=True))
    add(S("vault.set_passphrase", "the same passphrase again is refused and nothing rotates",
          lambda c: {"passphrase": c["pw"], "newPassphrase": c["pw"]}, refuse("malformed_request")))
    add(S("vault.set_passphrase", "an agent never holds admin", {"passphrase": "x", "newPassphrase": "y"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("vault.anomalies_ack", "the owner clears the anomaly notice", {},
          ok("{acknowledged}", shape(acknowledged=ANY)), primary=True))
    add(S("vault.anomalies_ack", "an agent never holds a login", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))

    # ADR-164: node-scoped agent tokens. No presence key is enrolled here, so issuing stops at the Touch ID
    # gate after every check that needs no finger; brokerd/tests/agent_tokens.rs and isolation I-30 cover the
    # token itself. No vault gate is enrolled yet at this point, so the second factor is not asked.
    add(S("agent.token_issue", "a valid request stops at the Touch ID gate, nothing minted",
          {"node": "acme", "label": "matrix agent", "capabilities": ["list"], "expiresIn": 3600},
          refuse("presence_required", operation="agent.token_issue"), primary=True))
    add(S("agent.token_issue", "admin is never an agent token's",
          {"node": "acme", "label": "matrix agent", "capabilities": ["admin"]}, refuse("malformed_request")))
    add(S("agent.token_issue", "an expiry beyond seven days",
          {"node": "acme", "label": "matrix agent", "capabilities": ["list"], "expiresIn": 604801},
          refuse("malformed_request")))
    add(S("agent.token_issue", "label missing", {"node": "acme", "capabilities": ["list"]},
          refuse("malformed_request")))
    add(S("agent.token_issue", "never for Global: a token is for one project (review P2-7)",
          {"node": "global", "label": "matrix agent", "capabilities": ["list"]}, refuse("malformed_request")))
    add(S("agent.token_issue", "an agent never mints a token",
          {"node": "acme", "label": "self", "capabilities": ["list"]},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("agent.token_status", "no token is live, metadata only", {},
          ok("{tokens:[], max, defaultExpiresIn, maxExpiresIn}",
             shape(tokens=[], max=32, defaultExpiresIn=86400, maxExpiresIn=604800)), primary=True))
    add(S("agent.token_status", "an agent never lists tokens", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("agent.token_rotate", "no token exists to rotate", {"id": "a_0000000000000000"},
          refuse("not_found"), primary=True))
    add(S("agent.token_rotate", "an agent never rotates a token", {"id": "a_0000000000000000"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("agent.token_revoke", "no token exists to revoke", {"id": "a_0000000000000000"},
          refuse("not_found"), primary=True))
    add(S("agent.token_revoke", "id missing", {}, refuse("malformed_request")))
    add(S("agent.token_revoke", "an agent never revokes a token", {"id": "a_0000000000000000"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))

    # ---- 8b. presence, Touch ID unlock and sealed entries (ADR-098) -----------------------------
    # The daemon here has no Secure Enclave helper beside it and no key is enrolled, so these rows pin
    # the refusals and the empty states; the proofs themselves are exercised by brokerd/tests/presence.rs
    # and scripts/e2e-presence.sh against the real Enclave.
    add(S("presence.status", "nothing enrolled, Touch ID unlock off",
          {}, ok("{enrolled:[], touchIdUnlock:false}", shape(enrolled=[], touchIdUnlock=False, helper=ANY,
                                                           secureEnclave=ANY, biometry=ANY, passcode=ANY)),
          primary=True))
    add(S("presence.status", "an agent never holds a login", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("presence.challenge", "no presence key enrolled yet", {"op": "audit.get", "params": {}},
          refuse("presence_failed", reason="not_enrolled"), primary=True))
    add(S("presence.challenge", "an op that takes no proof gets no challenge", {"op": "entry.list", "params": {}},
          refuse("malformed_request")))
    add(S("presence.challenge", "op missing", {}, refuse("malformed_request")))
    add(S("presence.challenge", "an agent never holds a login", {"op": "audit.get", "params": {}},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("presence.enrol", "publicKey missing", {}, refuse("malformed_request"), primary=True))
    add(S("presence.enrol", "a key that is not a P-256 point", {"publicKey": "AAAA"}, refuse("malformed_request")))
    add(S("presence.enrol", "an agent never holds admin", {"publicKey": "AAAA"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("presence.unenrol", "id missing", {}, refuse("malformed_request"), primary=True))
    add(S("presence.unenrol", "an agent never holds admin", {"id": "x"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("device.enrol", "no Secure Enclave helper beside this daemon", {},
          refuse("presence_failed", reason="unavailable"), primary=True))
    add(S("device.enrol", "an agent never holds admin", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("device.remove", "removing what is not there is not an error", {},
          ok("{touchIdUnlock:false}", shape(touchIdUnlock=False)), primary=True))
    add(S("device.remove", "an agent never holds admin", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    # ADR-163: the recovery-code unlock is for a LOCKED vault; on this open one it is refused before any code is read
    # and nothing rotates (the success path and its crash points are brokerd/tests/recover_unlock.rs).
    add(S("vault.recover", "an open vault is refused: change the passphrase instead",
          {"recoveryCode": "0" * 64, "newPassphrase": "a new passphrase"}, refuse("malformed_request"), primary=True))
    add(S("vault.recover", "an agent is refused before any code is read",
          {"recoveryCode": "0" * 64, "newPassphrase": "a new passphrase"},
          refuse("capability_not_held"), "agent:acme"))
    # ---- 8b'. the machine lock (ADR-165): bind (two phases since review N1: prepare shows the new code and changes nothing,
    # commit takes it typed back) proves the passphrase and the current recovery code, rotates the root key,
    # re-keys every project and seals root.wrap.pass under a device key in the state directory (review P0-1, P1-1); its
    # NEW recovery code replaces "rc" for the rows after it. Unbind puts the plain wrap back; with no gate and no presence
    # key yet it needs the passphrase (review P2-4). The refusals on another machine, the swap attack and the recovery
    # path are brokerd/tests/machine_lock.rs.
    ML = dict(bound=ANY, tier=ANY, secureEnclave=False, opensHere=True, sealedKeyId=ANY, damaged=False,
              deviceKeyPresent=ANY, deviceKeyId=ANY, deviceKeyUnreadable=False, deviceKeyModeOpen=False,
              deviceKeyForeignOwner=False, recoveryUnlock=True, plainWhileBound=False, preBindNodes=[],
              # ADR-174: no presence key or gate yet (O-5), a temporary folder no sync service shares (O-3), and the
              # device key's Time Machine state, which depends on the host (O-2).
              bindProof="none", syncedFolder=None, deviceKeyTimeMachineExcluded=ANY, deviceKeyTimeMachineCovered=ANY,
              protects=_is_str(20), doesNotProtect=_is_str(20))
    add(S("keystore.status", "off on a new vault: the honest tier, never the Secure Enclave", {},
          ok("{bound:false, tier:off, secureEnclave:false}", shape(**{**ML, "bound": False, "tier": "off"})), primary=True))
    add(S("keystore.status", "an agent is refused before anything is read", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("keystore.bind", "an agent never holds admin",
          {"phase": "prepare", "passphrase": "x", "recoveryCode": "0" * 64},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("keystore.bind", "phase is required (prepare, commit or cancel)", {}, refuse("malformed_request")))
    add(S("keystore.bind", "prepare: passphrase and recoveryCode are required", {"phase": "prepare"},
          refuse("malformed_request")))
    add(S("keystore.bind", "prepare: a recovery code that is not the current one changes nothing (a counted guess)",
          lambda c: {"phase": "prepare", "passphrase": c["pw"],
                     "recoveryCode": "0000-0000-0000-0000-0000-0000-0000-0000"},
          refuse("recovery_code_mismatch")))
    add(S("keystore.bind", "commit with nothing prepared changes nothing", lambda c: {"phase": "commit", "recoveryCode": c["rc"]},
          refuse("malformed_request")))
    # Review N1: prepare changes nothing and shows the new code; the commit takes it typed back.
    add(S("keystore.bind", "prepare: changes nothing, shows the NEW recovery code the commit will install",
          lambda c: {"phase": "prepare", "passphrase": c["pw"], "recoveryCode": c["rc"]},
          ok("{bound:false, phase:prepare, changed:false, already:false, newRecoveryCode, expiresIn}",
             shape(**{**ML, "bound": False, "tier": "off", "phase": "prepare", "changed": False, "already": False,
                      "newRecoveryCode": _is_str(20), "expiresIn": ANY, "nodesToRekey": ANY})),
          save=_save_secret("rc_new", lambda v: v["newRecoveryCode"])))
    add(S("keystore.bind", "commit: the OLD code typed back is not the one shown (not counted; the bind still waits)",
          lambda c: {"phase": "commit", "recoveryCode": c["rc"]}, refuse("recovery_code_mismatch")))
    add(S("keystore.bind", "commit: rotates the root key, re-keys every project and seals to a new device key file",
          lambda c: {"phase": "commit", "recoveryCode": c["rc_new"]},
          ok("{bound:true, tier:file, changed:true, deviceKeyCreated:true, nodesRekeyed}",
             shape(**{**ML, "bound": True, "tier": "file", "changed": True, "deviceKeyCreated": True,
                      "deviceKeyReplaced": False, "markedBound": True, "nodesRekeyed": ANY, "rekeyFailed": [], "orphanKeyReplaced": ANY,
                      "rotation": ANY})), primary=True,
          save=lambda c, v, resp: c.set_secret("rc", c["rc_new"])))
    add(S("keystore.bind", "a second prepare on a bound vault draws no code",
          lambda c: {"phase": "prepare", "passphrase": c["pw"], "recoveryCode": c["rc"]},
          ok("{bound:true, already:true, newRecoveryCode:null}",
             shape(**{**ML, "bound": True, "tier": "file", "phase": "prepare", "already": True,
                      "newRecoveryCode": None}))))
    add(S("keystore.bind", "and its commit changes nothing and reuses the key",
          {"phase": "commit"},
          ok("{bound:true, changed:false, deviceKeyCreated:false}",
             shape(**{**ML, "bound": True, "tier": "file", "changed": False, "deviceKeyCreated": False}))))
    add(S("keystore.bind", "cancel with nothing prepared is not an error", {"phase": "cancel"},
          ok("{changed:false}", shape(**{**ML, "bound": True, "tier": "file", "changed": False}))))
    add(S("keystore.status", "bound, and this machine holds the key", {},
          ok("{bound:true, tier:file, opensHere:true}", shape(**{**ML, "bound": True, "tier": "file"}))))
    add(S("keystore.unbind", "an agent never holds admin", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("keystore.unbind", "with no gate and no presence key the passphrase is required", {},
          refuse("malformed_request")))
    add(S("keystore.unbind", "puts the plain passphrase file back; the device key stays",
          lambda c: {"passphrase": c["pw"]},
          ok("{bound:false, tier:off, changed:true, deviceKeyPresent:true}",
             shape(**{**ML, "bound": False, "tier": "off", "changed": True, "deviceKeyPresent": True})), primary=True))
    add(S("keystore.unbind", "unbinding what is not bound is not an error", lambda c: {"passphrase": c["pw"]},
          ok("{bound:false, changed:false}", shape(**{**ML, "bound": False, "tier": "off", "changed": False}))))
    add(S("orphan.list", "names only", {}, ok("{entries:[...]}", shape(entries=ANY)), primary=True))
    add(S("orphan.list", "an agent never holds a login", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("orphan.reveal", "entry missing", {}, refuse("malformed_request"), primary=True))
    add(S("orphan.reveal", "an entry that is not sealed", {"entry": "e_000000000000"}, refuse("not_found")))
    add(S("orphan.reveal", "an agent never holds a login", {"entry": "e_000000000000"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))

    # ---- 8c. confirm before showing secrets (ADR-150) -----------------------------------------
    # The policy is off on this vault, so reveals elsewhere in the table are unaffected; these rows pin the
    # confirmation op itself. Policy on/off, refusals and windows: brokerd/tests/reveal_confirm.rs.
    add(S("session.confirm", "the vault passphrase confirms the owner's login",
          lambda c: {"passphrase": c["pw"]},
          ok("{confirmed:true, method:passphrase}", shape(confirmed=True, method="passphrase", expiresIn=ANY)),
          primary=True))
    add(S("session.confirm", "no passphrase means Touch ID, and no proof is presence_required", {},
          refuse("presence_required", operation="session.confirm")))
    add(S("session.confirm", "a passphrase that is not text", {"passphrase": 7}, refuse("malformed_request")))
    add(S("session.confirm", "an agent never holds a login", {"passphrase": "x"},
          refuse("capability_not_held", capability="admin"), "agent:acme"))

    # ---- 8d. the switchboard (ADR-155) -------------------------------------------------------
    # Every row runs on the real socket; the rules per caller are in brokerd/tests/switchboard.rs.
    add(S("settings.list", "every vault setting with its value and the owner's rule", {},
          ok("{caller:owner, settings}", shape(caller="owner", settings=lambda l: isinstance(l, list) and len(l) >= 15)),
          primary=True))
    add(S("settings.list", "an agent sees its own project's settings too", {"node": "acme"},
          ok("{caller:agent, settings}", shape(caller="agent", settings=lambda l: any(x.get("id") == "node.securityLevel" for x in l))),
          "agent:acme"))
    add(S("settings.get", "one setting in full", {"id": "app.autoLockMins"},
          ok("{id, value, recentChanges}", shape(id="app.autoLockMins", value=int, recentChanges=list)), primary=True))
    add(S("settings.get", "an unknown setting", {"id": "no.such"}, refuse("not_found")))
    add(S("settings.set", "the owner changes a cosmetic setting", {"id": "app.theme", "value": "dark", "reason": "matrix: theme"},
          ok("{applied:true, changeId}", lambda v, c: (shape(applied=True, change="cosmetic", changeId=_is_str(3))(v, c),
                                                        c.__setitem__("sc_theme", v["changeId"]))),
          primary=True))
    add(S("settings.set", "a value the setting does not take", {"id": "app.autoLockMins", "value": 7, "reason": "matrix: bad"},
          refuse("malformed_request")))
    add(S("settings.revert", "the owner puts the theme back", lambda c: {"change": c["sc_theme"]},
          ok("{applied:true}", shape(applied=True)), primary=True))
    add(S("settings.revert", "an unknown change", {"change": "sc-0000000000000000"}, refuse("not_found")))
    # ADR-155 amendment (wiring audit Q-1): an agent changes only its own node's settings, holding `update` there; a
    # vault setting is Global's and Global's own node settings are too (the full rules are isolation.rs I-32).
    add(S("settings.set", "a project agent may not change a vault setting, not even a cosmetic one",
          {"id": "app.theme", "value": "dark", "reason": "matrix: agent theme"},
          refuse("capability_not_held", capability="update"), "agent:acme"))
    add(S("settings.set", "nor Global's own node settings, not even to make them stricter",
          {"id": "node.lockAfterSeconds", "node": "global", "value": 60, "reason": "matrix: agent global"},
          refuse("capability_not_held", capability="update"), "agent:acme"))
    add(S("settings.set", "an agent's weakening change to its own project waits for the owner",
          {"id": "node.requireTwoFactor", "node": "acme", "value": "never", "reason": "matrix: agent asks"},
          ok("{state:pending, request}", lambda v, c: (shape(applied=False, state="pending", request=_is_str(3))(v, c),
                                                         c.__setitem__("sr_lock", v["request"]))),
          "agent:acme"))
    add(S("settings.request_get", "the agent reads its own request", lambda c: {"request": c["sr_lock"]},
          ok("{state:pending}", shape(state="pending")), "agent:acme", primary=True))
    add(S("settings.request_list", "the owner sees the waiting request", {},
          ok("{requests}", shape(requests=lambda l: isinstance(l, list) and len(l) >= 1)), primary=True))
    add(S("settings.request_list", "an agent never lists requests", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("settings.request_decide", "an agent never decides", lambda c: {"request": c["sr_lock"], "approve": True},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("settings.request_decide", "the owner denies it: nothing changes", lambda c: {"request": c["sr_lock"], "approve": False},
          ok("{state:denied}", shape(state="denied", applied=False)), primary=True))
    add(S("settings.kb", "the LLM knowledge base", {},
          ok("{markdown}", shape(markdown=lambda m: isinstance(m, str) and "credmgr_settings_set" in m)), "agent:acme", primary=True))

    # ---- 9. two-factor gate, lock, recovery --------------------------------------------------
    add(S("vault.gate_enroll_begin", "an agent never holds admin", {},
          refuse("capability_not_held", capability="admin"), "agent:acme"))
    add(S("vault.gate_enroll_begin", "stage a TOTP enrolment", {},
          ok("{otpauthUri}", shape(otpauthUri=lambda u: isinstance(u, str) and u.startswith("otpauth://totp/"))),
          primary=True, fatal=True,
          save=lambda c, v, r: c.set_secret("gate_secret", c.parse_otp_secret(v["otpauthUri"]))))
    add(S("vault.gate_enroll_confirm", "code missing", {}, refuse("malformed_request")))
    add(S("vault.gate_enroll_confirm", "a wrong code does not activate it", lambda c: {"code": c.wrong_code()},
          refuse("gate_verification_failed")))
    add(S("vault.gate_enroll_confirm", "a right code activates it and returns 10 recovery codes once",
          lambda c: {"code": c.gate_code(0)},
          ok("{recoveryCodes:10}", shape(recoveryCodes=_list_of(10))), primary=True, fatal=True,
          save=lambda c, v, r: [c.set_secret(f"grc{i}", code) for i, code in enumerate(v["recoveryCodes"])]))
    add(S("vault.gate_enroll_begin", "replacing an active gate needs the second factor, fresh", {},
          refuse("two_factor_required", scope="global", expiresIn=0)))
    add(S("maintenance.rotate_root", "with a gate enrolled and no fresh second factor, two_factor_required comes "
                                     "before the presence refusal",
          lambda c: {"passphrase": c["pw"]}, refuse("two_factor_required", scope="global", expiresIn=0)))
    add(S("grant.create", "ADR-174: with a gate enrolled a grant needs a fresh code, asked before presence",
          {"from": "beta", "to": {"kind": "node", "nodeId": "acme"}, "scope": ["read"], "reason": "matrix: code probe"},
          refuse("two_factor_required", scope="global", expiresIn=0)))
    add(S("vault.lock", "lock the vault (drops every login session)", {}, ok("{locked:true}", shape(locked=True)),
          primary=True, fatal=True))
    add(S("vault.status", "locked", {}, ok("{locked:true, initialized:true}", shape(locked=True, initialized=True)),
          "anon"))
    add(S("entry.list", "the login that was locked away is refused as session_expired", {"node": "acme"},
          refuse("session_expired"), "owner"))
    add(S("entry.create", "an agent can still write while locked - to the tray",
          lambda c: {"node": "acme", "name": "LOCKED_WRITE", "value": c["v_locked"]},
          ok("{pending:true}", shape(pending=True, entry=_is_str(3))), "agent:acme",
          save=_save(p3=lambda v: v["entry"])))
    add(S("entry.update", "but an update needs the vault unlocked", lambda c: {
        "node": "acme", "entry": c["e_api"], "value": "x", "generation": 0}, refuse("vault_locked"), "agent:acme"))
    add(S("vault.unlock", "factor 1 passed; a second factor is required", lambda c: {"passphrase": c["pw"]},
          refuse("two_factor_required", challenge="totp", scope="global", expiresIn=_positive), "anon"))
    add(S("vault.gate_verify", "code missing", {}, refuse("malformed_request"), "anon"))
    add(S("vault.gate_verify", "a wrong code", lambda c: {"code": c.wrong_code()},
          refuse("gate_verification_failed"), "anon"))
    add(S("vault.gate_verify", "the next TOTP step completes the login (the enrol step is spent)",
          lambda c: {"code": c.gate_code(1)},
          ok("{locked:false, token}", shape(locked=False, token=_is_str(8))), "anon", primary=True, fatal=True,
          save=_save_secret("tok", lambda v: v["token"])))
    add(S("vault.pending_list", "the locked-time write survived the lock", {"node": "acme"},
          ok("{pending ∋ LOCKED_WRITE}", shape(pending=lambda p: any(x["name"] == "LOCKED_WRITE" for x in p)))))
    add(S("vault.pending_discard", "discard it", lambda c: {"node": "acme", "entry": c["p3"]},
          ok("{discarded:true}", shape(discarded=True))))
    # Wiring audit Q-2 (ADR-064/163 amendment): the last door refuses an agent exactly as `vault.recover` does, before
    # either factor is read - here with both right factors, and the gate is still in force for the rows below.
    add(S("vault.gate_recover", "an agent is refused before either factor is read",
          lambda c: {"passphrase": c["pw"], "recoveryCode": c["rc"]}, refuse("capability_not_held", capability="admin"),
          "agent:acme"))
    add(S("vault.gate_recover", "a wrong root recovery code resets nothing",
          lambda c: {"passphrase": c["pw"], "recoveryCode": "0000-0000-0000"}, refuse("wrong_passphrase"), "anon"))
    add(S("vault.gate_recover", "recovery code missing", lambda c: {"passphrase": c["pw"]},
          refuse("malformed_request"), "anon"))
    add(S("vault.gate_recover", "passphrase + root recovery code reset the gate (the last door)",
          lambda c: {"passphrase": c["pw"], "recoveryCode": c["rc"]}, ok("{gateReset:true}", shape(gateReset=True)),
          "anon", primary=True))
    add(S("vault.lock", "lock again", {}, ok("{locked:true}", shape(locked=True))))
    add(S("vault.unlock", "with the gate reset the passphrase alone unlocks", lambda c: {"passphrase": c["pw"]},
          ok("{locked:false, token}", shape(locked=False, token=_is_str(8))), "anon", fatal=True,
          save=_save_secret("tok", lambda v: v["token"])))
    add(S("entry.reveal", "and the vault serves its data again", lambda c: {"node": "acme", "entry": c["e_api"]},
          ok("{value == v2}", lambda v, c: shape(value=c["v_api2"])(v, c))))
    add(S("audit.tail", "after three logins, two locks and a gate reset the feed still names no bearer - live "
                        "or dead", {"limit": 500},
          ok("{records: actors are non-secret names, none a session token seen in this run}", lambda v, c: (
              shape(records=lambda r: isinstance(r, list) and len(r) > 40)(v, c),
              _audit_feed_is_clean(v, c),
              c.expect_session_named(v))), "owner"))

    # ---- 10. brute-force backoff (last: it leaves a 30 s lockout behind) ----------------------
    for i in range(1, 6):
        add(S("vault.unlock", f"wrong passphrase, consecutive failure {i}/5", {"passphrase": f"wrong-{i}"},
              refuse("wrong_passphrase"), "anon"))
    add(S("vault.unlock", "the 5th failure starts a lockout: even the right passphrase is refused",
          lambda c: {"passphrase": c["pw"]}, refuse("rate_limited", retryAfterSeconds=_positive), "anon"))
    add(S("vault.gate_verify", "the second factor shares that counter", {"code": "000000"},
          refuse("rate_limited", retryAfterSeconds=_positive), "anon"))
    add(S("vault.gate_recover", "and so does the last door", lambda c: {"passphrase": c["pw"], "recoveryCode": c["rc"]},
          refuse("rate_limited", retryAfterSeconds=_positive), "anon"))
    add(S("vault.lock", "lock is not an auth path: it still works during a lockout", {},
          ok("{locked:true}", shape(locked=True)), "anon"))
    return s


# --------------------------------------------------------------------------------------------
# coverage - the op list is the broker's, not this file's
# --------------------------------------------------------------------------------------------


@dataclass
class Coverage:
    real: set
    covered: set
    uncovered: list
    unknown: list
    no_primary: list
    many_primary: list

    @property
    def failed(self) -> bool:
        return bool(self.uncovered or self.unknown or self.no_primary or self.many_primary)


def compute_coverage(steps: list[Step], real: set) -> Coverage:
    covered = {st.op for st in steps if not st.probe}
    primaries: dict = {}
    for st in steps:
        if not st.probe and st.primary:
            primaries[st.op] = primaries.get(st.op, 0) + 1
    return Coverage(
        real=set(real),
        covered=covered,
        uncovered=sorted(set(real) - covered),
        unknown=sorted(covered - set(real)),
        no_primary=sorted(op for op in covered & set(real) if primaries.get(op, 0) == 0),
        many_primary=sorted(op for op in covered & set(real) if primaries.get(op, 0) > 1),
    )


def load_broker_ops() -> set:
    if not CORPUS_CHECK.is_file():
        raise RuntimeError(f"{CORPUS_CHECK} not found - cannot read the broker's op list")
    spec = importlib.util.spec_from_file_location("corpus_check", CORPUS_CHECK)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["corpus_check"] = mod  # dataclasses in that module resolve their own module by name
    spec.loader.exec_module(mod)
    ops = set(mod.broker_ops())
    if len(ops) < 10:
        raise RuntimeError(f"corpus_check.broker_ops() returned only {len(ops)} ops - refusing to trust it")
    return ops


def print_coverage(cov: Coverage) -> None:
    print(f"broker ops (corpus_check.broker_ops): {len(cov.real)}   covered by this table: {len(cov.covered & cov.real)}")
    for label, items, why in (
        ("UNCOVERED", cov.uncovered, "the broker dispatches it; no row exercises it - add one"),
        ("UNKNOWN", cov.unknown, "a row names it; the broker does not dispatch it - fix or delete the row"),
        ("NO PRIMARY", cov.no_primary, "no row is marked primary=True for it"),
        ("MANY PRIMARY", cov.many_primary, "more than one row is marked primary=True for it"),
    ):
        for op in items:
            print(f"  COVERAGE FAIL  {label:<12} {op}   ({why})")


# --------------------------------------------------------------------------------------------
# TOTP (RFC 6238, SHA-1, 6 digits, 30 s) - only to answer the gate the broker enrols
# --------------------------------------------------------------------------------------------


def totp(secret_b32: str, step_offset: int = 0, at: Optional[float] = None) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((at if at is not None else time.time()) // 30) + step_offset
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000)


# --------------------------------------------------------------------------------------------
# sandbox: one private directory, an environment built from scratch, the real daemon
# --------------------------------------------------------------------------------------------


def real_default_locations() -> list[Path]:
    """Where a real V2 vault / state tree would live for THIS user (mirrors crates/store/src/paths.rs),
    plus whatever the caller's environment points at. Never the V1 vault: that is not ours to look at."""
    home = Path(os.path.expanduser("~"))
    out = [home / ".credmgr"]
    if sys.platform == "darwin":
        out += [home / "Library/Application Support/credmgr", home / "Library/Application Support/credmgr-state"]
    else:
        data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local/share")
        state = Path(os.environ.get("XDG_STATE_HOME") or home / ".local/state")
        out += [data / "credmgr", state / "credmgr"]
    for var in ("CREDMGR_VAULT_DIR", "CREDMGR_STATE_DIR"):
        if os.environ.get(var):
            out.append(Path(os.environ[var]))
    seen, uniq = set(), []
    for p in out:
        if str(p) not in seen:
            seen.add(str(p))
            uniq.append(p)
    return uniq


def fingerprint(path: Path) -> Any:
    """Metadata only - names, sizes, mtimes, modes. File contents are never opened."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError as e:
        return f"unreadable:{e.errno}"
    if not stat.S_ISDIR(st.st_mode):
        return ("file", st.st_size, st.st_mtime_ns, stat.S_IMODE(st.st_mode))
    rows = [("dir", ".", st.st_mtime_ns, stat.S_IMODE(st.st_mode))]
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in sorted(dirs + files):
            full = os.path.join(root, name)
            try:
                s = os.lstat(full)
            except OSError:
                rows.append((os.path.relpath(full, path), "gone"))
                continue
            rows.append((os.path.relpath(full, path), s.st_size, s.st_mtime_ns, stat.S_IMODE(s.st_mode)))
    return rows


class Sandbox:
    def __init__(self, bin_dir: Path, keep: bool = False):
        tmp_base = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="cmx.", dir=tmp_base)))
        self.keep = keep
        self.bin_dir = bin_dir
        self.vault = self.root / "v"
        self.state = self.root / "s"
        self.home = self.root / "h"
        self.neutral = self.root / "n"  # a cwd that matches no registered workdir
        self.dirs = {
            "home": self.home,
            "wd_acme": self.root / "w" / "acme",
            "wd_acme2": self.root / "w" / "acme2",
            "wd_beta": self.root / "w" / "beta",
        }
        for p in (self.vault, self.state, self.home, self.neutral, *self.dirs.values(), self.root / "t",
                  self.dirs["wd_acme"] / "src"):
            p.mkdir(parents=True, exist_ok=True)
        self.socket = self.vault / "run" / "broker.sock"
        self.proc: Optional[subprocess.Popen] = None
        self.log = self.root / "credmgrd.log"
        try:
            self._assert_confined()
        except RuntimeError:
            shutil.rmtree(self.root, ignore_errors=True)  # nothing has run yet: leave nothing behind
            raise

    def env(self) -> dict:
        """Built from nothing: no CREDMGR_*, no real HOME, no XDG_*, no token. PATH only."""
        h = str(self.home)
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "HOME": h,
            "USERPROFILE": h,
            "XDG_DATA_HOME": h + "/.local/share",
            "XDG_STATE_HOME": h + "/.local/state",
            "XDG_CONFIG_HOME": h + "/.config",
            "XDG_CACHE_HOME": h + "/.cache",
            "APPDATA": h + "/appdata",
            "LOCALAPPDATA": h + "/localappdata",
            "TMPDIR": str(self.root / "t"),
            "CREDMGR_VAULT_DIR": str(self.vault),
            "CREDMGR_STATE_DIR": str(self.state),
        }

    def _assert_confined(self) -> None:
        env = self.env()
        for var in ("HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "CREDMGR_VAULT_DIR", "CREDMGR_STATE_DIR", "TMPDIR"):
            p = Path(os.path.realpath(env[var]))
            if self.root != p and self.root not in p.parents:
                raise RuntimeError(f"refusing to run: {var}={p} is outside the throwaway directory {self.root}")
        if len(str(self.socket)) > 100:
            raise RuntimeError(f"socket path too long for AF_UNIX ({len(str(self.socket))} bytes): {self.socket}")

    def start(self) -> None:
        daemon = self.bin_dir / "credmgrd"
        with open(self.log, "wb") as log:
            self.proc = subprocess.Popen([str(daemon)], env=self.env(), cwd=str(self.neutral),
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"credmgrd exited at startup ({self.proc.returncode}): {self.log_text()[:400]}")
            if self.socket.exists():
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect(str(self.socket))
                    s.close()
                    return
                except OSError:
                    pass
            time.sleep(0.05)
        raise RuntimeError("credmgrd did not start serving its socket within 30 s")

    def log_text(self) -> str:
        try:
            return self.log.read_text(errors="replace")
        except OSError:
            return ""

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def cleanup(self) -> None:
        self.stop()
        if self.keep:
            print(f"(kept) {self.root}")
        else:
            shutil.rmtree(self.root, ignore_errors=True)


class Wire:
    """One short connection per request, like the CLI's transport. The broker reads the peer's cwd
    when the connection is accepted, so `cwd` is held for the whole call (an agent is "launched
    inside" a workdir)."""

    def __init__(self, sock: Path):
        self.sock = str(sock)
        self.n = 0

    def call(self, op: str, params: Any, token: Optional[str] = None, cwd: Optional[Path] = None,
             raw: Optional[bytes] = None, timeout: float = 180.0) -> tuple[dict, Optional[str]]:
        self.n += 1
        rid = f"m{self.n}"
        if raw is not None:
            frame, sent_id = raw, None
        else:
            frame = (json.dumps({"id": rid, "op": op, "token": token, "params": params}, separators=(",", ":"))
                     + "\n").encode()
            sent_id = rid
        old = os.getcwd()
        if cwd is not None:
            os.chdir(cwd)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(self.sock)
            buf = b""
            try:
                s.sendall(frame)
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except (ConnectionResetError, BrokenPipeError):
                pass  # the broker closed on us: reported as Dropped below, unless a full line arrived
            finally:
                s.close()
        finally:
            if cwd is not None:
                os.chdir(old)
        if not buf.strip():
            raise Dropped("credmgrd closed the connection with no response")
        return json.loads(buf), sent_id


class Ctx:
    """Per-run state: generated secrets, ids captured from earlier responses, the wire."""

    def __init__(self, box: Sandbox, wire: Wire):
        self.box, self.wire = box, wire
        self.v: dict = {}
        self.secrets: set = set()
        self.last_error: dict = {}
        self.tokens: list = []  # every session token this run has been handed, live or dead
        for name in ("pw", "bpw", "v_api1", "v_api2", "v_api3", "v_db", "v_spare_a", "v_spare_b", "v_tray1",
                     "v_tray2", "v_seal", "v_locked", "v_fld_host", "v_fld_user", "v_fld_pass", "v_fld_note",
                     "v_fld_extra", "v_fld_edit", "v_fld_batch"):
            self.set_secret(name, ("pw-" if name in ("pw", "bpw") else "val-") + secrets.token_hex(10))
        # generated, never a real seed: 20 bytes = 160 bits (32 base32 chars), 10 bytes = 80 bits (16 chars)
        self.set_secret("otp_seed", base64.b32encode(os.urandom(20)).decode())
        self.set_secret("otp_short", base64.b32encode(os.urandom(10)).decode())
        # 9 bytes = 72 bits (15 base32 chars): under the 80-bit floor, so totp.code refuses it
        self.set_secret("otp_tiny", base64.b32encode(os.urandom(9)).decode().rstrip("="))

    def __getitem__(self, k: str) -> Any:
        if k == "last_error":
            return self.last_error
        if k not in self.v:
            raise KeyError(f"setup value `{k}` was never captured (an earlier step failed)")
        return self.v[k]

    def __setitem__(self, k: str, val: Any) -> None:
        self.v[k] = val

    def set_secret(self, k: str, val: str) -> None:
        self.v[k] = val
        self.secrets.add(val)
        if k == "tok":
            self.tokens.append(val)

    def dir(self, name: str) -> str:
        return str(self.box.dirs[name])

    def mask(self, text: str) -> str:
        for s in sorted(self.secrets, key=len, reverse=True):
            if s and len(s) >= 6:
                text = text.replace(s, "***")
        return text

    # -- support calls (not table rows) ----
    def gen(self, node: str) -> int:
        resp, _ = self.wire.call("entry.list", {"node": node}, token=self["tok"], cwd=self.box.neutral)
        if not resp.get("ok"):
            raise KeyError(f"could not read the current generation of {node}: {resp.get('error')}")
        return resp["value"]["generation"]

    def parse_otp_secret(self, uri: str) -> str:
        return urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]

    def gate_code(self, step_offset: int) -> str:
        return totp(self["gate_secret"], step_offset)

    def wrong_code(self) -> str:
        valid = {totp(self["gate_secret"], o) for o in range(-4, 5)}
        n = 0
        while True:
            cand = "%06d" % n
            if cand not in valid:
                return cand
            n += 1

    def expect_totp(self, code: str, seed: str) -> None:
        if code not in {totp(seed, o) for o in (-1, 0, 1)}:
            raise Mismatch("totp.code is not the RFC 6238 code for the stored seed")

    # An origin, an origin plus a session's public id, or a broker-internal writer (`system:entry.undo`
    # records the rotation an undo performs) - none of which can authenticate anything. `Factors` is the
    # actor of an approval decided with the unlock factors while the vault is locked (ADR-088): there is
    # no session to name, and the word carries no secret.
    ACTOR_RE = re.compile(r"^((HumanUi|Cli|Agent|Native)(:s_[0-9a-f]{16})?|Factors|system:[a-z_.]+)$")
    BEARER_RE = re.compile(r"cmt_[0-9a-fA-F]{8,}")

    def expect_no_bearer(self, feed: Any) -> None:
        """ADR-077. The audit feed must hold no session token (any this run was handed, nor anything
        bearer-shaped) and every actor must be a name that cannot authenticate: `Origin` or
        `Origin:s_<16 hex>`. Judged on the bytes of the response, not on a field the broker promises."""
        text = json.dumps(feed, sort_keys=True)
        for t in self.tokens:
            if t in text:
                raise Mismatch("the audit feed contains a live or dead session token - it can be replayed "
                               "as the owner (ADR-077)")
        if self.BEARER_RE.search(text):
            raise Mismatch("the audit feed contains a bearer-shaped string (cmt_...)")
        bad = sorted({r["actor"] for r in feed.get("records", []) if not self.ACTOR_RE.match(str(r.get("actor")))})
        if bad:
            raise Mismatch(f"audit actors that are not a non-secret name: {bad[:3]}")

    def expect_session_named(self, feed: Any) -> None:
        """The control for expect_no_bearer: the feed still tells sessions apart (a `HumanUi:s_...` actor
        exists), so 'no bearer' was not achieved by deleting the actor."""
        if not any(str(r.get("actor", "")).startswith("HumanUi:s_") for r in feed.get("records", [])):
            raise Mismatch("no record names the owner session by its public id (HumanUi:s_...)")

    def expect_backup(self, path: str) -> None:
        p = Path(os.path.realpath(path))
        backups = Path(os.path.realpath(self.box.vault / "backups"))
        if backups not in p.parents:
            raise Mismatch(f"backup path {p} is not inside {backups}")
        if not p.is_file() or p.stat().st_size == 0:
            raise Mismatch("backup file is missing or empty")


# --------------------------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------------------------


@dataclass
class Result:
    index: int
    step: Step
    # PASS | FAIL | XFAIL (known gap, as pinned) | XPASS (gap closed - marker is stale)
    # | BLOCKED (would pass, but depends on a gap that still holds - not evidence) | NOT RUN
    status: str
    detail: str = ""
    secs: float = 0.0


def who_args(ctx: Ctx, who: str) -> tuple[Optional[str], Path]:
    if who == "owner":
        return ctx["tok"], ctx.box.neutral
    if who == "anon":
        return None, ctx.box.neutral
    if who == "stale":  # a well-formed token the broker never minted
        return "t_" + secrets.token_hex(6), ctx.box.neutral
    if who.startswith("agent:"):
        name = who.split(":", 1)[1]
        return None, ctx.box.dirs["wd_" + name] / ("src" if name == "acme" else "")
    raise ValueError(f"unknown actor {who}")


def classify(st: Step, outcome: Any, ctx: Any, expect_id: Optional[str]) -> tuple[str, str]:
    """PASS / XFAIL / XPASS for one observed outcome, or raise Mismatch. Pure: no I/O."""
    try:
        evaluate(st.expect, outcome, ctx, expect_id)
    except Mismatch as documented_failure:
        if st.gap is None:
            raise
        try:
            evaluate(st.gap.observed, outcome, ctx, expect_id)
        except Mismatch as e:
            raise Mismatch(f"neither the documented behaviour ({documented_failure}) nor the pinned known "
                           f"gap {st.gap.id} ({e})") from None
        return "XFAIL", f"{st.gap.id}: {st.gap.text}"
    if st.gap is not None:
        return "XPASS", (f"known gap {st.gap.id} no longer reproduces - the documented behaviour holds. "
                         f"Delete this row's gap= marker (and, once no row uses it, the gap itself).")
    return "PASS", ""


def apply_block(status: str, st: Step, results: list) -> tuple[str, str]:
    """A row that depends on a known gap (`blocked_by`) proves nothing while that gap holds.

    Example: "SEALME reads back unchanged after the seal/restore round trip" passes today only
    because the seal never happened (K-7). A green PASS there would be a lie, so while any earlier row
    pinned to the same gap id is XFAIL, a row that would PASS is reported BLOCKED instead - loud, not
    counted as a pass, and (like a known gap) a failure under --strict. A row that would FAIL stays a
    FAIL. The day the gap closes its own row goes XPASS and fails the run, and the blocked rows are then
    judged on their merits. Pure."""
    if status == "PASS" and st.blocked_by:
        holds = any(r.status == "XFAIL" and r.step.gap is not None and r.step.gap.id == st.blocked_by
                    for r in results)
        if holds:
            return "BLOCKED", (f"{st.blocked_by} still holds, so this row proves nothing yet - it cannot "
                               f"count as a pass until the gap is fixed")
    return status, ""


def run_step(ctx: Ctx, idx: int, st: Step, verbose: bool) -> Result:
    t0 = time.time()
    try:
        params = st.params(ctx) if callable(st.params) else st.params
        token, cwd = who_args(ctx, st.who) if st.raw is None else (None, ctx.box.neutral)
        try:
            resp, sent_id = ctx.wire.call(st.op, params, token=token, cwd=cwd, raw=st.raw)
            outcome: Any = resp
            if verbose:
                print("        <- " + ctx.mask(_clip(resp, 400)))
            if not resp.get("ok"):
                ctx.last_error = resp
        except Dropped:
            outcome, sent_id = Dropped, None
            if verbose:
                print("        <- (connection closed, no response)")
        status, detail = classify(st, outcome, ctx, "?" if st.raw is not None else sent_id)
        if status == "PASS" and st.save and outcome is not Dropped and outcome.get("ok"):
            st.save(ctx, outcome["value"], outcome)
        return Result(idx, st, status, detail, time.time() - t0)
    except Mismatch as e:
        return Result(idx, st, "FAIL", ctx.mask(str(e)), time.time() - t0)
    except KeyError as e:
        return Result(idx, st, "FAIL", ctx.mask(f"setup: {e}"), time.time() - t0)
    except Exception as e:  # wire / JSON / OS error
        return Result(idx, st, "FAIL", ctx.mask(f"{type(e).__name__}: {e}"), time.time() - t0)


def run_invariants(box: Sandbox, ctx: Ctx, tripwire_before: dict,
                   expected_panics: int) -> list[tuple[str, bool, str]]:
    out: list[tuple[str, bool, str]] = []

    # 1. no generated secret appears as plaintext anywhere under the vault dir. "Secret" means EVERY value
    #    the run generated or was handed (ctx.secrets): entry values, passphrases, TOTP seeds (long and
    #    short), the gate secret, the root recovery code, the ten gate recovery codes - and every session
    #    token, live or dead. (An earlier version listed a hand-picked subset by name and so left out the
    #    session tokens, which is how a bearer sitting in the audit log went unseen: ADR-077.)
    hits = []
    needles = [x.encode() for x in ctx.secrets if len(x) >= 6]
    for root, _d, files in os.walk(box.vault):
        for f in files:
            p = Path(root) / f
            if p.name == "broker.sock":
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if any(n in data for n in needles):
                hits.append(str(p.relative_to(box.vault)))
    n_tokens = len(ctx.tokens)
    out.append((f"no plaintext secret under the vault directory ({len(needles)} generated secrets incl. "
                f"{n_tokens} session tokens)", not hits and n_tokens >= 3,
                f"found in {hits}" if hits else ("" if n_tokens >= 3 else
                                                 f"only {n_tokens} session tokens were captured - the control failed")))

    # 2. the socket is 0600 and its directory 0700
    try:
        sm = stat.S_IMODE(os.lstat(box.socket).st_mode)
        dm = stat.S_IMODE(os.lstat(box.socket.parent).st_mode)
        out.append(("socket 0600, run directory 0700", sm == 0o600 and dm == 0o700, f"socket {sm:o}, dir {dm:o}"))
    except OSError as e:
        out.append(("socket 0600, run directory 0700", False, str(e)))

    # 3. the daemon survived, and every panic in its log is one a pinned known gap predicted
    alive = box.proc is not None and box.proc.poll() is None
    out.append(("credmgrd still running at the end", alive,
                "" if alive else f"exited {box.proc.returncode if box.proc else '?'}"))
    panics = box.log_text().count("panicked at")
    out.append(("no unexpected panic in credmgrd's log", panics == expected_panics,
                f"{panics} panic(s) logged, {expected_panics} predicted by known gaps"))

    # 4. every byte the run wrote is inside the throwaway directory; the real default locations did not move
    after = {str(p): fingerprint(p) for p in real_default_locations()}
    moved = [p for p in tripwire_before if tripwire_before[p] != after.get(p)]
    out.append(("real default vault/state locations untouched", not moved,
                "changed: " + ", ".join(moved) if moved else f"{len(after)} location(s) watched, metadata only"))
    return out


def render_table(steps: list[Step], results: list[Result], real: set) -> tuple[list[dict], int]:
    by_op: dict = {}
    for r in results:
        if not r.step.probe:
            by_op.setdefault(r.step.op, []).append(r)
    rows, bad = [], 0
    for op in sorted(real | set(by_op)):
        rs = by_op.get(op, [])
        prim = next((r for r in rs if r.step.primary), None)
        n_pass = sum(1 for r in rs if r.status == "PASS")
        n_gap = sum(1 for r in rs if r.status == "XFAIL")
        n_blocked = sum(1 for r in rs if r.status == "BLOCKED")
        gaps = sorted({r.step.gap.id for r in rs if r.status == "XFAIL" and r.step.gap}
                      | {r.step.blocked_by for r in rs if r.status == "BLOCKED" and r.step.blocked_by})
        failing = [r for r in rs if r.status not in ("PASS", "XFAIL", "BLOCKED")]
        if not rs:
            status, exp = "FAIL (no row ran)", "-"
        else:
            exp = prim.step.expect.desc if prim else rs[0].step.expect.desc
            if failing:
                status = f"FAIL {len(rs) - len(failing)}/{len(rs)}"
            elif n_pass == 0:  # an op that demonstrated nothing but a gap has not been tested at all
                status = f"FAIL 0/{len(rs)} (no passing row)"
            elif n_gap or n_blocked:
                parts = [f"{n_pass} pass"]
                if n_gap:
                    parts.append(f"{n_gap} known gap")
                if n_blocked:
                    parts.append(f"{n_blocked} blocked")
                status = f"GAP {'+'.join(gaps)}: " + ", ".join(parts)
            else:
                status = f"PASS {n_pass}/{len(rs)}"
        if not (status.startswith("PASS") or status.startswith("GAP")):
            bad += 1
        rows.append({"op": op, "expectation": exp, "result": status, "rows": len(rs), "passed": n_pass,
                     "gaps": gaps})
    return rows, bad


def print_table(rows: list[dict]) -> None:
    w_op = max(len(r["op"]) for r in rows)
    w_ex = min(max(len(r["expectation"]) for r in rows), 64)
    print()
    print(f"{'op':<{w_op}}  {'expectation (primary row)':<{w_ex}}  result")
    print(f"{'-' * w_op}  {'-' * w_ex}  {'-' * 12}")
    for r in rows:
        ex = r["expectation"] if len(r["expectation"]) <= w_ex else r["expectation"][: w_ex - 1] + "…"
        print(f"{r['op']:<{w_op}}  {ex:<{w_ex}}  {r['result']}")


# --------------------------------------------------------------------------------------------
# self-check: the checker must be able to say no
# --------------------------------------------------------------------------------------------


def self_check() -> list[str]:
    """In-process, no daemon. Each case feeds the evaluator a response that is WRONG for its
    expectation and demands a Mismatch - so a checker that waved everything through cannot pass."""
    problems: list[str] = []
    fake = Ctx.__new__(Ctx)
    cases = [
        ("success expectation, error response", ok("x", shape(locked=True)),
         {"id": "a", "ok": False, "error": "vault_locked"}),
        ("success expectation, wrong field value", ok("x", shape(locked=True)),
         {"id": "a", "ok": True, "value": {"locked": False}}),
        ("success expectation, missing field", ok("x", shape(locked=True)), {"id": "a", "ok": True, "value": {}}),
        ("success expectation, wrong type", ok("x", shape(n=int)), {"id": "a", "ok": True, "value": {"n": True}}),
        ("refusal expectation, success response", refuse("presence_required"),
         {"id": "a", "ok": True, "value": {}}),
        ("refusal expectation, other refusal", refuse("presence_required"),
         {"id": "a", "ok": False, "error": "malformed_request"}),
        ("refusal expectation, wrong extra field", refuse("presence_required", operation="grant.create"),
         {"id": "a", "ok": False, "error": "presence_required", "operation": "node.reparent"}),
        ("refusal expectation, extra field absent", refuse("conflict", currentGeneration=ANY),
         {"id": "a", "ok": False, "error": "conflict"}),
        ("response id not echoed", ok("x", shape()), {"id": "zzz", "ok": True, "value": {}}),
        ("audit id required but absent", ok("x", shape(), audit=True), {"id": "a", "ok": True, "value": {}}),
    ]
    for name, expect, resp in cases:
        try:
            evaluate(expect, resp, fake, "a")
            problems.append(f"checker accepted a wrong response: {name}")
        except Mismatch:
            pass
    positives = [
        (ok("x", shape(locked=True)), {"id": "a", "ok": True, "value": {"locked": True}}),
        (refuse("presence_required", operation="grant.create"),
         {"id": "a", "ok": False, "error": "presence_required", "operation": "grant.create"}),
    ]
    for expect, resp in positives:
        try:
            evaluate(expect, resp, fake, "a")
        except Mismatch as e:
            problems.append(f"checker rejected a correct response: {e}")
    # a dropped connection satisfies nothing but a `dropped` expectation
    for expect in (ok("x"), refuse("internal"), answers("x")):
        try:
            evaluate(expect, Dropped, fake, "a")
            problems.append(f"checker accepted a dropped connection for `{expect.kind}`")
        except Mismatch:
            pass
    # known-gap bookkeeping: pinned -> XFAIL; documented behaviour appears -> XPASS (stale marker);
    # anything else -> Mismatch. A gap must be neither ignorable nor sticky.
    gap = KnownGap("T-1", "self-check gap", dropped("x"))
    gstep = S("t.op", "gap row", {}, answers("x"), gap=gap)
    live = {"id": "a", "ok": True, "value": {}}
    for label, outcome, want in (("the pinned break", Dropped, "XFAIL"), ("the break is fixed", live, "XPASS")):
        got = classify(gstep, outcome, fake, "a")[0]
        if got != want:
            problems.append(f"known-gap classification: {label} gave {got}, expected {want}")
    shifted = S("t.op", "gap row", {}, ok("x", shape(n=1)), gap=KnownGap("T-2", "t", refuse("internal")))
    try:
        classify(shifted, {"id": "a", "ok": False, "error": "vault_locked"}, fake, "a")
        problems.append("known-gap classification accepted a behaviour that is neither documented nor pinned")
    except Mismatch:
        pass
    if classify(S("t.op", "plain", {}, answers("x")), live, fake, "a")[0] != "PASS":
        problems.append("a plain passing row was not classified PASS")
    # The coverage logic is proven on a small synthetic table, NOT on the real one: checking the real
    # table against itself would turn a mistake in the table (two primaries on one op, a typo'd op
    # name) into "coverage logic is broken", sending the developer to the wrong file. A table mistake
    # is reported where it belongs - by print_coverage, which names the op - in main().
    def mk(op: str, primary: bool = True) -> Step:
        return S(op, "", {}, ok("x"), primary=primary)

    toy = [mk("a.op"), mk("b.op"), mk("b.op", primary=False), S("(frame)", "", {}, ok("x"), probe=True)]
    toy_real = {"a.op", "b.op"}
    if compute_coverage(toy, toy_real).failed:
        problems.append("coverage logic reports a failure on a correct table")
    if "b.op" not in compute_coverage([x for x in toy if x.op != "b.op"], toy_real).uncovered:
        problems.append("coverage logic did not notice a removed op")
    if "bogus.op" not in compute_coverage(toy + [mk("bogus.op")], toy_real).unknown:
        problems.append("coverage logic did not notice an unknown op")
    if "b.op" not in compute_coverage(toy + [mk("b.op")], toy_real).many_primary:
        problems.append("coverage logic did not notice a second primary row")
    if "b.op" not in compute_coverage([mk("a.op"), mk("b.op", primary=False)], toy_real).no_primary:
        problems.append("coverage logic did not notice an op with no primary row")
    # a probe is a negative control: it can never stand in for a row of a real op
    if "b.op" not in compute_coverage([mk("a.op"), S("b.op", "", {}, ok("x"), probe=True)], toy_real).uncovered:
        problems.append("coverage logic let a probe row cover a real op")
    # blocked-by-gap bookkeeping: a row that depends on a gap that still holds is not evidence
    held = [Result(1, S("t.seal", "", {}, ok("x"), gap=KnownGap("T-9", "t", dropped("x"))), "XFAIL")]
    dependent = S("t.dep", "", {}, answers("x"), blocked_by="T-9")
    if apply_block("PASS", dependent, held)[0] != "BLOCKED":
        problems.append("a row depending on a gap that still holds was allowed to PASS")
    if apply_block("PASS", dependent, [])[0] != "PASS":
        problems.append("a row was blocked by a gap that is not holding")
    if apply_block("FAIL", dependent, held)[0] != "FAIL":
        problems.append("blocking hid a genuine failure")
    if apply_block("PASS", S("t.dep", "", {}, answers("x")), held)[0] != "PASS":
        problems.append("a row with no dependency was blocked")
    return problems


# --------------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="CredMgr V2 endpoint matrix: every broker op over the real socket.")
    ap.add_argument("--bin", default=os.environ.get("BIN", "target/debug"),
                    help="directory holding the credmgrd binary (relative paths resolve against v2/)")
    ap.add_argument("--check-coverage", action="store_true", help="only compare the table with the broker's op list")
    ap.add_argument("--list", action="store_true", help="print the op list and exit")
    ap.add_argument("--json", metavar="FILE", help="also write the per-op table as JSON")
    ap.add_argument("--keep", action="store_true", help="keep the throwaway directory (debugging)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every raw response (secrets masked)")
    ap.add_argument("--strict", action="store_true",
                    help="treat pinned known gaps as failures (default: reported loudly, exit 0)")
    ap.add_argument("--drop-op", action="append", default=[], metavar="OP",
                    help="demonstration: remove every row of OP from the table, to show coverage fails")
    ap.add_argument("--mutate-op", action="append", default=[], metavar="OP",
                    help="demonstration: swap OP's expectations for impossible ones, to show the run fails")
    args = ap.parse_args()

    if os.name != "posix":
        print("endpoint-matrix: needs Unix-domain sockets (macOS / Linux)", file=sys.stderr)
        return EXIT_CANNOT_RUN

    try:
        real = load_broker_ops()
    except Exception as e:
        print(f"endpoint-matrix: cannot read the broker's op list: {e}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    steps = build_steps()
    for op in args.drop_op:
        steps = [x for x in steps if x.op != op]
    for op in args.mutate_op:
        for x in steps:
            if x.op == op and not x.probe:
                x.expect = refuse("__mutation_probe__", "(deliberately wrong)")

    if args.list:
        for op in sorted(real):
            print(op)
        return EXIT_OK

    problems = self_check()
    if problems:
        for p in problems:
            print(f"SELF-CHECK FAIL  {p}")
        return EXIT_FAIL
    print("self-check: the checker rejects wrong responses and the coverage logic sees missing/unknown ops")

    cov = compute_coverage(steps, real)
    print_coverage(cov)
    if args.check_coverage:
        print("coverage: " + ("FAIL" if cov.failed else f"ok - all {len(real)} broker ops have a row and one primary"))
        return EXIT_FAIL if cov.failed else EXIT_OK
    if cov.failed:
        print("coverage failed - not starting the daemon (fix the table first)")
        return EXIT_FAIL

    bin_dir = Path(args.bin)
    if not bin_dir.is_absolute():
        bin_dir = V2 / bin_dir
    if not (bin_dir / "credmgrd").is_file():
        print(f"endpoint-matrix: {bin_dir / 'credmgrd'} not found - run `cargo build -p credmgr-brokerd` in v2/ "
              f"(or pass --bin)", file=sys.stderr)
        return EXIT_CANNOT_RUN

    tripwire_before = {str(p): fingerprint(p) for p in real_default_locations()}
    try:
        box = Sandbox(bin_dir, keep=args.keep)
    except RuntimeError as e:
        print(f"endpoint-matrix: {e}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    def _interrupt(*_: Any) -> None:
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _interrupt)  # the finally below then stops the daemon and deletes the sandbox
    results: list[Result] = []
    invariants: list[tuple[str, bool, str]] = []
    t_start = time.time()
    try:
        print(f"sandbox: {box.root}  (vault, state, HOME, XDG_*, TMPDIR all inside it)")
        print(f"daemon:  {bin_dir / 'credmgrd'}")
        box.start()
        ctx = Ctx(box, Wire(box.socket))
        print()
        print(f"{'#':>3}  {'':<4}  {'who':<10} {'op':<26} expectation")
        aborted = False
        for i, st in enumerate(steps, 1):
            if aborted:
                results.append(Result(i, st, "NOT RUN", "an earlier fatal step failed"))
                continue
            r = run_step(ctx, i, st, args.verbose)
            blocked_status, blocked_detail = apply_block(r.status, st, results)
            if blocked_status != r.status:
                r.status, r.detail = blocked_status, blocked_detail
            results.append(r)
            tag = " (probe)" if st.probe else ""
            print(f"{i:>3}  {r.status:<5} {st.who:<10} {st.op:<26} {st.expect.desc} - {st.note}{tag}")
            if r.status in ("FAIL", "XPASS"):
                print(f"           └─ {r.detail}")
                if st.fatal:
                    aborted = True
                    print("           └─ fatal step: the rest of the matrix depends on it - stopping")
            elif r.status == "XFAIL":
                print(f"           └─ KNOWN GAP {st.gap.id} (pinned, strict): {st.gap.observed.desc}")
            elif r.status == "BLOCKED":
                print(f"           └─ BLOCKED by {st.blocked_by}: {r.detail}")
        expected_panics = sum(r.step.gap.panics for r in results if r.status == "XFAIL" and r.step.gap)
        invariants = run_invariants(box, ctx, tripwire_before, expected_panics)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_FAIL
    except Exception as e:
        print(f"endpoint-matrix: the run could not complete: {type(e).__name__}: {e}", file=sys.stderr)
        tail = box.log_text()[-600:]
        if tail:
            print("credmgrd log tail:\n" + tail, file=sys.stderr)
        return EXIT_CANNOT_RUN
    finally:
        box.cleanup()

    rows, bad_ops = render_table(steps, results, real)
    print_table(rows)
    print()
    print("invariants")
    bad_inv = 0
    for name, passed, detail in invariants:
        bad_inv += 0 if passed else 1
        print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))

    n_fail = sum(1 for r in results if r.status not in ("PASS", "XFAIL", "BLOCKED"))
    gap_rows = [r for r in results if r.status == "XFAIL"]
    blocked_rows = [r for r in results if r.status == "BLOCKED"]
    n_probe = sum(1 for r in results if r.step.probe)
    ops_full = sum(1 for r in rows if r["result"].startswith("PASS"))
    ops_gap = sum(1 for r in rows if r["result"].startswith("GAP"))
    print()
    print(f"ops: {len(real)} in broker, {ops_full} fully passing, {ops_gap} with a known gap, {bad_ops} failing   "
          f"rows: {len(results)} ({n_probe} probes), {sum(1 for r in results if r.status == 'PASS')} passed, "
          f"{len(gap_rows)} known-gap, {len(blocked_rows)} blocked, {n_fail} failed   "
          f"invariants failed: {bad_inv}   "
          f"time: {time.time() - t_start:.1f}s")
    if gap_rows:
        print()
        print("KNOWN GAPS (pinned strictly: the run fails the day one of these starts to hold, or changes shape)")
        seen: set = set()
        for r in gap_rows:
            g = r.step.gap
            assert g is not None
            if g.id not in seen:
                seen.add(g.id)
                print(f"  {g.id}: {g.text}")
            print(f"       row {r.index:>3}  {r.step.op}: {r.step.note}")
        for r in blocked_rows:
            print(f"       row {r.index:>3}  {r.step.op}: {r.step.note}   [BLOCKED by {r.step.blocked_by}: "
                  f"not evidence until it is fixed]")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "ops": rows,
            "rows": [{"n": r.index, "op": r.step.op, "who": r.step.who, "note": r.step.note,
                      "expectation": r.step.expect.desc, "status": r.status, "probe": r.step.probe,
                      "gap": r.step.gap.id if r.step.gap else None, "blockedBy": r.step.blocked_by,
                      "detail": r.detail} for r in results],
            "invariants": [{"name": n, "passed": p, "detail": d} for n, p, d in invariants],
        }, indent=2) + "\n")
    good = n_fail == 0 and bad_ops == 0 and bad_inv == 0
    if good and (gap_rows or blocked_rows) and args.strict:
        print("ENDPOINT MATRIX: FAILED (--strict: known gaps and blocked rows count as failures)")
        return EXIT_FAIL
    if good:
        print("ENDPOINT MATRIX: " + (f"PASSED WITH {len({r.step.gap.id for r in gap_rows if r.step.gap})} "
                                     f"KNOWN GAP(S) LISTED ABOVE" if gap_rows else "ALL PASSED"))
        return EXIT_OK
    print("ENDPOINT MATRIX: FAILURES ABOVE")
    return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
