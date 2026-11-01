"""Content-hash-keyed incremental build cache for the doc-system engine (ENGINE_PLAN §4b).

The generator is deterministic: identical inputs (source markdown + sibling figure spec +
requested formats + ``local_preview`` flag + engine source) always produce byte-identical
outputs (``generator.build`` embeds no wall-clock timestamps in hashed content). That property
is exactly what makes a content-hash cache SAFE: if the cache key for a document is unchanged
AND every output it produced last time still exists on disk, rebuilding would reproduce the
same bytes, so the build can be skipped.

Design (all fail-open — a cache miss, a corrupt entry, an unreadable file, or ANY error
degrades to a full ``generator.build``; the cache is only ever an optimization, never a
gate and never a source of truth):

* **Key** = sha256 over, in a fixed order: the source ``.md`` bytes, the sibling
  ``<stem>_spec.json`` bytes (or a sentinel when absent), the sorted requested ``formats``,
  the ``local_preview`` flag, and an **engine-source fingerprint** (the sha256 of every
  ``tools/docgen/*.py`` file). Folding the engine fingerprint in means any change to the
  renderer/generator/gate invalidates every entry — a doc whose output would differ after an
  engine edit is never wrongly skipped.
* **Store** = one JSON file (default ``<build_dir>/.docgen_cache.json``), mapping the
  canonical source path (repo-relative) to ``{key, outputs: [rel_path, ...]}``. The outputs
  are recorded so a skip can verify every promised artifact is still present before trusting
  the entry (a deleted output forces a rebuild).

Nothing here embeds a timestamp, so the cache file itself is deterministic given the same
corpus + engine — two clean rebuilds write the same cache bytes.

This module NEVER relaxes the leak-gate: a skip only happens for a doc that already built
cleanly (its outputs are on disk, which only occurs when its gate passed). A blocked build
writes no output, so it is never cached as skippable and always re-runs the gate.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from tools.docgen import generator
from tools.docgen.models import BuildResult, Finding, GateResult, Severity

_LOG = logging.getLogger("tools.docgen.build_cache")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCGEN_DIR = Path(__file__).resolve().parent
_DEFAULT_CACHE_NAME = ".docgen_cache.json"
_NO_SIBLING = b"\x00<no-sibling-spec>\x00"

# Cache-format version: bump if the key composition below changes so stale on-disk caches
# (written by an older layout) are treated as a miss rather than mis-trusted.
_CACHE_FORMAT = "docgen-build-cache/v1"


@dataclass(frozen=True)
class CacheEntry:
    """A single cached build record: the content key + the outputs it produced."""

    key: str
    outputs: dict[str, str]  # format -> repo-relative POSIX path of the written artifact


def _engine_fingerprint() -> str:
    """sha256 over every ``tools/docgen/*.py`` source file (sorted), so an engine edit busts the cache.

    Deterministic: files are hashed in sorted-name order; the digest of this file's own bytes
    is included too (it is a ``*.py`` under the dir), which is harmless — it only means a change
    to the cache module itself also invalidates entries, which is the conservative choice.
    """
    hasher = hashlib.sha256()
    for py_file in sorted(_DOCGEN_DIR.glob("*.py"), key=lambda p: p.name):
        hasher.update(py_file.name.encode("utf-8"))
        hasher.update(b"\x00")
        try:
            hasher.update(py_file.read_bytes())
        except OSError:  # pragma: no cover - a file vanishing mid-scan; fail toward a miss
            hasher.update(b"\x00<unreadable>\x00")
        hasher.update(b"\x00")
    return hasher.hexdigest()


def _sibling_spec_bytes(md_path: Path) -> bytes:
    """Return the ``<stem>_spec.json`` sidecar bytes, or a stable sentinel when absent/unreadable."""
    sidecar = md_path.with_name(f"{md_path.stem}_spec.json")
    try:
        return sidecar.read_bytes()
    except OSError:
        return _NO_SIBLING


def compute_key(
    md_path: Path,
    *,
    formats: tuple[str, ...],
    local_preview: bool,
    engine_fingerprint: str,
) -> str:
    """Content key for one document build.

    Composes the source bytes, sibling spec bytes, sorted formats, the ``local_preview`` flag,
    and the engine fingerprint into one sha256. Fixed field order + sorted formats keep it
    deterministic. Raises ``OSError`` only if the source markdown itself cannot be read (the
    caller treats that as a miss and lets ``generator.build`` surface the real error).
    """
    hasher = hashlib.sha256()
    hasher.update(_CACHE_FORMAT.encode("utf-8"))
    hasher.update(b"\x00")
    hasher.update(md_path.read_bytes())
    hasher.update(b"\x00")
    hasher.update(_sibling_spec_bytes(md_path))
    hasher.update(b"\x00")
    hasher.update(",".join(sorted(formats)).encode("utf-8"))
    hasher.update(b"\x00")
    hasher.update(b"lp=1" if local_preview else b"lp=0")
    hasher.update(b"\x00")
    hasher.update(engine_fingerprint.encode("utf-8"))
    return hasher.hexdigest()


def load_cache(cache_path: Path) -> dict[str, CacheEntry]:
    """Read the on-disk cache. Fail-open: any error (missing, corrupt, wrong format) → empty."""
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict) or raw.get("format") != _CACHE_FORMAT:
        return {}
    entries_obj = raw.get("entries")
    if not isinstance(entries_obj, dict):
        return {}
    out: dict[str, CacheEntry] = {}
    for src, record in entries_obj.items():
        if not isinstance(record, dict):
            continue
        key = record.get("key")
        outputs = record.get("outputs")
        if not isinstance(key, str) or not isinstance(outputs, dict):
            continue
        # Coerce/validate the outputs mapping (format -> str path); skip malformed entries.
        clean_outputs = {
            str(fmt): str(rel) for fmt, rel in outputs.items() if isinstance(rel, str)
        }
        out[str(src)] = CacheEntry(key=key, outputs=clean_outputs)
    return out


def save_cache(cache_path: Path, cache: dict[str, CacheEntry]) -> None:
    """Write the cache deterministically (sorted keys, no timestamp). Fail-open: log + return on error."""
    payload = {
        "format": _CACHE_FORMAT,
        "entries": {
            src: {"key": entry.key, "outputs": entry.outputs}
            for src, entry in sorted(cache.items())
        },
    }
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:  # pragma: no cover - disk/permission failure; cache is best-effort
        _LOG.warning("build_cache: could not write cache %s: %s", cache_path, exc)


def _repo_rel(path: Path) -> str:
    """POSIX repo-relative path for stable cache keys/values; falls back to the absolute path."""
    try:
        return path.resolve().relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _entry_is_fresh(entry: CacheEntry, key: str) -> bool:
    """A cache entry may be trusted iff the key matches AND every recorded output still exists."""
    if entry.key != key:
        return False
    if not entry.outputs:
        return False
    for rel in entry.outputs.values():
        candidate = (_REPO_ROOT / rel).resolve()
        if not candidate.is_file():
            return False
    return True


def _skipped_result(doc_id: str, entry: CacheEntry) -> BuildResult:
    """Synthesize a passing ``BuildResult`` for a cache-hit skip (no gate re-run needed)."""
    outputs = {fmt: (_REPO_ROOT / rel) for fmt, rel in entry.outputs.items()}
    gate = GateResult(
        gate="build-cache",
        findings=[
            Finding(
                gate="build-cache",
                message=f"unchanged — reused cached build ({doc_id})",
                severity=Severity.INFO,
                blocking=False,
            )
        ],
    )
    return BuildResult(doc_id=doc_id, gate=gate, outputs=outputs)


def build_cached(
    md_path: Path,
    *,
    formats: tuple[str, ...] = ("html",),
    out_dir: Path | None = None,
    local_preview: bool = False,
    cache: dict[str, CacheEntry],
    engine_fingerprint: str,
) -> tuple[BuildResult, bool]:
    """Build ``md_path`` through the cache. Returns ``(result, was_skipped)``.

    Fail-open at every step: if the key cannot be computed, if the entry is stale, or if the
    entry is missing, fall straight through to ``generator.build``. A cache hit is trusted ONLY
    when the content key matches AND every output it recorded is still on disk — otherwise the
    document is rebuilt and the cache is refreshed. A blocked build (``result.ok`` False) is
    NOT cached as skippable (it produced no trustworthy outputs), so the gate always re-runs on
    a still-broken document.

    The passed ``cache`` dict is mutated in place with the fresh entry on a real build; the
    caller persists it once at the end via :func:`save_cache`.
    """
    src_key = _repo_rel(md_path)
    try:
        key = compute_key(
            md_path,
            formats=formats,
            local_preview=local_preview,
            engine_fingerprint=engine_fingerprint,
        )
    except OSError:
        # Source unreadable — let generator.build raise the real, honest error.
        result = generator.build(
            md_path, formats=formats, out_dir=out_dir, local_preview=local_preview
        )
        return result, False

    existing = cache.get(src_key)
    if existing is not None and _entry_is_fresh(existing, key):
        # Recover the doc_id cheaply from the parsed header without a full build.
        try:
            from tools.docgen.classification import parse_header

            doc_id = parse_header(md_path.read_text(encoding="utf-8")).id
        except (OSError, ValueError, KeyError):
            doc_id = existing.outputs and next(iter(existing.outputs.values())) or src_key
        return _skipped_result(str(doc_id), existing), True

    # Miss (or stale) → full build, then refresh the entry only if it produced outputs.
    result = generator.build(
        md_path, formats=formats, out_dir=out_dir, local_preview=local_preview
    )
    if result.ok and result.outputs:
        cache[src_key] = CacheEntry(
            key=key,
            outputs={fmt: _repo_rel(path) for fmt, path in sorted(result.outputs.items())},
        )
    else:
        # Do not cache a blocked/empty build as skippable; drop any stale entry for it.
        cache.pop(src_key, None)
    return result, False


def default_cache_path(build_dir: Path) -> Path:
    """The conventional cache file location for a corpus built into ``build_dir``."""
    return build_dir / _DEFAULT_CACHE_NAME


@dataclass
class CorpusResult:
    """Aggregate outcome of a corpus build: per-doc results plus which were skipped/blocked."""

    results: dict[str, BuildResult]  # source rel-path -> BuildResult
    skipped: list[str]  # source rel-paths reused from cache
    blocked: list[str]  # source rel-paths whose build was blocked

    @property
    def ok(self) -> bool:
        return not self.blocked


def build_corpus(
    md_paths: list[Path],
    *,
    formats: tuple[str, ...] = ("html",),
    out_dir: Path | None = None,
    local_preview: bool = False,
    cache_path: Path,
) -> CorpusResult:
    """Build many documents through one shared cache, skipping unchanged ones.

    Loads the cache once, builds each path via :func:`build_cached`, then persists the cache
    once at the end. Fail-open throughout: a corrupt cache simply means nothing is skipped this
    run. The engine fingerprint is computed a single time for the whole corpus so every doc is
    keyed against the same engine snapshot.
    """
    cache = load_cache(cache_path)
    fingerprint = _engine_fingerprint()
    results: dict[str, BuildResult] = {}
    skipped: list[str] = []
    blocked: list[str] = []

    for md_path in md_paths:
        rel = _repo_rel(md_path)
        result, was_skipped = build_cached(
            md_path,
            formats=formats,
            out_dir=out_dir,
            local_preview=local_preview,
            cache=cache,
            engine_fingerprint=fingerprint,
        )
        results[rel] = result
        if was_skipped:
            skipped.append(rel)
        if not result.ok:
            blocked.append(rel)

    save_cache(cache_path, cache)
    return CorpusResult(results=results, skipped=skipped, blocked=blocked)
