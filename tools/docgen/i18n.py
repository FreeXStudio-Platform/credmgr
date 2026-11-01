# classification: public
"""i18n SCAFFOLD for the CredMgr doc-system engine (structure only — NOT translation).

Deferred to POOL by ``ENGINE_PLAN.md §4b``; this module lays the *structural* groundwork
so a future session can add real translations without touching the generator's interface:

1. **Locale directory convention.** Translatable UI strings for a language ``<lang>`` live in
   ``tools/docgen/locales/<lang>/catalog.json`` — a flat ``{key: string}`` JSON map. The
   shipped ``en`` catalog is the canonical set of keys (the *default* strings); other
   languages are added by copying it and translating the values. No document *content* is
   ever translated by this engine — only the small set of chrome/UI strings the generator
   itself emits (e.g. the "Contents" heading, the classification-badge label prefix).

2. **A generator hook for the ``lang`` attribute.** ``resolve_lang(locale)`` maps a
   document's declared locale (an optional ``locale:`` front-matter field) to a validated
   BCP-47 language tag suitable for ``<html lang="…">``. It is FAIL-SAFE: an absent,
   malformed, or unknown locale degrades to ``DEFAULT_LOCALE`` (``en``) and is logged,
   never faked (KB-010) and never raised.

3. **A string-catalog stub loader.** ``load_catalog(lang)`` returns the ``<lang>`` catalog
   merged over the ``en`` fallback, so a partially-translated catalog never yields a missing
   key. ``translate(key, lang)`` is the lookup helper. Because only ``en`` ships today, every
   language currently resolves to the English strings — this is the honest scaffold state,
   surfaced by ``available_locales()`` returning ``["en"]``.

Determinism (critical for the hash-gate): catalogs are read as sorted JSON; ``load_catalog``
returns keys in sorted order; no wall-clock/random values are produced. Stdlib only;
mypy --strict clean; additive (imports nothing from the generator, so nothing it does can
break an existing build path unless a caller opts in via ``resolve_lang``).

CLI (inspection only — never writes)::

    python -m tools.docgen.i18n --list
    python -m tools.docgen.i18n --resolve pt-BR
    python -m tools.docgen.i18n --catalog en
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger("docgen.i18n")

# ---------------------------------------------------------------------------
# Convention: locale root + default language.
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
LOCALES_DIR = _THIS_DIR / "locales"
CATALOG_FILENAME = "catalog.json"
DEFAULT_LOCALE = "en"

# A conservative BCP-47 subset: primary language subtag (2–3 alpha), optional script
# (4 alpha) and/or region (2 alpha or 3 digit) subtags. This validates the *shape* of a
# tag for the ``lang`` attribute; it does not assert the tag is a registered language.
_BCP47_RE = re.compile(
    r"^[A-Za-z]{2,3}"  # primary language
    r"(?:-[A-Za-z]{4})?"  # optional script
    r"(?:-(?:[A-Za-z]{2}|[0-9]{3}))?$"  # optional region
)


def normalize_locale(locale: str | None) -> str | None:
    """Canonicalize a raw locale string to ``ll`` / ``ll-Ssss`` / ``ll-RR`` casing.

    Returns ``None`` when ``locale`` is falsy or not a shape-valid BCP-47 tag — the caller
    (``resolve_lang``) treats ``None`` as "fall back to the default". No exception is raised;
    this is a fail-safe scaffold, not a validator that gates a build.
    """
    if not locale or not isinstance(locale, str):
        return None
    candidate = locale.strip()
    if not _BCP47_RE.match(candidate):
        return None
    parts = candidate.split("-")
    out = [parts[0].lower()]
    for part in parts[1:]:
        if len(part) == 4 and part.isalpha():  # script subtag → Titlecase
            out.append(part.title())
        elif len(part) == 2 and part.isalpha():  # region subtag → UPPERCASE
            out.append(part.upper())
        else:  # numeric region
            out.append(part)
    return "-".join(out)


def available_locales() -> list[str]:
    """Return the sorted list of shipped locales (directories with a ``catalog.json``).

    Only ``en`` ships today; that is the honest scaffold state. Never raises — a missing
    ``locales/`` directory yields ``[DEFAULT_LOCALE]`` (the default catalog is guaranteed).
    """
    found: set[str] = {DEFAULT_LOCALE}
    if LOCALES_DIR.is_dir():
        for child in LOCALES_DIR.iterdir():
            if child.is_dir() and (child / CATALOG_FILENAME).is_file():
                found.add(child.name)
    return sorted(found)


def resolve_lang(locale: str | None) -> str:
    """Generator hook: map a document's declared locale to an ``<html lang="…">`` value.

    Fail-safe resolution order:

    * a shape-valid, shipped locale (exact or primary-language match) → that tag;
    * a shape-valid but not-yet-shipped locale → the tag is still returned for the ``lang``
      attribute (the markup is correct even though only English *strings* exist), and a debug
      note is logged;
    * anything absent/malformed → :data:`DEFAULT_LOCALE`.

    Never raises. The returned value is always a safe, shape-valid ``lang`` attribute string.
    """
    normalized = normalize_locale(locale)
    if normalized is None:
        if locale:
            logger.debug("i18n: unrecognized locale %r → default %r", locale, DEFAULT_LOCALE)
        return DEFAULT_LOCALE
    shipped = set(available_locales())
    primary = normalized.split("-", 1)[0]
    if normalized not in shipped and primary not in shipped:
        logger.debug(
            "i18n: locale %r has no shipped catalog yet (using English strings, lang=%r)",
            normalized,
            normalized,
        )
    return normalized


def _catalog_path(lang: str) -> Path:
    return LOCALES_DIR / lang / CATALOG_FILENAME


def _read_catalog_file(lang: str) -> dict[str, str]:
    """Read one locale's catalog file. Missing/unreadable → empty dict (fail-safe, logged)."""
    path = _catalog_path(lang)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
        logger.warning("i18n: could not read catalog %s: %s", path, exc)
        return {}
    if not isinstance(raw, dict):
        logger.warning("i18n: catalog %s is not a JSON object; ignoring", path)
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def load_catalog(lang: str = DEFAULT_LOCALE) -> dict[str, str]:
    """Return the ``lang`` string catalog merged over the English fallback.

    A partially-translated (or absent) ``lang`` catalog never yields a missing key: any key
    not present for ``lang`` falls back to its English value. Keys are returned in sorted
    order for deterministic serialization. Passing the default language returns the English
    catalog unchanged.
    """
    base = _read_catalog_file(DEFAULT_LOCALE)
    if lang == DEFAULT_LOCALE:
        merged = dict(base)
    else:
        merged = {**base, **_read_catalog_file(lang)}
    return {key: merged[key] for key in sorted(merged)}


def translate(key: str, lang: str = DEFAULT_LOCALE) -> str:
    """Look up ``key`` in the ``lang`` catalog (English fallback). Missing key → the key itself.

    Returning the key verbatim on a miss is the honest scaffold behavior — it makes an
    untranslated string visible rather than silently blank, and never raises.
    """
    return load_catalog(lang).get(key, key)


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.docgen.i18n",
        description="Inspect the doc-system i18n scaffold (structure only; never writes).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list shipped locales")
    group.add_argument("--resolve", metavar="LOCALE", help="show the resolved <html lang> value")
    group.add_argument("--catalog", metavar="LANG", help="print a locale's merged catalog as JSON")
    args = parser.parse_args(argv)

    if args.list:
        for lang in available_locales():
            print(lang)
        return 0
    if args.resolve is not None:
        print(resolve_lang(args.resolve))
        return 0
    print(json.dumps(load_catalog(args.catalog), indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(_cli())
