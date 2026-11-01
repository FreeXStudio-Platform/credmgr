<!-- classification: public -->
<!-- Defensive security documentation: describes the doc-system engine's i18n scaffold. -->
# doc-system i18n scaffold — locale directory

> **Scaffold only — NOT translation.** This directory establishes the *structure* for future
> localization of the doc-system's UI chrome. No document *content* is translated by the engine;
> only the small set of generator-emitted UI strings (the "Contents" heading, classification-badge
> labels, the verified stamp, theme-toggle labels) are catalogued here. See `tools/docgen/i18n.py`
> and `ENGINE_PLAN.md §4b` (deferred-to-POOL item "i18n").

## Convention

```
tools/docgen/locales/
  <lang>/
    catalog.json      # flat { "key": "string" } map of translatable UI strings
```

- `<lang>` is a BCP-47 language tag (e.g. `en`, `pt-BR`, `de`, `zh-Hans`).
- `en/catalog.json` is the **canonical** catalog: it defines every key and holds the default
  (English) strings. It is the fallback for every other language.
- A new language is added by copying `en/catalog.json` into `locales/<lang>/catalog.json` and
  translating the *values only* (never the keys). Partial catalogs are fine — any missing key
  falls back to its English value (`i18n.load_catalog`).

## Generator hook — the `lang` attribute

A document may declare an optional `locale:` field in its front-matter. The generator resolves it
via `i18n.resolve_lang(...)` and emits `<html lang="…">` accordingly. Resolution is **fail-safe**:
an absent, malformed, or unknown locale degrades to `en` and is logged, never raised. A document
that declares no `locale:` is unaffected — its output stays byte-identical (`lang="en"`).

```yaml
---
id: EDU-001
classification: public
locale: pt-BR        # optional; drives <html lang="pt-BR">
# … other required header fields …
---
```

## Inspecting the scaffold

```bash
python -m tools.docgen.i18n --list             # shipped locales (currently just: en)
python -m tools.docgen.i18n --resolve pt-BR     # -> pt-BR
python -m tools.docgen.i18n --catalog en        # print the merged English catalog
```

## Current state (honest)

Only `en` ships. Every language therefore currently resolves to the English strings — that is the
expected scaffold state. Real translations are a future POOL item; this structure lets them be
added without any change to the generator's public interface.
