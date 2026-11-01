//! ADR-084 — one canonical form for names, shared by the broker, the CLI and
//! the desktop window (closes threat T4 in `docs/FRONTEND_THREAT_MODEL.md`).
//!
//! A name is *stored as typed* and *compared canonically*: two names are the
//! same name when [`canonical_name`] returns the same string for both. The
//! canonical form is never shown and never stored; it exists so that
//! `payroll` (with a Cyrillic `а`) cannot sit beside `payroll` as a second,
//! look-alike entry that an agent could use to spoof a human's choice.
//!
//! The pipeline, in this order, repeated until nothing changes (so the
//! function is idempotent by construction):
//!
//! 1. remove bidi controls and zero-width characters ([`is_invisible_control`]);
//! 2. Unicode NFKC (compatibility composition: full-width letters, ligatures,
//!    circled letters and the like fold to their plain forms);
//! 3. Unicode lower-casing;
//! 4. fold the look-alike table ([`LOOKALIKES`]) to its Latin twin.
//!
//! ASCII `0`/`o` and `1`/`l` are **not** folded: they are legitimate in real
//! names (`db01`, `v1`). Pure and I/O-free like the rest of this crate.

use unicode_normalization::UnicodeNormalization;

/// Look-alike letters (already lower-case, already NFKC) and the Latin letter
/// each one is folded to. The table is `FRONTEND_THREAT_MODEL.md` "Look-alike
/// table"; `tests/names.rs` pins it against that file's text so the two cannot
/// drift.
pub const LOOKALIKES: &[(char, char)] = &[
    // Cyrillic
    ('\u{0430}', 'a'), // а
    ('\u{0435}', 'e'), // е
    ('\u{043E}', 'o'), // о
    ('\u{0440}', 'p'), // р
    ('\u{0441}', 'c'), // с
    ('\u{0443}', 'y'), // у
    ('\u{0445}', 'x'), // х
    ('\u{0456}', 'i'), // і
    ('\u{0458}', 'j'), // ј
    ('\u{0455}', 's'), // ѕ
    ('\u{0501}', 'd'), // ԁ
    ('\u{04BB}', 'h'), // һ
    ('\u{051B}', 'q'), // ԛ
    ('\u{051D}', 'w'), // ԝ
    ('\u{04CF}', 'l'), // ӏ
    // Greek
    ('\u{03BF}', 'o'), // ο
    ('\u{03B1}', 'a'), // α
    ('\u{03BD}', 'v'), // ν
    ('\u{03C1}', 'p'), // ρ
    ('\u{03B9}', 'i'), // ι
    ('\u{03BA}', 'k'), // κ
    ('\u{03C5}', 'u'), // υ
    ('\u{03C7}', 'x'), // χ
    // Other
    ('\u{0131}', 'i'), // ı (dotless i)
    ('\u{0261}', 'g'), // ɡ (script g)
    ('\u{0262}', 'g'), // ɢ (small capital g)
];

/// Bidirectional controls and zero-width characters: they render as nothing
/// (or reorder what is around them), so a name carrying one can look identical
/// to a name that does not.
#[must_use]
pub fn is_invisible_control(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'               // soft hyphen
        | '\u{061C}'             // Arabic letter mark
        | '\u{180E}'             // Mongolian vowel separator
        | '\u{200B}'..='\u{200F}' // zero-width space/non-joiner/joiner, LRM, RLM
        | '\u{202A}'..='\u{202E}' // embeddings and overrides
        | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}' // isolates
        | '\u{FEFF}'              // zero-width no-break space
        // Characters that render as nothing (or only change how a neighbour is drawn) and
        // that NFKC leaves in place - found by the 2026-10-24 review of this function.
        | '\u{034F}'             // combining grapheme joiner
        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
        | '\u{17B4}' | '\u{17B5}' // Khmer inherent vowels
        | '\u{180B}'..='\u{180D}' | '\u{180F}' // Mongolian free variation selectors
        | '\u{FE00}'..='\u{FE0F}' // variation selectors
        | '\u{E0000}'..='\u{E007F}' // tag characters
        | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
    )
}

fn fold_lookalike(c: char) -> char {
    LOOKALIKES
        .iter()
        .find(|(from, _)| *from == c)
        .map_or(c, |(_, to)| *to)
}

fn canonical_once(name: &str) -> String {
    let visible: String = name.chars().filter(|c| !is_invisible_control(*c)).collect();
    visible
        .nfkc()
        .flat_map(char::to_lowercase)
        .map(fold_lookalike)
        .collect()
}

/// The canonical form two names are compared by (ADR-084). Idempotent:
/// `canonical_name(&canonical_name(x)) == canonical_name(x)`.
#[must_use]
pub fn canonical_name(name: &str) -> String {
    let mut current = canonical_once(name);
    // NFKC/lower-casing can in rare cases expose a new foldable character;
    // iterate to the fixed point (it converges in at most a few rounds, and the
    // cap keeps a pathological input from looping).
    for _ in 0..8 {
        let next = canonical_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Whether two names are the same name once folded.
#[must_use]
pub fn same_name(a: &str, b: &str) -> bool {
    canonical_name(a) == canonical_name(b)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
}

fn script_of(c: char) -> Option<Script> {
    match c {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{00C0}'..='\u{024F}' if c != '\u{00D7}' && c != '\u{00F7}' => Some(Script::Latin),
        '\u{1E00}'..='\u{1EFF}' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{052F}'
        | '\u{1C80}'..='\u{1C8F}'
        | '\u{2DE0}'..='\u{2DFF}'
        | '\u{A640}'..='\u{A69F}' => Some(Script::Cyrillic),
        _ => None,
    }
}

/// ADR-084: a name that mixes Latin letters with Greek or Cyrillic ones is
/// accepted but flagged — it is the shape of a homoglyph spoof. A name that is
/// *entirely* Greek or Cyrillic is a normal name and is never flagged. Judged
/// on the name as typed, minus invisible controls and after NFKC (so a
/// full-width Latin letter counts as Latin).
#[must_use]
pub fn mixes_scripts(name: &str) -> bool {
    let (mut latin, mut other) = (false, false);
    for c in name.chars().filter(|c| !is_invisible_control(*c)).nfkc() {
        match script_of(c) {
            Some(Script::Latin) => latin = true,
            Some(Script::Greek | Script::Cyrillic) => other = true,
            None => {}
        }
    }
    latin && other
}

/// The value of the reply's additive `warnings` entry for a mixed-script name.
pub const WARN_MIXED_SCRIPT: &str = "mixed_script_name";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyrillic_a_in_payroll_is_the_same_name() {
        assert!(same_name("payroll", "p\u{0430}yroll"));
        assert_eq!(canonical_name("p\u{0430}yroll"), "payroll");
    }

    #[test]
    fn cyrillic_c_in_cloud_is_the_same_name() {
        assert!(same_name("cloud", "\u{0441}loud"));
    }

    #[test]
    fn greek_omicron_in_open_is_the_same_name() {
        assert!(same_name("open", "\u{03BF}pen"));
    }

    #[test]
    fn case_nfkc_and_invisible_controls_fold() {
        assert!(same_name("Payroll", "PAYROLL"));
        assert!(same_name("payroll", "\u{FF50}\u{FF41}\u{FF59}roll")); // full-width
        assert!(same_name("payroll", "pay\u{200B}roll"));
        assert!(same_name("payroll", "pay\u{202E}roll"));
        for invisible in [
            '\u{034F}',
            '\u{FE0F}',
            '\u{3164}',
            '\u{E0041}',
            '\u{E0100}',
            '\u{180B}',
        ] {
            assert!(
                same_name("payroll", &format!("pay{invisible}roll")),
                "{invisible:?}"
            );
            assert!(
                same_name("payroll", &format!("payroll{invisible}")),
                "{invisible:?}"
            );
        }
        assert!(same_name("ﬁle", "file")); // ligature
    }

    #[test]
    fn ascii_pairs_are_not_folded() {
        assert!(!same_name("db01", "dbo1"));
        assert!(!same_name("v1", "vl"));
    }

    #[test]
    fn a_pure_cyrillic_name_is_a_name_of_its_own() {
        let n = "\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}"; // пример
        assert!(!mixes_scripts(n));
        assert!(!same_name(n, "example"));
    }

    #[test]
    fn mixed_scripts_are_detected_only_when_latin_meets_greek_or_cyrillic() {
        assert!(mixes_scripts("p\u{0430}yroll"));
        assert!(mixes_scripts("\u{03BF}pen"));
        assert!(!mixes_scripts("payroll"));
        assert!(!mixes_scripts("\u{03BF}\u{03BC}\u{03B5}\u{03B3}\u{03B1}")); // all Greek
        assert!(!mixes_scripts("caf\u{00E9}")); // accented Latin is Latin
        assert!(!mixes_scripts("db-01 \u{2192} prod")); // symbols and digits are neutral
    }

    #[test]
    fn canonical_form_is_idempotent_for_the_whole_table() {
        for (from, to) in LOOKALIKES {
            let s = format!("A{from}\u{200B}\u{FF21}\u{0130}x");
            let once = canonical_name(&s);
            assert_eq!(canonical_name(&once), once, "not idempotent for {from:?}");
            assert_eq!(canonical_name(&from.to_string()), to.to_string());
        }
    }
}
