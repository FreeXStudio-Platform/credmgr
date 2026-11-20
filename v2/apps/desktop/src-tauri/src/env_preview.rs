//! `env_preview` - the `.env` text a person pastes or opens, read into name/value pairs
//! (ADR-122). **No broker, no socket, no session, no audit record**: it is the same parser
//! `credmgr import-env` runs (`credmgr_core::dotenv`), so what the window previews is what
//! the command line would have read, and the page keeps no parser of its own. The pairs go
//! on to `entry_import_env` (a dry run first, then the write).
//!
//! Like [`crate::fields_preview`] it uses only the pure text half of `credmgr-core` (this
//! shell holds no key and decrypts nothing, ADR-001), keeps nothing it was given, and says
//! a line NUMBER when a line is wrong - never the line, which may be the secret itself.

use serde::Serialize;

use crate::error::BridgeError;

/// The most text one preview reads: a `.env` file is a few KiB (the command line reads 4 MiB).
pub const ENV_MAX_BYTES: usize = 4 * 1024 * 1024;
/// `entry.import_env` takes at most this many pairs in one call.
pub const ENV_MAX_ENTRIES: usize = 500;

/// One pair, in file order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvPair {
    pub name: String,
    pub value: String,
}

/// What a `.env` text holds: the pairs with a value, and the names that had none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvPreview {
    pub entries: Vec<EnvPair>,
    /// Names whose value was empty (a `.env.example` placeholder): not importable, but said.
    pub skipped_empty: Vec<String>,
    /// ADR-148 addendum: line numbers skipped because the line is only the padded end of a base64 value (never
    /// their text). The other lines still import.
    pub refused_lines: Vec<usize>,
}

fn invalid(message: impl Into<String>) -> BridgeError {
    BridgeError::bridge("invalid_env", message)
}

/// Read `text` as a `.env` file. Refuses text over [`ENV_MAX_BYTES`], more than
/// [`ENV_MAX_ENTRIES`] pairs, and any line the grammar rejects (by line number).
pub fn preview(text: &str) -> Result<EnvPreview, BridgeError> {
    if text.len() > ENV_MAX_BYTES {
        return Err(invalid(format!(
            "that text is larger than {ENV_MAX_BYTES} bytes"
        )));
    }
    let parsed = credmgr_core::dotenv::parse(text).map_err(invalid)?;
    if parsed.entries.len() > ENV_MAX_ENTRIES {
        return Err(invalid(format!(
            "that file holds {} entries; one import takes at most {ENV_MAX_ENTRIES} - split it",
            parsed.entries.len()
        )));
    }
    Ok(EnvPreview {
        entries: parsed
            .entries
            .into_iter()
            .map(|e| EnvPair {
                name: e.name,
                value: e.value,
            })
            .collect(),
        skipped_empty: parsed.skipped_empty,
        refused_lines: parsed.refused_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_come_back_in_file_order_with_quotes_and_export_read_like_the_command_line() {
        let p = preview(
            "# a comment\nexport DB_HOST=db.internal\nAPI_KEY=\"abc def\"\nEMPTY=\nTOKEN='x#y'\n",
        )
        .unwrap();
        let got: Vec<(&str, &str)> = p
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("DB_HOST", "db.internal"),
                ("API_KEY", "abc def"),
                ("TOKEN", "x#y")
            ]
        );
        assert_eq!(p.skipped_empty, ["EMPTY"]);
    }

    #[test]
    fn a_bad_line_is_refused_by_number_and_never_quoted() {
        let secret = format!("{}{}", "sk_li", "ve_zzzzzzzzzzzzzzzzzzzz");
        let e = preview(&format!("GOOD=1\n{secret}\n")).unwrap_err();
        let said = serde_json::to_string(&e).unwrap();
        assert!(said.contains("invalid_env"), "{said}");
        assert!(said.contains('2'), "the line number: {said}");
        assert!(!said.contains(&secret), "{said}");
    }

    #[test]
    fn the_size_and_count_ceilings_hold() {
        let big = "A=".to_string() + &"x".repeat(ENV_MAX_BYTES);
        assert!(preview(&big).is_err());
        let many: String = (0..=ENV_MAX_ENTRIES).map(|i| format!("K{i}=v\n")).collect();
        let e = preview(&many).unwrap_err();
        assert!(serde_json::to_string(&e).unwrap().contains("at most 500"));
        let ok: String = (0..ENV_MAX_ENTRIES).map(|i| format!("K{i}=v\n")).collect();
        assert_eq!(preview(&ok).unwrap().entries.len(), ENV_MAX_ENTRIES);
    }

    #[test]
    fn a_lone_padded_base64_line_is_skipped_by_number_and_the_rest_previews() {
        let p = preview("A=1\nQUJDRA==\nB=2\n").unwrap();
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.refused_lines, [2]);
    }

    #[test]
    fn nothing_but_comments_is_an_empty_preview_not_an_error() {
        let p = preview("# nothing here\n\n").unwrap();
        assert!(p.entries.is_empty() && p.skipped_empty.is_empty());
    }
}
