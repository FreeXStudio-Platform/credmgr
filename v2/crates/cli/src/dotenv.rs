//! The `.env`-style parser behind `credmgr import` (`10_API_AND_MCP.md §2`,
//! `11_MIGRATION.md §5`: "an `.env`-shaped file into one named node").
//!
//! **No error here ever carries a line's content.** A line that fails to parse
//! may be exactly the secret the operator meant to import (a bare token pasted
//! without its `NAME=`), so a diagnostic names the *line number* and what was
//! wrong — never the text. The one place a name is echoed is a duplicate key,
//! and by then the name has already passed [`valid_name`].
//!
//! Accepted grammar, deliberately small and close to what shells, Docker
//! Compose and dotenv libraries agree on:
//!
//! * blank lines and lines starting with `#` are ignored;
//! * an optional leading `export ` (the shell form);
//! * `NAME=value`, with optional whitespace around the `=`;
//! * an unquoted value runs to the end of the line, trimmed; a `#` that
//!   follows whitespace starts a comment (`KEY=abc#def` keeps the `#`);
//! * `'single quoted'` is literal and may span lines;
//! * `"double quoted"` understands `\n \r \t \" \\` (any other backslash is
//!   kept as written) and may span lines — a PEM block in a `.env` file is
//!   the usual reason;
//! * after a closing quote only whitespace or a `# comment` may follow;
//! * a quoted value that spans lines may not run into a line that itself starts
//!   like `NAME=…`. That is the signature of a closing quote that was forgotten
//!   (`PASSWORD="abc` … `API_KEY=xyz"`): every dotenv reader would swallow the
//!   lines in between into one value, silently, and the import would be
//!   missing entries. Here it is refused, naming both line numbers. A value
//!   that really contains such a line can be written on one line with `\n`
//!   escapes inside double quotes. (A line that is only base64 padding — a PEM
//!   body's last line, `Zm8=` — is not mistaken for an assignment.)
//!
//! An empty value is not an entry: `.env.example` files are full of `KEY=`
//! placeholders and importing them would fill the vault with empty
//! credentials. They are reported back by name ([`Parsed::skipped_empty`]) so
//! nothing is dropped silently.

/// One importable `NAME=value` pair, in file order.
pub struct EnvEntry {
    pub name: String,
    pub value: String,
}

pub struct Parsed {
    pub entries: Vec<EnvEntry>,
    /// Names whose value was empty — not imported, but reported.
    pub skipped_empty: Vec<String>,
}

/// An entry name: non-empty, `[A-Za-z0-9_.-]`. Tighter than the broker's
/// "non-empty" so a malformed line cannot become an entry whose name is part
/// of a secret.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

pub fn parse(text: &str) -> Result<Parsed, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut items: Vec<(usize, String, String)> = Vec::new(); // (line, name, value)
    let mut i = 0;
    while i < lines.len() {
        let line_no = i + 1;
        let mut line = lines[i].trim_start();
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with([' ', '\t']) {
                line = rest.trim_start();
            }
        }
        let Some((raw_name, rest)) = line.split_once('=') else {
            return Err(format!("line {line_no}: expected NAME=value"));
        };
        let name = raw_name.trim_end();
        if !valid_name(name) {
            return Err(format!(
                "line {line_no}: not a valid name (letters, digits, '_', '.' and '-' only)"
            ));
        }
        let rest_raw = rest;
        let rest = rest_raw.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let (value, after) = quoted(q, &rest[1..], &lines, &mut i, line_no)?;
                let after = after.trim_start();
                if !(after.is_empty() || after.starts_with('#')) {
                    return Err(format!(
                        "line {line_no}: unexpected text after the closing quote"
                    ));
                }
                value
            }
            // The untrimmed text: whether a `#` follows whitespace is what
            // makes it a comment, and `KEY= # note` must not lose that space.
            _ => unquoted(rest_raw),
        };
        items.push((line_no, name.to_string(), value));
    }

    let mut first_seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (line_no, name, _) in &items {
        if let Some(first) = first_seen.insert(name.as_str(), *line_no) {
            return Err(format!(
                "line {line_no}: {name} appears again (first on line {first}) — \
                 remove one so the import is unambiguous"
            ));
        }
    }

    let mut entries = Vec::new();
    let mut skipped_empty = Vec::new();
    for (_, name, value) in items {
        if value.is_empty() {
            skipped_empty.push(name);
        } else {
            entries.push(EnvEntry { name, value });
        }
    }
    Ok(Parsed {
        entries,
        skipped_empty,
    })
}

/// Does `line` start like a fresh assignment (`[export ]NAME=…`)? Used only on
/// the continuation lines of a quoted value, where it means a quote is unbalanced
/// above.
///
/// Base64 padding (`Zm8=`, `Zg==`) has the same shape as `NAME=` and is the last
/// line of every PEM body, so a whole line that is nothing but base64 followed by
/// one or two `=`, a multiple of four characters long, and that LOOKS like base64
/// (a digit, `+` or `/`, or both letter cases — a conventional name such as
/// `KEY=` or `PLACEHOLDER=` is one case, letters only) is not an assignment. The
/// edge is a name that happens to be exactly that shape; the failure is then a
/// refusal with a clear way out, never a silent mis-import.
fn looks_like_assignment(line: &str) -> bool {
    let mut l = line.trim_start();
    if let Some(rest) = l.strip_prefix("export") {
        if rest.starts_with([' ', '\t']) {
            l = rest.trim_start();
        }
    }
    let Some((name, _)) = l.split_once('=') else {
        return false;
    };
    if !valid_name(name.trim_end()) {
        return false;
    }
    let whole = l.trim_end();
    let body = whole.trim_end_matches('=');
    let pads = whole.len() - body.len();
    let bytes = body.as_bytes();
    let base64_alphabet = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/');
    let looks_random = bytes
        .iter()
        .any(|b| b.is_ascii_digit() || *b == b'+' || *b == b'/')
        || (bytes.iter().any(u8::is_ascii_lowercase) && bytes.iter().any(u8::is_ascii_uppercase));
    let base64_tail =
        (1..=2).contains(&pads) && whole.len() % 4 == 0 && base64_alphabet && looks_random;
    !base64_tail
}

/// An unquoted value: to end of line, a whitespace-preceded `#` starts a comment.
fn unquoted(rest: &str) -> String {
    let bytes = rest.as_bytes();
    let mut end = rest.len();
    for (idx, b) in bytes.iter().enumerate() {
        if *b == b'#' && idx > 0 && bytes[idx - 1].is_ascii_whitespace() {
            end = idx;
            break;
        }
    }
    rest[..end].trim().to_string()
}

/// Reads a quoted value that starts at `first` (the text after the opening
/// quote on its line) and may continue over following lines. Returns the value
/// and whatever follows the closing quote on its line; advances `*next` past
/// every line consumed.
fn quoted<'a>(
    quote: char,
    first: &'a str,
    lines: &[&'a str],
    next: &mut usize,
    start_line: usize,
) -> Result<(String, &'a str), String> {
    let mut value = String::new();
    let mut segment = first;
    loop {
        let mut chars = segment.char_indices();
        while let Some((idx, c)) = chars.next() {
            if c == quote {
                return Ok((value, &segment[idx + c.len_utf8()..]));
            }
            if quote == '"' && c == '\\' {
                match chars.next() {
                    Some((_, 'n')) => value.push('\n'),
                    Some((_, 'r')) => value.push('\r'),
                    Some((_, 't')) => value.push('\t'),
                    Some((_, '"')) => value.push('"'),
                    Some((_, '\\')) => value.push('\\'),
                    Some((_, other)) => {
                        value.push('\\');
                        value.push(other);
                    }
                    None => value.push('\\'),
                }
            } else {
                value.push(c);
            }
        }
        // No closing quote on this line: the value continues on the next one.
        let Some(&line) = lines.get(*next) else {
            return Err(format!("line {start_line}: a quoted value is never closed"));
        };
        let line_no = *next + 1;
        if looks_like_assignment(line) {
            return Err(format!(
                "line {start_line}: a quoted value is not closed before line {line_no}, \
                 which starts like a new NAME=value — a closing quote is probably missing \
                 on line {start_line}. (To keep such a line inside a value, write the value \
                 on one line with \\n escapes in double quotes.)"
            ));
        }
        *next += 1;
        value.push('\n');
        segment = line;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text)
            .expect("parses")
            .entries
            .into_iter()
            .map(|e| (e.name, e.value))
            .collect()
    }

    fn one(text: &str) -> String {
        let mut p = pairs(text);
        assert_eq!(p.len(), 1, "{p:?}");
        p.remove(0).1
    }

    #[test]
    fn plain_pairs_comments_blank_lines_and_export_prefix() {
        let got = pairs(
            "# a comment\n\nAPI_KEY=abc123\nexport DB_URL=postgres://h/db\n  INDENTED = spaced out  \n",
        );
        assert_eq!(
            got,
            vec![
                ("API_KEY".into(), "abc123".into()),
                ("DB_URL".into(), "postgres://h/db".into()),
                ("INDENTED".into(), "spaced out".into()),
            ]
        );
    }

    #[test]
    fn exportish_names_are_not_mistaken_for_the_export_keyword() {
        assert_eq!(one("EXPORTED=1"), "1");
        assert_eq!(one("export_dir=/x"), "/x");
    }

    #[test]
    fn comments_need_whitespace_before_the_hash() {
        assert_eq!(one("K=abc#def"), "abc#def");
        assert_eq!(one("K=#start"), "#start");
        assert_eq!(one("K=abc # trailing note"), "abc");
        assert!(parse("K= # only a comment\n").unwrap().entries.is_empty());
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(
            one(r"K='a\nb $x # not a comment'"),
            r"a\nb $x # not a comment"
        );
    }

    #[test]
    fn double_quotes_unescape_and_keep_unknown_backslashes() {
        assert_eq!(one(r#"K="a\nb\t\"q\" \\ \d""#), "a\nb\t\"q\" \\ \\d");
    }

    #[test]
    fn quoted_values_may_span_lines() {
        let got = pairs("PEM=\"-----BEGIN-----\nline two\n-----END-----\"\nNEXT=1\n");
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].1.lines().count(), 3);
        assert_eq!(got[1], ("NEXT".into(), "1".into()));
        let got = pairs("A='x\ny'\nB=2\n");
        assert_eq!(got[0], ("A".into(), "x\ny".into()));
        assert_eq!(got[1], ("B".into(), "2".into()));
    }

    #[test]
    fn text_after_a_closing_quote_is_refused_but_a_comment_is_fine() {
        assert_eq!(one("K=\"v\" # why"), "v");
        let err = parse("K=\"v\" extra").err().unwrap();
        assert!(err.contains("line 1"), "{err}");
        assert!(!err.contains("extra"), "must not echo content: {err}");
    }

    #[test]
    fn empty_values_are_skipped_by_name() {
        let p = parse("A=1\nB=\nC=\"\"\nD='' # note\n").unwrap();
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.skipped_empty, vec!["B", "C", "D"]);
    }

    #[test]
    fn a_duplicate_key_is_refused_with_both_line_numbers() {
        let err = parse("A=1\nB=2\nA=3\n").err().unwrap();
        assert!(
            err.contains("line 3") && err.contains("line 1") && err.contains('A'),
            "{err}"
        );
        // Even when one of the two is an empty placeholder.
        assert!(parse("A=\nA=1\n").is_err());
    }

    #[test]
    fn errors_name_the_line_and_never_echo_its_content() {
        for (text, line) in [
            ("OK=1\nsk-this-is-a-bare-token-shaped-line\n", "line 2"),
            ("OK=1\n=novalue-token-9f3\n", "line 2"),
            ("bad name=tok-shaped-77\n", "line 1"),
            ("K=\"never closed tok-shaped-88\nmore\n", "line 1"),
            ("OK=1\nK=\"v\" tok-shaped-99\n", "line 2"),
        ] {
            let err = parse(text)
                .err()
                .unwrap_or_else(|| panic!("{text:?} parsed"));
            assert!(err.contains(line), "{err} should name {line}");
            assert!(!err.contains("tok-shaped"), "echoed content: {err}");
            assert!(!err.contains("bare-token"), "echoed content: {err}");
            assert!(!err.contains("novalue"), "echoed content: {err}");
        }
    }

    #[test]
    fn a_missing_closing_quote_that_would_swallow_the_next_assignment_is_refused() {
        // `SECOND="..."` would otherwise close FIRST's quote with its own opening
        // one, and `API_KEY=xyz"` with its trailing one — both silently.
        for (text, start, swallowed) in [
            (
                "PASSWORD=\"abc\nAPI_KEY=xyz\"\nOTHER=1\n",
                "line 1",
                "line 2",
            ),
            ("OK=1\nPASSWORD='abc\nAPI_KEY=xyz'\n", "line 2", "line 3"),
            ("A=\"abc\nexport B=1\n", "line 1", "line 2"),
            // Lower-case and dotted names are assignments too.
            ("A=\"abc\napi_key=xyz\"\n", "line 1", "line 2"),
            ("A=\"abc\nsvc.token = xyz\"\n", "line 1", "line 2"),
            // Even when the swallowed line is not the first continuation.
            ("A=\"one\ntwo\nthree\nB=4\"\n", "line 1", "line 4"),
        ] {
            let err = parse(text)
                .err()
                .unwrap_or_else(|| panic!("{text:?} parsed instead of being refused"));
            assert!(
                err.contains(start) && err.contains(swallowed),
                "{err} should name {start} and {swallowed}"
            );
            // Line numbers and fixed words only — never what the lines held.
            for content in ["abc", "xyz", "two", "three"] {
                assert!(!err.contains(content), "echoed content {content:?}: {err}");
            }
        }
    }

    #[test]
    fn multi_line_values_that_are_not_assignments_still_parse() {
        // A PEM body, ending in base64 padding that has the shape of `NAME=`.
        for tail in ["Zm8=", "Zg==", "QUJD"] {
            let text = format!("PEM=\"-----BEGIN X-----\nMIIBIjANBgkq+/hkiG9w0B\n{tail}\n-----END X-----\"\nNEXT=1\n");
            let got = pairs(&text);
            assert_eq!(got.len(), 2, "{tail}: {got:?}");
            assert!(got[0].1.contains(tail), "{tail}: {got:?}");
        }
        // Prose, JSON, a YAML-ish block: nothing there starts `NAME=`.
        let got = pairs("MSG=\"first line\nsecond: line\n{\\\"k\\\": 1}\nlast\"\nNEXT=1\n");
        assert_eq!(got.len(), 2, "{got:?}");
        // A line with `=` that is not a valid name does not trip it either.
        let got = pairs("K='a b\nsome text = more\nx+y=z\nend'\n");
        assert_eq!(got.len(), 1, "{got:?}");
        // And the way out for a value that really holds an assignment-shaped
        // line: one line, `\n` escapes, double quotes.
        assert_eq!(
            one("K=\"line one\\nFOO=bar\\nline three\""),
            "line one\nFOO=bar\nline three"
        );
    }

    #[test]
    fn looks_like_assignment_tells_padding_from_names() {
        for yes in [
            "A=1",
            "  export A=1",
            "a_b = 2",
            "svc.token=x",
            // One case, letters only: a name, not padding — even at a length
            // that is a multiple of four.
            "KEY=",
            "PLACEHOLDER=",
            "Z==",
        ] {
            assert!(looks_like_assignment(yes), "{yes:?} should look like one");
        }
        for no in [
            "Zm8=",
            "Zg==",
            "AB+/CD==",
            "plain text",
            "x+y=z",
            "a b=c",
            "=v",
            "",
        ] {
            assert!(
                !looks_like_assignment(no),
                "{no:?} should not look like one"
            );
        }
    }

    #[test]
    fn crlf_and_a_byte_order_mark_are_tolerated() {
        let got = pairs("\u{feff}A=1\r\nB=\"two\"\r\n");
        assert_eq!(
            got,
            vec![("A".into(), "1".into()), ("B".into(), "two".into())]
        );
    }

    #[test]
    fn a_file_with_nothing_importable_parses_to_nothing() {
        let p = parse("# only comments\n\n").unwrap();
        assert!(p.entries.is_empty() && p.skipped_empty.is_empty());
    }
}
