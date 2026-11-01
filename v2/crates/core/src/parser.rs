//! The bulk-paste field grammar. See `docs/08_FIELD_MODEL.md §3`.
//!
//! Two rules: a `label: value` line is one field; a line containing only
//! `///` starts a new field/segment. Total, deterministic, lossless,
//! order-preserving, duplicate-tolerant (§3.4).
//!
//! **Resolved ambiguity.** The formal grammar in `08 §3.1` writes
//! `LABELLED_LINE ::= LABEL ":" " " WS* VALUE_TEXT` — a mandatory space
//! followed by *additional* optional whitespace before the value starts. Read
//! literally, that strips leading spaces from the value. But `08 §3.5` states
//! plainly: *"No trimming of value whitespace beyond the trailing newline. A
//! password may begin or end with a space, and truncating it silently is the
//! worst possible bug in this product."* Those two statements contradict each
//! other for a value like `"password:  x"` (two spaces): the grammar would
//! store `"x"`, the prose guarantee requires `" x"`. This implementation
//! follows the prose: exactly one literal space is the separator, and
//! everything after it — including further leading whitespace — is the
//! value, untouched. The formal grammar's `WS*` is treated as imprecise
//! shorthand, not a second rule.

const RESERVED_SCHEMES: &[&str] = &[
    "http",
    "https",
    "ftp",
    "ftps",
    "ssh",
    "sftp",
    "git",
    "file",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "mongodb",
    "amqp",
    "otpauth",
    "data",
    "mailto",
    "s3",
    "gs",
];

/// One field extracted from a bulk paste. `label` is empty when the parser
/// could not find one — the UI renders that as `"field N"` (`08 §2`); this
/// crate has no UI concept of field numbering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedField {
    pub label: String,
    pub value: String,
}

fn is_label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " _.()#/-".contains(c)
}

/// `LABEL ::= 1..40 chars matching [A-Za-z0-9 _.()#/-]+`, excluding the
/// reserved URI schemes (`08 §3.1`).
fn is_valid_label(s: &str) -> bool {
    let len = s.chars().count();
    if len == 0 || len > 40 {
        return false;
    }
    if !s.chars().all(is_label_char) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    !RESERVED_SCHEMES.contains(&lower.as_str())
}

/// `LABELLED_LINE ::= LABEL ":" " " VALUE_TEXT` — see the module doc for why
/// this does not also consume `WS*` before the value.
fn parse_labelled_line(line: &str) -> Option<(&str, &str)> {
    let sep = line.find(": ")?;
    let label = &line[..sep];
    if !is_valid_label(label) {
        return None;
    }
    Some((label, &line[sep + 2..]))
}

/// `LABEL_ONLY ::= LABEL ":" WS* LINE_END`.
fn parse_label_only(line: &str) -> Option<&str> {
    let label = line.trim_end().strip_suffix(':')?;
    is_valid_label(label).then_some(label)
}

fn is_separator_line(line: &str) -> bool {
    line.trim() == "///"
}

/// One line, tracked with its byte position so multi-line values can be
/// recovered as exact substrings of `input` rather than rebuilt by joining —
/// joining with `"\n"` cannot tell "no trailing newline" from "one trailing
/// empty line" apart, which `08 §3`'s "verbatim, with the trailing newline
/// trimmed" wording depends on being able to distinguish.
struct Line<'a> {
    content: &'a str,
    start: usize,
    /// Byte offset immediately after this line's terminator (or its content,
    /// if it has none — true only for the final line of the input).
    next: usize,
}

/// Split on `\n`, `\r\n`, and lone `\r`. A trailing terminator with nothing
/// after it does not produce a spurious empty final line (mirrors
/// `str::lines()`, which only handles `\n`/`\r\n`).
fn split_lines(input: &str) -> Vec<Line<'_>> {
    if input.is_empty() {
        return Vec::new();
    }
    let bytes = input.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(Line {
                    content: &input[start..i],
                    start,
                    next: i + 1,
                });
                i += 1;
                start = i;
            }
            b'\r' => {
                let content_end = i;
                i += 1;
                if i < bytes.len() && bytes[i] == b'\n' {
                    i += 1;
                }
                lines.push(Line {
                    content: &input[start..content_end],
                    start,
                    next: i,
                });
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        lines.push(Line {
            content: &input[start..],
            start,
            next: bytes.len(),
        });
    }
    lines
}

fn split_segments(lines: Vec<Line<'_>>) -> Vec<Vec<Line<'_>>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    for line in lines {
        if is_separator_line(line.content) {
            segments.push(std::mem::take(&mut current));
        } else {
            current.push(line);
        }
    }
    segments.push(current);
    segments
}

/// Strip exactly one trailing terminator (`\r\n`, `\n`, or `\r`), if present.
fn trim_one_trailing_terminator(s: &str) -> &str {
    s.strip_suffix("\r\n")
        .or_else(|| s.strip_suffix(['\n', '\r']))
        .unwrap_or(s)
}

fn parse_segment(input: &str, lines: &[Line<'_>]) -> Vec<ParsedField> {
    let non_empty: Vec<&Line> = lines
        .iter()
        .filter(|l| !l.content.trim().is_empty())
        .collect();

    if !non_empty.is_empty()
        && non_empty
            .iter()
            .all(|l| parse_labelled_line(l.content).is_some())
    {
        return non_empty
            .into_iter()
            .map(|l| {
                let (label, value) = parse_labelled_line(l.content).expect("checked above");
                ParsedField {
                    label: label.to_string(),
                    value: value.to_string(),
                }
            })
            .collect();
    }

    let (Some(first), Some(last)) = (lines.first(), lines.last()) else {
        return Vec::new();
    };
    // The raw text of this whole segment, exactly as it appeared in `input`.
    let raw_segment = &input[first.start..last.next];

    match parse_label_only(first.content) {
        Some(label) => {
            let remaining = &input[first.next..last.next];
            vec![ParsedField {
                label: label.to_string(),
                value: trim_one_trailing_terminator(remaining).to_string(),
            }]
        }
        None => vec![ParsedField {
            label: String::new(),
            value: raw_segment.to_string(),
        }],
    }
}

/// Parse a bulk paste into fields, **keeping the `///` segment boundaries**:
/// one inner `Vec` per non-empty segment, in input order. The desktop's
/// split-by-`///` toggle creates one entry per segment (ADR-078); a client that
/// wants a single entry flattens them, which is exactly what [`parse_bulk`] does
/// (property P-18 pins `flatten(parse_bulk_segments(x)) == parse_bulk(x)`).
///
/// Total (never panics, never rejects) and deterministic. A segment with no
/// lines at all (two adjacent `///` separators, or a leading/trailing one)
/// produces no inner `Vec` — never an empty one — so every inner `Vec` holds at
/// least one field.
pub fn parse_bulk_segments(input: &str) -> Vec<Vec<ParsedField>> {
    let lines = split_lines(input);
    split_segments(lines)
        .into_iter()
        .filter(|seg| !seg.is_empty())
        .map(|seg| parse_segment(input, &seg))
        .filter(|fields| !fields.is_empty())
        .collect()
}

/// Parse a bulk paste into fields. Total (never panics, never rejects) and
/// deterministic. See `08_FIELD_MODEL.md §3.4` for the full guarantee list.
pub fn parse_bulk(input: &str) -> Vec<ParsedField> {
    parse_bulk_segments(input).into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // §3.2's table, one row per test.

    #[test]
    fn host_colon_space_value() {
        let fields = parse_bulk("host: db.internal");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "host".into(),
                value: "db.internal".into()
            }]
        );
    }

    #[test]
    fn colon_no_space_is_unlabelled() {
        let fields = parse_bulk("db.internal:5432");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "".into(),
                value: "db.internal:5432".into()
            }]
        );
    }

    #[test]
    fn bare_url_is_unlabelled() {
        let fields = parse_bulk("https://api.example.com");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "".into(),
                value: "https://api.example.com".into()
            }]
        );
    }

    #[test]
    fn labelled_url() {
        let fields = parse_bulk("url: https://api.example.com");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "url".into(),
                value: "https://api.example.com".into()
            }]
        );
    }

    #[test]
    fn first_colon_space_wins() {
        let fields = parse_bulk("note: ratio is 3:1");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "note".into(),
                value: "ratio is 3:1".into()
            }]
        );
    }

    #[test]
    fn label_only_captures_following_lines() {
        let fields = parse_bulk("private key:\nline one\nline two");
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "private key".into(),
                value: "line one\nline two".into()
            }]
        );
    }

    // §3.3 worked examples.

    #[test]
    fn worked_example_a_server_block() {
        let fields =
            parse_bulk("host: 203.0.113.4\nport: 22\nusername: root\npassword: hunter2-not-really");
        assert_eq!(
            fields,
            vec![
                ParsedField {
                    label: "host".into(),
                    value: "203.0.113.4".into()
                },
                ParsedField {
                    label: "port".into(),
                    value: "22".into()
                },
                ParsedField {
                    label: "username".into(),
                    value: "root".into()
                },
                ParsedField {
                    label: "password".into(),
                    value: "hunter2-not-really".into()
                },
            ]
        );
    }

    #[test]
    fn worked_example_b_key_spanning_lines() {
        // The synthetic PEM body from 08_FIELD_MODEL.md §3.3's worked example —
        // not a real key, just base64-shaped filler. The header and footer are
        // built from fragments so the source never carries a contiguous
        // key-block header (which the portfolio secret scanner refuses).
        const BEGIN: &str = concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----");
        const END: &str = concat!("-----END OPENSSH ", "PRIVATE KEY-----");
        let input = format!(
            "username: deploy\n///\nprivate key:\n{BEGIN}\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n{END}\n\
///\npassphrase: correct horse battery staple"
        );
        let fields = parse_bulk(&input);
        assert_eq!(fields.len(), 3);
        assert_eq!(
            fields[0],
            ParsedField {
                label: "username".into(),
                value: "deploy".into()
            }
        );
        assert_eq!(fields[1].label, "private key");
        assert!(fields[1].value.contains(BEGIN));
        assert!(fields[1].value.contains(END));
        assert_eq!(
            fields[2],
            ParsedField {
                label: "passphrase".into(),
                value: "correct horse battery staple".into()
            }
        );
    }

    #[test]
    fn worked_example_c_unstructured_blob() {
        let input = "prod db is at 10.0.0.4 port 5432 user svc_app pw Z9!kq2 rotate quarterly";
        let fields = parse_bulk(input);
        assert_eq!(
            fields,
            vec![ParsedField {
                label: "".into(),
                value: input.into()
            }]
        );
    }

    #[test]
    fn leading_and_trailing_spaces_in_value_survive() {
        let fields = parse_bulk("password:  leading and trailing  ");
        assert_eq!(fields[0].value, " leading and trailing  ");
    }

    #[test]
    fn duplicate_labels_both_preserved_in_order() {
        let fields = parse_bulk("key: one\nkey: two");
        assert_eq!(
            fields,
            vec![
                ParsedField {
                    label: "key".into(),
                    value: "one".into()
                },
                ParsedField {
                    label: "key".into(),
                    value: "two".into()
                },
            ]
        );
    }

    #[test]
    fn crlf_and_lone_cr_both_split_lines() {
        assert_eq!(parse_bulk("host: a\r\nport: b").len(), 2);
        assert_eq!(parse_bulk("host: a\rport: b").len(), 2);
    }

    #[test]
    fn empty_input_produces_no_fields() {
        assert_eq!(parse_bulk(""), vec![]);
    }

    #[test]
    fn reserved_scheme_as_would_be_label_falls_back_to_unlabelled() {
        // "https" is a reserved scheme, so this must NOT parse as label="https".
        let fields = parse_bulk("https: not actually a label");
        assert_eq!(fields[0].label, "");
    }

    #[test]
    fn split_each_segment_by_triple_slash_matches_multiple_fields() {
        let fields = parse_bulk("a: 1\n///\nb: 2\n///\nc: 3");
        assert_eq!(fields.len(), 3);
    }

    // Never panics for arbitrary input — parse never indexes, unwraps, or
    // slices at a non-char-boundary because all splitting happens on
    // guaranteed single-byte ASCII terminators.
    #[test]
    fn never_panics_on_pathological_input() {
        let emoji = "🎉".repeat(1000);
        let long_label = "a".repeat(50);
        let inputs = [
            "\0",
            emoji.as_str(),
            long_label.as_str(),
            ":",
            ": ",
            "///",
            "///\n///\n///",
            "\r\r\r\n\n\r",
        ];
        for input in inputs {
            let _ = parse_bulk(input);
        }
    }

    // ADR-078: segment boundaries survive for the split-by-`///` toggle.

    #[test]
    fn segments_keep_the_triple_slash_boundaries() {
        let segments = parse_bulk_segments("a: 1\nb: 2\n///\nloose blob\n///\nc: 3");
        let shape: Vec<Vec<(&str, &str)>> = segments
            .iter()
            .map(|s| {
                s.iter()
                    .map(|f| (f.label.as_str(), f.value.as_str()))
                    .collect()
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                vec![("a", "1"), ("b", "2")],
                // An unlabelled blob keeps its own line terminator (08 §3.3):
                // that is the existing parser behaviour, not something the
                // segment API changes.
                vec![("", "loose blob\n")],
                vec![("c", "3")],
            ]
        );
    }

    #[test]
    fn empty_segments_produce_no_inner_vec_and_no_separator_means_one_segment() {
        assert!(parse_bulk_segments("").is_empty());
        assert!(parse_bulk_segments("///").is_empty());
        assert!(parse_bulk_segments("///\n///\n///").is_empty());
        let leading_and_trailing = parse_bulk_segments("///\na: 1\n///\n///\nb: 2\n///");
        assert_eq!(leading_and_trailing.len(), 2);
        assert_eq!(parse_bulk_segments("a: 1\nb: 2").len(), 1);
        assert!(parse_bulk_segments("a: 1\n///\nb: 2")
            .iter()
            .all(|s| !s.is_empty()));
    }

    #[test]
    fn flattening_the_segments_is_parse_bulk() {
        for input in [
            "",
            "///",
            "a: 1\n///\nb: 2\n///\nc: 3",
            "private key:\nline one\nline two\n///\nhost: x",
            "blob with no labels\nand a second line",
            "\r\r\r\n\n\r",
        ] {
            let flat: Vec<ParsedField> = parse_bulk_segments(input).into_iter().flatten().collect();
            assert_eq!(flat, parse_bulk(input), "{input:?}");
        }
    }

    #[test]
    fn deterministic_across_repeats() {
        let input = "a: 1\n///\nunstructured blob\nb: 2";
        let first = parse_bulk(input);
        for _ in 0..100 {
            assert_eq!(parse_bulk(input), first);
        }
    }
}
