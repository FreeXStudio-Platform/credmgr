//! ADR-167 — entry tags: free-text labels the owner puts on an entry, normalised here so the broker, the
//! CLI and the desktop shell agree on what one tag is.
//!
//! A tag is **names-level metadata**: it sits on the entry's signed manifest row beside the name and the
//! aliases, it is readable by exactly whoever may list the node (and hidden from a reader who may not see
//! the node's names), and it is never an index across nodes. Nothing here touches I/O.
//!
//! The rule, in order:
//! 1. surrounding white space is trimmed;
//! 2. the tag is lower-cased (so `Prod` and `prod` are one tag);
//! 3. every run of inner white space becomes one `-` (so `staging db` is `staging-db`);
//! 4. what is left must be 1 to [`TAG_MAX_CHARS`] characters, each a letter or digit (any script) or one of
//!    `-` `_` `.` `:` `/`;
//! 5. an entry holds at most [`TAGS_MAX`] tags; two that normalise the same are one tag (the first kept).

/// The most tags one entry holds.
pub const TAGS_MAX: usize = 16;
/// The longest one tag may be, in characters, once normalised.
pub const TAG_MAX_CHARS: usize = 32;
/// The punctuation a tag may hold besides letters and digits.
pub const TAG_PUNCTUATION: &[char] = &['-', '_', '.', ':', '/'];

/// Why a supplied tag is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagError {
    /// Nothing is left once white space is trimmed.
    Empty,
    /// Longer than [`TAG_MAX_CHARS`] once normalised.
    TooLong,
    /// A character that is not a letter, a digit or [`TAG_PUNCTUATION`].
    BadCharacter,
}

impl TagError {
    pub fn as_str(self) -> &'static str {
        match self {
            TagError::Empty => "is empty",
            TagError::TooLong => "is longer than 32 characters",
            TagError::BadCharacter => "may hold only letters, digits, spaces and - _ . : /",
        }
    }
}

/// One tag, normalised (see the module rule), or why it is refused.
pub fn normalise_tag(raw: &str) -> Result<String, TagError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TagError::Empty);
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut in_space = false;
    for c in trimmed.chars() {
        if c.is_whitespace() {
            in_space = true;
            continue;
        }
        if in_space {
            out.push('-');
            in_space = false;
        }
        if c.is_alphanumeric() || TAG_PUNCTUATION.contains(&c) {
            out.extend(c.to_lowercase());
        } else {
            return Err(TagError::BadCharacter);
        }
    }
    if out.chars().count() > TAG_MAX_CHARS {
        return Err(TagError::TooLong);
    }
    Ok(out)
}

/// Why a supplied list of tags is refused: which one (by index) and why, or that there are too many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagsError {
    /// The tag at this index is refused.
    Tag(usize, TagError),
    /// More than [`TAGS_MAX`] distinct tags once normalised.
    TooMany,
}

/// A whole list, normalised and de-duplicated in the order given (the first spelling of a repeated tag is
/// the one kept, in its normalised form).
pub fn normalise_tags<'a>(
    raw: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, TagsError> {
    let mut out: Vec<String> = Vec::new();
    for (i, t) in raw.into_iter().enumerate() {
        let tag = normalise_tag(t).map_err(|e| TagsError::Tag(i, e))?;
        if !out.contains(&tag) {
            out.push(tag);
        }
    }
    if out.len() > TAGS_MAX {
        return Err(TagsError::TooMany);
    }
    Ok(out)
}

/// `current` with `add` appended and `remove` taken out (all normalised), the way `credmgr tag --add/--remove`
/// edits a set: what is added is added once, what is removed and not there is ignored.
pub fn edit_tags(current: &[String], add: &[String], remove: &[String]) -> Vec<String> {
    let mut out: Vec<String> = current
        .iter()
        .filter(|t| !remove.contains(t))
        .cloned()
        .collect();
    for t in add {
        if !out.contains(t) && !remove.contains(t) {
            out.push(t.clone());
        }
    }
    out
}

/// The union of two tag sets, `first`'s order first (a merge keeps the kept entry's tags in front).
pub fn union_tags(first: &[String], second: &[String]) -> Vec<String> {
    let mut out = first.to_vec();
    for t in second {
        if !out.contains(t) {
            out.push(t.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_trimmed_lower_cased_and_its_inner_spaces_become_one_dash() {
        assert_eq!(normalise_tag("  Prod ").unwrap(), "prod");
        assert_eq!(normalise_tag("Staging   DB").unwrap(), "staging-db");
        assert_eq!(
            normalise_tag("team:payments/eu").unwrap(),
            "team:payments/eu"
        );
        assert_eq!(normalise_tag("ÉQUIPE").unwrap(), "équipe");
        assert_eq!(normalise_tag("v1.2_rc").unwrap(), "v1.2_rc");
    }

    #[test]
    fn empty_long_and_odd_tags_are_refused() {
        assert_eq!(normalise_tag("   "), Err(TagError::Empty));
        assert_eq!(normalise_tag(""), Err(TagError::Empty));
        assert_eq!(normalise_tag(&"a".repeat(33)), Err(TagError::TooLong));
        assert!(normalise_tag(&"a".repeat(32)).is_ok());
        assert_eq!(normalise_tag("no,commas"), Err(TagError::BadCharacter));
        assert_eq!(normalise_tag("tab\u{7}bell"), Err(TagError::BadCharacter));
        assert_eq!(normalise_tag("quote\""), Err(TagError::BadCharacter));
        assert_eq!(normalise_tag("#hash"), Err(TagError::BadCharacter));
    }

    #[test]
    fn a_list_is_deduplicated_after_normalising_and_capped() {
        assert_eq!(
            normalise_tags(["Prod", "prod", " PROD ", "db"]).unwrap(),
            vec!["prod".to_string(), "db".to_string()]
        );
        let many: Vec<String> = (0..17).map(|i| format!("t{i}")).collect();
        assert_eq!(
            normalise_tags(many.iter().map(String::as_str)),
            Err(TagsError::TooMany)
        );
        let sixteen: Vec<String> = (0..16).map(|i| format!("t{i}")).collect();
        assert_eq!(
            normalise_tags(sixteen.iter().map(String::as_str))
                .unwrap()
                .len(),
            16
        );
        // Duplicates do not count toward the cap.
        let repeated = ["x"; 40];
        assert_eq!(normalise_tags(repeated).unwrap(), vec!["x".to_string()]);
        assert_eq!(
            normalise_tags(["ok", "bad,one"]),
            Err(TagsError::Tag(1, TagError::BadCharacter))
        );
    }

    #[test]
    fn edit_and_union_keep_order_and_never_duplicate() {
        let cur = vec!["a".to_string(), "b".to_string()];
        assert_eq!(
            edit_tags(&cur, &["c".into(), "a".into()], &["b".into()]),
            vec!["a".to_string(), "c".to_string()]
        );
        assert_eq!(
            union_tags(&cur, &["b".into(), "z".into()]),
            vec!["a".to_string(), "b".to_string(), "z".to_string()]
        );
    }
}
