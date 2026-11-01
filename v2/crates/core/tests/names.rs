//! ADR-084: `names::LOOKALIKES` is the table in `docs/FRONTEND_THREAT_MODEL.md`
//! ("Look-alike table"), pair for pair — so the broker, the CLI and the window
//! (which folds from the same text) cannot drift apart.

use credmgr_core::names::{canonical_name, LOOKALIKES};

fn doc_pairs() -> Option<Vec<(char, char)>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/FRONTEND_THREAT_MODEL.md"
    );
    // The public export may not ship the imported threat model.
    let text = std::fs::read_to_string(path).ok()?;
    let start = text.find("## Look-alike table (T4)")?;
    let section = &text[start..];
    let end = section[3..].find("\n## ").map_or(section.len(), |i| i + 3);
    let mut pairs = Vec::new();
    for line in section[..end].lines().skip(1) {
        // Lines look like: `Cyrillic: а→a е→e …`, `Greek: ο→o …`, `Other: ı→i …`
        let Some((_, rest)) = line.split_once(": ") else {
            continue;
        };
        for tok in rest.split_whitespace() {
            let Some((from, to)) = tok.split_once('→') else {
                continue;
            };
            let (mut f, mut t) = (from.chars(), to.trim_end_matches('.').chars());
            if let (Some(a), Some(b), None, None) = (f.next(), t.next(), f.next(), t.next()) {
                pairs.push((a, b));
            }
        }
    }
    Some(pairs)
}

#[test]
fn the_table_in_code_is_the_table_in_the_threat_model() {
    let Some(mut doc) = doc_pairs() else {
        eprintln!("FRONTEND_THREAT_MODEL.md not present — pin test skipped");
        return;
    };
    let mut code: Vec<(char, char)> = LOOKALIKES.to_vec();
    doc.sort_unstable();
    code.sort_unstable();
    assert_eq!(doc.len(), 26, "the doc table lists 26 pairs");
    assert_eq!(code, doc);
}

#[test]
fn every_pair_folds_and_ascii_digits_do_not() {
    for (from, to) in LOOKALIKES {
        assert_eq!(canonical_name(&from.to_string()), to.to_string());
        assert_eq!(
            canonical_name(&from.to_uppercase().to_string()),
            to.to_string()
        );
    }
    assert_ne!(canonical_name("0"), canonical_name("o"));
    assert_ne!(canonical_name("1"), canonical_name("l"));
}

/// The shared test vectors (`tests/fixtures/name_vectors.json`): the design side runs the same file against its own fold, so the
/// window and the broker cannot drift (ADR-084, front-end handoff 2026-10-25 section 3, item 3).
#[test]
fn the_shared_name_vectors_hold() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/name_vectors.json"
    ))
    .expect("read name_vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("name_vectors.json is JSON");
    let vectors = doc["vectors"].as_array().expect("a vectors array");
    assert!(vectors.len() >= 10, "the file must keep its vectors");
    for v in vectors {
        let input = v["input"].as_str().expect("input");
        let want = v["canonical"].as_str().expect("canonical");
        assert_eq!(
            credmgr_core::names::canonical_name(input),
            want,
            "canonical_name({:?}) — {}",
            input,
            v["note"]
        );
        assert_eq!(
            credmgr_core::names::mixes_scripts(input),
            v["mixedScript"].as_bool().expect("mixedScript"),
            "mixes_scripts({:?}) — {}",
            input,
            v["note"]
        );
    }
}
