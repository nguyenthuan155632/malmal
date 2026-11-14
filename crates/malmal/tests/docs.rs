//! Keeps `docs/findings.md` complete: every finding code the sources can
//! emit has a row there, and every row names a code that exists.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const GROUPS: [&str; 10] = [
    "type", "name", "payload", "limit", "hash", "yara", "image", "svg", "pdf", "ps",
];

/// Everything between two `quote` characters that is spelled like a code.
fn codes(text: &str, quote: char) -> BTreeSet<String> {
    text.split(quote)
        .filter(|candidate| {
            let group = candidate.split('.').next().unwrap_or("");
            candidate.contains('.')
                && GROUPS.contains(&group)
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_')
                && candidate.ends_with(|c: char| c.is_ascii_lowercase())
        })
        .map(str::to_string)
        .collect()
}

fn sources(dir: &Path, text: &mut String) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, text);
        } else if path.ends_with("report.rs") {
            // Holds the list of codes, which is checked against the others.
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            text.push_str(&fs::read_to_string(&path).unwrap());
        }
    }
}

#[test]
fn every_finding_code_is_documented() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source = String::new();
    sources(&root.join("src"), &mut source);
    let emitted = codes(&source, '"');
    let documented = codes(
        &fs::read_to_string(root.join("../../docs/findings.md")).unwrap(),
        '`',
    );
    assert!(emitted.len() > 40, "codes were not found in the sources");

    let undocumented: Vec<_> = emitted.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "missing from docs/findings.md: {undocumented:?}"
    );
    let unknown: Vec<_> = documented.difference(&emitted).collect();
    assert!(
        unknown.is_empty(),
        "documented but never emitted: {unknown:?}"
    );

    let listed: BTreeSet<String> = malmal::report::CODES
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        listed.len(),
        malmal::report::CODES.len(),
        "a code is listed twice"
    );
    assert_eq!(listed, emitted, "malmal::report::CODES is out of date");
}
