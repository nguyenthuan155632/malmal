//! Scans every file in `tests/corpus` at the repository root; see the README
//! there.

use std::fs;
use std::path::{Path, PathBuf};

use malmal::{ScanHints, Scanner, Verdict};

fn corpus(kind: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus")
        .join(kind);
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    assert!(!files.is_empty(), "{} is empty", dir.display());
    files
}

fn verdicts(kind: &str, expected: Verdict) -> Vec<String> {
    let scanner = Scanner::builder().build();
    corpus(kind)
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_string();
            let hints = ScanHints {
                filename: Some(&name),
                content_type: None,
            };
            let report = scanner.scan_bytes(&fs::read(&path).unwrap(), hints);
            (report.verdict != expected)
                .then(|| format!("{name}: {:?} {:?}", report.verdict, report.findings))
        })
        .collect()
}

#[test]
fn clean_corpus_is_clean() {
    let wrong = verdicts("clean", Verdict::Clean);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn malicious_corpus_is_blocked() {
    let wrong = verdicts("malicious", Verdict::Malicious);
    assert!(wrong.is_empty(), "{wrong:#?}");
}
