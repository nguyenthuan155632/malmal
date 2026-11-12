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

/// One line per sample: its path, verdict and finding codes.
fn recorded() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests");
    let scanner = Scanner::builder().build();
    let mut lines = Vec::new();
    for dir in ["corpus/clean", "corpus/malicious", "prototypes/files"] {
        let Ok(entries) = fs::read_dir(root.join(dir)) else {
            continue;
        };
        for path in entries.map(|entry| entry.unwrap().path()) {
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if !path.is_file() || name == "manifest.csv" {
                continue;
            }
            let hints = ScanHints {
                filename: Some(&name),
                content_type: None,
            };
            let report = scanner.scan_bytes(&fs::read(&path).unwrap(), hints);
            let mut codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
            codes.sort_unstable();
            codes.dedup();
            lines.push(format!(
                "{dir}/{name}\t{:?}\t{}\n",
                report.verdict,
                codes.join(",")
            ));
        }
    }
    lines.sort();
    lines.concat()
}

/// A change to an analyzer shows up here as the samples whose findings
/// moved, in either direction. When the change is intended, record it:
///
///     MALMAL_RECORD=1 cargo test -p malmal --test corpus
#[test]
fn findings_match_the_recorded_ones() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/expected.tsv");
    let actual = recorded();
    if std::env::var_os("MALMAL_RECORD").is_some() {
        fs::write(&file, &actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&file).unwrap_or_default();
    let changed: Vec<String> = actual
        .lines()
        .filter(|line| !expected.lines().any(|known| known == *line))
        .map(|line| format!("now:      {line}"))
        .chain(
            expected
                .lines()
                .filter(|line| !actual.lines().any(|found| found == *line))
                .map(|line| format!("recorded: {line}")),
        )
        .collect();
    assert!(
        changed.is_empty(),
        "findings differ from tests/corpus/expected.tsv:\n{}",
        changed.join("\n")
    );
}
