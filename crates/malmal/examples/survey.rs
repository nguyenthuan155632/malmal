//! Measure verdicts over a set of real files:
//!
//!     cargo run --release --example survey -- [OPTIONS] PATH...
//!
//! Every file below each PATH is scanned with its name as the hint. The
//! summary counts verdicts and findings; what matters on a set of files that
//! are known to be good is the list of those that did not come back clean.
//!
//!     --expect-clean   Exit with status 1 unless every file is clean
//!     --tsv            Print one `path<TAB>verdict<TAB>codes` line per file
//!                      instead of the summary, to diff between two versions

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use malmal::{ScanHints, Scanner, Verdict};

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = match fs::read_dir(path) {
            Ok(entries) => entries
                .filter_map(|entry| Some(entry.ok()?.path()))
                .collect(),
            Err(error) => return eprintln!("{}: {error}", path.display()),
        };
        entries.sort();
        for entry in entries {
            collect(&entry, files);
        }
    } else {
        files.push(path.to_path_buf());
    }
}

fn main() -> ExitCode {
    let (mut expect_clean, mut tsv) = (false, false);
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--expect-clean" => expect_clean = true,
            "--tsv" => tsv = true,
            path => collect(Path::new(path), &mut files),
        }
    }
    if files.is_empty() {
        eprintln!("usage: survey [--expect-clean] [--tsv] PATH...");
        return ExitCode::from(2);
    }

    let scanner = Scanner::builder().build();
    let mut verdicts: BTreeMap<Verdict, usize> = BTreeMap::new();
    let mut codes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut flagged = Vec::new();
    for path in &files {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                continue;
            }
        };
        let name = path.file_name().and_then(|name| name.to_str());
        let hints = ScanHints {
            filename: name,
            content_type: None,
        };
        let report = scanner.scan_bytes(&data, hints);
        *verdicts.entry(report.verdict).or_default() += 1;
        let mut found: Vec<&'static str> = report.findings.iter().map(|f| f.code).collect();
        found.sort_unstable();
        found.dedup();
        for code in &found {
            *codes.entry(code).or_default() += 1;
        }
        let line = format!(
            "{}\t{:?}\t{}",
            path.display(),
            report.verdict,
            found.join(",")
        );
        if tsv {
            println!("{line}");
        }
        if report.verdict != Verdict::Clean {
            flagged.push(line);
        }
    }

    if !tsv {
        println!("{} files", files.len());
        for (verdict, count) in &verdicts {
            println!("{count:>8}  {verdict:?}");
        }
        println!("\nfindings, by number of files");
        let mut by_count: Vec<_> = codes.into_iter().collect();
        by_count.sort_by_key(|&(code, count)| (std::cmp::Reverse(count), code));
        for (code, count) in by_count {
            println!("{count:>8}  {code}");
        }
        if !flagged.is_empty() {
            println!("\nnot clean");
            for line in &flagged {
                println!("  {line}");
            }
        }
    }
    if expect_clean && !flagged.is_empty() {
        eprintln!("{} of {} files are not clean", flagged.len(), files.len());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
