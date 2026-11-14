//! Measure the scanner on files whose nature is known:
//!
//!     cargo run --release --example evaluate -- [OPTIONS]
//!
//!     --clean PATH       Files that must be accepted; may be repeated
//!     --malicious PATH   Files that must not be; may be repeated
//!     --strict           Use the strict policy
//!     --max-size BYTES   Largest file analyzed in full
//!     --tsv FILE         Write one `class<TAB>path<TAB>verdict<TAB>codes`
//!                        line per file, to diff between two versions
//!     --list N           How many wrong files of each kind to name [20]
//!
//! Every file below each PATH is scanned by its content alone, on every
//! processor. The report says how many malicious files were refused, how
//! many clean ones were refused with them, and for which findings: those
//! are the ones to look at before trusting either number.
//!
//! Sets of real PDF files with known labels:
//!
//! - CIC-Evasive-PDFMal2022, <https://www.unb.ca/cic/datasets/pdfmal-2022.html>
//! - PDF Insecurity, <https://pdf-insecurity.org/>
//!
//! The malicious halves are live malware. Keep them out of the repository
//! and off machines that open PDF files.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use malmal::{Limits, Policy, ScanHints, Scanner, Verdict};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    Clean,
    Malicious,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Malicious => "malicious",
        }
    }
}

struct Outcome {
    class: Class,
    path: PathBuf,
    verdict: Verdict,
    codes: Vec<&'static str>,
    /// Codes of the findings that made the file other than clean.
    deciding: Vec<&'static str>,
    bytes: u64,
}

fn collect(path: &Path, class: Class, files: &mut Vec<(Class, PathBuf)>) {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = match fs::read_dir(path) {
            Ok(entries) => entries
                .filter_map(|entry| Some(entry.ok()?.path()))
                .collect(),
            Err(error) => return eprintln!("{}: {error}", path.display()),
        };
        entries.sort();
        for entry in entries {
            collect(&entry, class, files);
        }
    } else {
        files.push((class, path.to_path_buf()));
    }
}

fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "-".to_string();
    }
    format!("{:.2} %", part as f64 * 100.0 / whole as f64)
}

fn usage(message: &str) -> ExitCode {
    eprintln!("evaluate: {message}");
    eprintln!(
        "usage: evaluate [--clean PATH]... [--malicious PATH]... [--strict] \
         [--max-size BYTES] [--tsv FILE] [--list N]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut files = Vec::new();
    let mut strict = false;
    let mut limits = Limits::default();
    let mut tsv = None;
    let mut list = 20;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        let parsed = match arg.as_str() {
            "--clean" => value().map(|path| collect(Path::new(&path), Class::Clean, &mut files)),
            "--malicious" => {
                value().map(|path| collect(Path::new(&path), Class::Malicious, &mut files))
            }
            "--strict" => {
                strict = true;
                Ok(())
            }
            "--max-size" => value().and_then(|text| {
                limits.max_file_size = text.parse().map_err(|_| "--max-size needs a number")?;
                Ok(())
            }),
            "--tsv" => value().map(|path| tsv = Some(path)),
            "--list" => value().and_then(|text| {
                list = text.parse().map_err(|_| "--list needs a number")?;
                Ok(())
            }),
            other => Err(format!("unknown argument {other:?}")),
        };
        if let Err(message) = parsed {
            return usage(&message);
        }
    }
    if files.is_empty() {
        return usage("no files; give --clean or --malicious");
    }

    let policy = if strict {
        Policy::strict()
    } else {
        Policy::default()
    };
    let scanner = Scanner::builder().policy(policy).limits(limits).build();
    let next = AtomicUsize::new(0);
    let outcomes = Mutex::new(Vec::with_capacity(files.len()));
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while let Some((class, path)) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let data = match fs::read(path) {
                        Ok(data) => data,
                        Err(error) => {
                            eprintln!("{}: {error}", path.display());
                            continue;
                        }
                    };
                    let report = scanner.scan_bytes(&data, ScanHints::default());
                    let mut codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
                    codes.sort_unstable();
                    codes.dedup();
                    // The findings without which the verdict would be better.
                    let worst = report.findings.iter().map(|f| f.severity).max();
                    let mut deciding: Vec<&str> = report
                        .findings
                        .iter()
                        .filter(|f| Some(f.severity) == worst)
                        .map(|f| f.code)
                        .collect();
                    deciding.sort_unstable();
                    deciding.dedup();
                    outcomes.lock().unwrap().push(Outcome {
                        class: *class,
                        path: path.clone(),
                        verdict: report.verdict,
                        codes,
                        deciding,
                        bytes: report.size,
                    });
                }
            });
        }
    });
    let elapsed = started.elapsed();
    let mut outcomes = outcomes.into_inner().unwrap();
    outcomes.sort_by(|a, b| (a.class, &a.path).cmp(&(b.class, &b.path)));

    if let Some(path) = tsv {
        let lines: String = outcomes
            .iter()
            .map(|o| {
                format!(
                    "{}\t{}\t{:?}\t{}\n",
                    o.class.name(),
                    o.path.display(),
                    o.verdict,
                    o.codes.join(",")
                )
            })
            .collect();
        if let Err(error) = fs::File::create(&path).and_then(|mut f| f.write_all(lines.as_bytes()))
        {
            eprintln!("{path}: {error}");
            return ExitCode::from(2);
        }
    }

    let bytes: u64 = outcomes.iter().map(|o| o.bytes).sum();
    println!(
        "{} files, {:.1} MiB, {:.1} s on {workers} threads ({:.0} files/s, {:.0} MiB/s)",
        outcomes.len(),
        bytes as f64 / 1048576.0,
        elapsed.as_secs_f64(),
        outcomes.len() as f64 / elapsed.as_secs_f64(),
        bytes as f64 / 1048576.0 / elapsed.as_secs_f64(),
    );

    for class in [Class::Malicious, Class::Clean] {
        let of_class: Vec<&Outcome> = outcomes.iter().filter(|o| o.class == class).collect();
        if of_class.is_empty() {
            continue;
        }
        let count = |verdict| of_class.iter().filter(|o| o.verdict == verdict).count();
        let (clean, suspicious, malicious) = (
            count(Verdict::Clean),
            count(Verdict::Suspicious),
            count(Verdict::Malicious),
        );
        println!("\n{} files: {}", class.name(), of_class.len());
        println!(
            "  malicious   {malicious:>7}  {}",
            percent(malicious, of_class.len())
        );
        println!(
            "  suspicious  {suspicious:>7}  {}",
            percent(suspicious, of_class.len())
        );
        println!(
            "  clean       {clean:>7}  {}",
            percent(clean, of_class.len())
        );
        let (label, wrong): (&str, Vec<&&Outcome>) = match class {
            Class::Malicious => (
                "refused",
                of_class
                    .iter()
                    .filter(|o| o.verdict == Verdict::Clean)
                    .collect(),
            ),
            Class::Clean => (
                "accepted",
                of_class
                    .iter()
                    .filter(|o| o.verdict != Verdict::Clean)
                    .collect(),
            ),
        };
        println!(
            "  {label}: {}",
            percent(of_class.len() - wrong.len(), of_class.len())
        );

        // What the verdicts of this class rest on.
        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        for outcome in of_class.iter().filter(|o| o.verdict != Verdict::Clean) {
            for code in &outcome.deciding {
                *reasons.entry(code).or_default() += 1;
            }
        }
        let mut reasons: Vec<(&str, usize)> = reasons.into_iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        if !reasons.is_empty() {
            println!("  findings that decided a verdict:");
            for (code, count) in reasons.iter().take(25) {
                println!("    {count:>7}  {code}");
            }
        }
        if !wrong.is_empty() && list > 0 {
            let kind = match class {
                Class::Malicious => "accepted though malicious",
                Class::Clean => "refused though clean",
            };
            println!("  {kind} ({} files; first {list}):", wrong.len());
            for outcome in wrong.iter().take(list) {
                println!(
                    "    {}  {:?}  {}",
                    outcome.path.display(),
                    outcome.verdict,
                    outcome.codes.join(",")
                );
            }
        }
    }
    ExitCode::SUCCESS
}
