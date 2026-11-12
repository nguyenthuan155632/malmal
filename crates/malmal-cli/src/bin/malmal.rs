#![forbid(unsafe_code)]

use std::fs::File;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use malmal::{Report, ScanHints, Verdict};
use malmal_cli::options::{self, Common};
use malmal_cli::sandbox;

const USAGE: &str = "\
Usage: malmal scan [OPTIONS] <FILE>...

Scans each FILE; `-` reads standard input.

Options:
  --json               Print one JSON object per file";

const EXIT_STATUS: &str = "  -h, --help           Print this help
  -V, --version        Print version

Exit status: 0 clean, 1 suspicious, 2 malicious, 3 error";

const EXIT_ERROR: u8 = 3;

struct Args {
    json: bool,
    common: Common,
    files: Vec<String>,
}

fn usage() -> String {
    format!("{USAGE}\n{}\n{EXIT_STATUS}", options::HELP)
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    match args.next().as_deref() {
        Some("scan") => {}
        Some(other) => return Err(format!("unknown command {other:?}")),
        None => return Err("missing command".into()),
    }
    let mut parsed = Args {
        json: false,
        common: Common::default(),
        files: Vec::new(),
    };
    let mut options_done = false;
    while let Some(arg) = args.next() {
        if options_done || !arg.starts_with('-') || arg == "-" {
            parsed.files.push(arg);
        } else if arg == "--" {
            options_done = true;
        } else if arg == "--json" {
            parsed.json = true;
        } else if !parsed.common.parse(&arg, &mut args)? {
            return Err(format!("unknown option {arg:?}"));
        }
    }
    if parsed.files.is_empty() {
        return Err("no files given".into());
    }
    Ok(parsed)
}

fn print_report(path: &str, report: &Report, json: bool) {
    if json {
        println!("{}", serde_json::json!({ "path": path, "report": report }));
        return;
    }
    let verdict = match report.verdict {
        Verdict::Clean => "CLEAN",
        Verdict::Suspicious => "SUSPICIOUS",
        Verdict::Malicious => "MALICIOUS",
    };
    println!("{path}: {verdict} ({})", report.detected_type.as_str());
    for finding in &report.findings {
        let offset = finding
            .offset
            .map(|o| format!(" at offset {o}"))
            .unwrap_or_default();
        println!(
            "  [{:?}] {}: {}{offset}",
            finding.severity, finding.code, finding.message
        );
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    // Help and version are honoured wherever they appear among the options,
    // including after the `scan` command, but not past a `--` terminator.
    let is_flag = |names: &[&str]| {
        raw.iter()
            .take_while(|arg| *arg != "--")
            .any(|arg| names.contains(&arg.as_str()))
    };
    if is_flag(&["-h", "--help"]) {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    if is_flag(&["-V", "--version"]) {
        println!("malmal {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let args = match parse_args(raw.into_iter()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("malmal: {message}\n\n{}", usage());
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let scanner = match args.common.scanner() {
        Ok(scanner) => scanner,
        Err(message) => {
            eprintln!("malmal: {message}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    // From here on, nothing but the files to scan can be opened.
    let readable: Vec<&Path> = args.files.iter().map(Path::new).collect();
    if let Err(message) = sandbox::enter(args.common.sandbox, &readable, options::MEMORY_LIMIT) {
        eprintln!("malmal: {message}");
        return ExitCode::from(EXIT_ERROR);
    }

    let mut exit = 0;
    for path in &args.files {
        let scanned = if path == "-" {
            scanner.scan_reader(io::stdin().lock(), ScanHints::default())
        } else {
            let hints = ScanHints {
                filename: Some(path),
                content_type: None,
            };
            File::open(path).and_then(|file| scanner.scan_reader(file, hints))
        };
        match scanned {
            Ok(report) => {
                print_report(path, &report, args.json);
                exit = exit.max(report.verdict as u8);
            }
            Err(error) => {
                eprintln!("malmal: {path}: {error}");
                exit = EXIT_ERROR;
            }
        }
    }
    ExitCode::from(exit)
}
