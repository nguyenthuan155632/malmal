#![forbid(unsafe_code)]

use std::fs::File;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use malmal::{Report, ScanHints, Verdict};
use malmal_cli::options::{self, Common};
use malmal_cli::sandbox;

#[cfg(not(feature = "cdr"))]
const USAGE: &str = "\
Usage: malmal scan [OPTIONS] <FILE>...

Scans each FILE; `-` reads standard input.

Options:
  --json               Print one JSON object per file";

#[cfg(feature = "cdr")]
const USAGE: &str = "\
Usage: malmal scan [OPTIONS] <FILE>...
       malmal sanitize [OPTIONS] <INPUT> <OUTPUT>

scan      Scans each FILE; `-` reads standard input.
sanitize  Scans INPUT and, if it is a clean raster image, writes it anew
          from its pixels to OUTPUT; `-` is standard input or output.
          Unless the exit status is 0, OUTPUT is left as it was, or
          empty if it did not exist.

Options:
  --json               scan: print one JSON object per file
  --jpeg-quality <N>   sanitize: quality of a rebuilt JPEG, 1-100 [default: 90]";

const EXIT_STATUS: &str = "  -h, --help           Print this help
  -V, --version        Print version

Exit status: 0 clean (sanitize: rebuilt), 1 suspicious, 2 malicious, 3 error";

const EXIT_ERROR: u8 = 3;

#[cfg_attr(not(feature = "cdr"), allow(dead_code))]
struct Args {
    /// `sanitize` rather than `scan`.
    sanitize: bool,
    json: bool,
    jpeg_quality: u8,
    common: Common,
    files: Vec<String>,
}

fn usage() -> String {
    format!("{USAGE}\n{}\n{EXIT_STATUS}", options::HELP)
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let sanitize = match args.next().as_deref() {
        Some("scan") => false,
        Some("sanitize") if cfg!(feature = "cdr") => true,
        Some(other) => return Err(format!("unknown command {other:?}")),
        None => return Err("missing command".into()),
    };
    let mut parsed = Args {
        sanitize,
        json: false,
        jpeg_quality: 90,
        common: Common::default(),
        files: Vec::new(),
    };
    let mut options_done = false;
    while let Some(arg) = args.next() {
        if options_done || !arg.starts_with('-') || arg == "-" {
            parsed.files.push(arg);
        } else if arg == "--" {
            options_done = true;
        } else if arg == "--json" && !sanitize {
            parsed.json = true;
        } else if arg == "--jpeg-quality" && sanitize {
            parsed.jpeg_quality = args
                .next()
                .and_then(|value| value.parse().ok())
                .filter(|quality| (1..=100).contains(quality))
                .ok_or("--jpeg-quality needs a number from 1 to 100")?;
        } else if !parsed.common.parse(&arg, &mut args)? {
            return Err(format!("unknown option {arg:?}"));
        }
    }
    if parsed.files.is_empty() {
        return Err("no files given".into());
    }
    if sanitize && parsed.files.len() != 2 {
        return Err("sanitize takes one input and one output".into());
    }
    Ok(parsed)
}

fn print_report(path: &str, report: &Report, json: bool) {
    if json {
        println!("{}", serde_json::json!({ "path": path, "report": report }));
        return;
    }
    print!("{}", describe(path, report));
}

fn describe(path: &str, report: &Report) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let verdict = match report.verdict {
        Verdict::Clean => "CLEAN",
        Verdict::Suspicious => "SUSPICIOUS",
        Verdict::Malicious => "MALICIOUS",
    };
    let _ = writeln!(out, "{path}: {verdict} ({})", report.detected_type.as_str());
    for finding in &report.findings {
        let offset = finding
            .offset
            .map(|o| format!(" at offset {o}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  [{:?}] {}: {}{offset}",
            finding.severity, finding.code, finding.message
        );
    }
    out
}

/// Scan `input` and write the rebuilt image to `output`. Everything a person
/// reads goes to standard error, which is never the image.
#[cfg(feature = "cdr")]
fn sanitize(args: &Args, scanner: &malmal::Scanner) -> ExitCode {
    use std::io::{Read, Write};

    use malmal::cdr::{Error, Options};

    let (input, output) = (&args.files[0], &args.files[1]);
    let fail = |message: String| {
        eprintln!("malmal: {message}");
        ExitCode::from(EXIT_ERROR)
    };
    // Opened before the sandbox closes the file system, and not truncated:
    // the file keeps its contents until there is something to replace them.
    let target = if output == "-" {
        None
    } else {
        let opened = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(output);
        match opened {
            Ok(file) => Some(file),
            Err(error) => return fail(format!("{output}: {error}")),
        }
    };
    let readable: Vec<&Path> = vec![Path::new(input)];
    if let Err(message) = sandbox::enter(args.common.sandbox, &readable, options::MEMORY_LIMIT) {
        return fail(message);
    }

    let limit = scanner.limits().max_file_size.saturating_add(1);
    let mut data = Vec::new();
    let read = if input == "-" {
        io::stdin().lock().take(limit).read_to_end(&mut data)
    } else {
        File::open(input).and_then(|file| file.take(limit).read_to_end(&mut data))
    };
    if let Err(error) = read {
        return fail(format!("{input}: {error}"));
    }
    let hints = ScanHints {
        filename: (input != "-").then_some(input.as_str()),
        content_type: None,
    };
    let mut options = Options::default();
    options.jpeg_quality = args.jpeg_quality;
    let sanitized = match scanner.sanitize(&data, hints, &options) {
        Ok(sanitized) => sanitized,
        Err(Error::Rejected(report)) => {
            eprint!("{}", describe(input, &report));
            return ExitCode::from(report.verdict as u8);
        }
        Err(error) => return fail(format!("{input}: {error}")),
    };
    let image = &sanitized.image;
    let written = match target {
        Some(mut file) => file
            .set_len(0)
            .and_then(|()| file.write_all(&image.data))
            .and_then(|()| file.sync_all()),
        None => io::stdout().lock().write_all(&image.data),
    };
    if let Err(error) = written {
        return fail(format!("{output}: {error}"));
    }
    eprintln!(
        "{input}: rebuilt as {} ({}x{}, {} frame{}, {} bytes)",
        image.file_type.as_str(),
        image.width,
        image.height,
        image.frames,
        if image.frames == 1 { "" } else { "s" },
        image.data.len()
    );
    ExitCode::SUCCESS
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
    #[cfg(feature = "cdr")]
    if args.sanitize {
        return sanitize(&args, &scanner);
    }
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
