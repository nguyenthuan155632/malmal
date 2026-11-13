#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
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
sanitize  Scans INPUT and, if it is clean and of a type that can be, writes
          it anew to OUTPUT: an image from its pixels, an SVG from what
          draws in it, a PDF as pictures of its pages. `-` is standard
          input or output. OUTPUT is replaced whole when the exit status
          is 0, and left as it was otherwise.

Options:
  --json               scan: print one JSON object per file
  --jpeg-quality <N>   sanitize: quality of a rebuilt JPEG, 1-100 [default: 90]
  --pdf-dpi <N>        sanitize: dots per inch of a rebuilt PDF's pages,
                       36-600 [default: 150]";

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
    pdf_dpi: u16,
    common: Common,
    files: Vec<String>,
    /// Where among the arguments the last of `files` is.
    last_file_at: usize,
}

/// Arguments, counted as they are taken.
struct Counted<I> {
    arguments: I,
    taken: usize,
}

impl<I: Iterator<Item = String>> Iterator for Counted<I> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let argument = self.arguments.next()?;
        self.taken += 1;
        Some(argument)
    }
}

fn usage() -> String {
    format!("{USAGE}\n{}\n{EXIT_STATUS}", options::HELP)
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Counted {
        arguments: args,
        taken: 0,
    };
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
        pdf_dpi: 150,
        common: Common::default(),
        files: Vec::new(),
        last_file_at: 0,
    };
    let mut options_done = false;
    while let Some(arg) = args.next() {
        if options_done || !arg.starts_with('-') || arg == "-" {
            parsed.files.push(arg);
            parsed.last_file_at = args.taken - 1;
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
        } else if arg == "--pdf-dpi" && sanitize {
            parsed.pdf_dpi = args
                .next()
                .and_then(|value| value.parse().ok())
                .filter(|dpi| (36..=600).contains(dpi))
                .ok_or("--pdf-dpi needs a number from 36 to 600")?;
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

/// The file at `path`, or standard input for `-`, up to one byte past the
/// size limit, which is how the scanner knows the file is too large.
fn read(path: &str, scanner: &malmal::Scanner) -> io::Result<Vec<u8>> {
    let limit = scanner.limits().max_file_size.saturating_add(1);
    let mut data = Vec::new();
    if path == "-" {
        io::stdin().lock().take(limit).read_to_end(&mut data)?;
    } else {
        File::open(path)?.take(limit).read_to_end(&mut data)?;
    }
    Ok(data)
}

/// `sanitize` into a file. The sandbox lets a process neither rename nor
/// remove a file, so the image is rebuilt by a second, sandboxed process
/// that writes it to its standard output. This one only moves bytes: into
/// a temporary file beside `output`, which takes the place of `output` once
/// the image is whole, so that `output` is never a part of one.
#[cfg(feature = "cdr")]
fn sanitize_into_file(arguments: &[String], output_at: usize) -> ExitCode {
    use std::fs;
    use std::process::{Command, Stdio};

    let output = Path::new(&arguments[output_at]);
    let fail = |subject: &Path, error: io::Error| {
        eprintln!("malmal: {}: {error}", subject.display());
        ExitCode::from(EXIT_ERROR)
    };
    let mut command = match std::env::current_exe() {
        Ok(program) => Command::new(program),
        Err(error) => return fail(Path::new("malmal"), error),
    };
    command.args(&arguments[..output_at]).arg("-");
    command.args(&arguments[output_at + 1..]);
    let code = |status: std::process::ExitStatus| {
        // Ended by a signal, there is no status to pass on.
        let code = status.code().and_then(|code| u8::try_from(code).ok());
        ExitCode::from(code.unwrap_or(EXIT_ERROR))
    };

    // A device or a pipe is written to, not replaced.
    let existing = fs::metadata(output).ok();
    if existing.as_ref().is_some_and(|found| !found.is_file()) {
        let opened = File::options().write(true).open(output);
        return match opened.and_then(|file| command.stdout(file).status()) {
            Ok(status) => code(status),
            Err(error) => fail(output, error),
        };
    }

    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = output.with_file_name(name);
    let mut file = match File::options()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(error) => return fail(output, error),
    };
    let discard = |result: ExitCode| {
        let _ = fs::remove_file(&temporary);
        result
    };
    let mut child = match command.stdout(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(error) => return discard(fail(Path::new("malmal"), error)),
    };
    let mut image = child.stdout.take().expect("the output is a pipe");
    let copied = io::copy(&mut image, &mut file)
        .and_then(|_| match &existing {
            // The new file is to be read by whoever could read the old one.
            Some(replaced) => file.set_permissions(replaced.permissions()),
            None => Ok(()),
        })
        .and_then(|()| file.sync_all());
    // Closed, so that a child still writing ends instead of waiting.
    drop(image);
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => return discard(fail(Path::new("malmal"), error)),
    };
    if !status.success() {
        return discard(code(status));
    }
    match copied.and_then(|()| fs::rename(&temporary, output)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => discard(fail(output, error)),
    }
}

/// Scan `input` and write the rebuilt image to standard output. Everything
/// a person reads goes to standard error, which is never the image.
#[cfg(feature = "cdr")]
fn sanitize(args: &Args, scanner: &malmal::Scanner) -> ExitCode {
    use std::io::Write;

    use malmal::cdr::{Error, Options};

    let input = &args.files[0];
    let fail = |message: String| {
        eprintln!("malmal: {message}");
        ExitCode::from(EXIT_ERROR)
    };
    let watchdog = args.common.watchdog("malmal");
    let readable: Vec<&Path> = vec![Path::new(input)];
    if let Err(message) = sandbox::enter(args.common.sandbox, &readable, options::MEMORY_LIMIT) {
        return fail(message);
    }

    let data = match read(input, scanner) {
        Ok(data) => data,
        Err(error) => return fail(format!("{input}: {error}")),
    };
    let hints = ScanHints {
        filename: (input != "-").then_some(input.as_str()),
        content_type: None,
    };
    let mut options = Options::default();
    options.jpeg_quality = args.jpeg_quality;
    options.pdf_dpi = args.pdf_dpi;
    let running = watchdog.watch();
    let sanitized = match scanner.sanitize(&data, hints, &options) {
        Ok(sanitized) => sanitized,
        Err(Error::Rejected(report)) => {
            eprint!("{}", describe(input, &report));
            return ExitCode::from(report.verdict as u8);
        }
        Err(Error::Unclean(report)) => {
            eprint!("{}", describe(&format!("{input}, rebuilt"), &report));
            return ExitCode::from(report.verdict as u8);
        }
        Err(error) => return fail(format!("{input}: {error}")),
    };
    drop(running);
    let image = &sanitized.image;
    if let Err(error) = io::stdout().lock().write_all(&image.data) {
        return fail(format!("standard output: {error}"));
    }
    // A document has pages, if anything; a picture has a size and frames.
    let plural = if image.frames == 1 { "" } else { "s" };
    let shape = match image.file_type {
        malmal::FileType::Pdf => format!("{} page{plural}, ", image.frames),
        _ if image.width == 0 => String::new(),
        _ => format!(
            "{}x{}, {} frame{plural}, ",
            image.width, image.height, image.frames
        ),
    };
    eprintln!(
        "{input}: rebuilt as {} ({shape}{} bytes)",
        image.file_type.as_str(),
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
    let args = match parse_args(raw.iter().cloned()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("malmal: {message}\n\n{}", usage());
            return ExitCode::from(EXIT_ERROR);
        }
    };

    #[cfg(feature = "cdr")]
    if args.sanitize && args.files[1] != "-" {
        return sanitize_into_file(&raw, args.last_file_at);
    }
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
    let watchdog = args.common.watchdog("malmal");
    // From here on, nothing but the files to scan can be opened.
    let readable: Vec<&Path> = args.files.iter().map(Path::new).collect();
    if let Err(message) = sandbox::enter(args.common.sandbox, &readable, options::MEMORY_LIMIT) {
        eprintln!("malmal: {message}");
        return ExitCode::from(EXIT_ERROR);
    }

    let mut exit = 0;
    for path in &args.files {
        let hints = ScanHints {
            filename: (path != "-").then_some(path.as_str()),
            content_type: None,
        };
        // Waiting for the file is not scanning it.
        let scanned = read(path, &scanner).map(|data| {
            let _running = watchdog.watch();
            scanner.scan_bytes(&data, hints)
        });
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
