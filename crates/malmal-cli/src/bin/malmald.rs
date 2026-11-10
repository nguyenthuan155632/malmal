//! Scanning daemon on a Unix socket.
//!
//! A request is one line of JSON, `{"size": N, "filename": ..., "content_type": ...}`
//! (the last two optional), followed by exactly N bytes of file content. The
//! reply is one line of JSON: `{"ok": true, "report": {...}}` or
//! `{"ok": false, "error": "..."}`. A connection may carry any number of
//! requests. Anything but `"ok": true` means the file was not scanned.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use malmal::{Limits, ScanHints, Scanner};
use malmal_cli::options::{self, Common};
use malmal_cli::sandbox;
use serde::Deserialize;

const USAGE: &str = "\
Usage: malmald --socket <PATH> [OPTIONS]

Options:
  --socket <PATH>      Unix socket to listen on (created with mode 0660)
  --workers <N>        Connections served at once [default: 4]
  --timeout <SECONDS>  Idle time before a connection is dropped [default: 30]";

const MAX_HEADER_LEN: u64 = 16 << 10;

#[derive(Deserialize)]
struct Request {
    size: u64,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

struct Args {
    socket: PathBuf,
    workers: usize,
    timeout: Duration,
    common: Common,
}

fn usage() -> String {
    format!(
        "{USAGE}\n{}\n  -h, --help           Print this help",
        options::HELP
    )
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut socket = None;
    let mut workers = 4;
    let mut timeout = 30;
    let mut common = Common::default();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--socket" => socket = Some(PathBuf::from(value("--socket")?)),
            "--workers" => {
                workers = value("--workers")?
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or("--workers needs a positive number")?
            }
            "--timeout" => {
                timeout = value("--timeout")?
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or("--timeout needs a positive number of seconds")?
            }
            other => {
                if !common.parse(other, &mut args)? {
                    return Err(format!("unknown option {other:?}"));
                }
            }
        }
    }
    Ok(Args {
        socket: socket.ok_or("--socket is required")?,
        workers,
        timeout: Duration::from_secs(timeout),
        common,
    })
}

fn listen(path: &Path) -> io::Result<UnixListener> {
    // A socket left behind by a previous run would make bind fail.
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket()) {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn reply(mut stream: &UnixStream, value: serde_json::Value) -> io::Result<()> {
    let mut line = value.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes())
}

fn reply_error(stream: &UnixStream, message: &str) -> io::Result<()> {
    reply(stream, serde_json::json!({ "ok": false, "error": message }))
}

/// Serve requests on one connection until the peer closes it or misbehaves.
fn serve(stream: &UnixStream, scanner: &Scanner, max_size: u64) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    loop {
        let mut header = String::new();
        if reader
            .by_ref()
            .take(MAX_HEADER_LEN)
            .read_line(&mut header)?
            == 0
        {
            return Ok(());
        }
        let request: Request = match serde_json::from_str(&header) {
            Ok(request) => request,
            Err(error) => return reply_error(stream, &format!("invalid request: {error}")),
        };
        // The body cannot be skipped safely, so the connection ends here.
        if request.size > max_size {
            return reply_error(stream, "file exceeds the size limit");
        }
        let mut body = vec![0; request.size as usize];
        reader.read_exact(&mut body)?;

        let hints = ScanHints {
            filename: request.filename.as_deref(),
            content_type: request.content_type.as_deref(),
        };
        match catch_unwind(AssertUnwindSafe(|| scanner.scan_bytes(&body, hints))) {
            Ok(report) => reply(stream, serde_json::json!({ "ok": true, "report": report }))?,
            Err(_) => reply_error(stream, "internal error while scanning")?,
        }
    }
}

fn worker(listener: UnixListener, scanner: Scanner, timeout: Duration, max_size: u64) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let configured = stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)));
        if configured.is_ok() {
            // Errors here are the peer's: a timeout, a reset, a short body.
            let _ = serve(&stream, &scanner, max_size);
        }
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let args = match parse_args(raw.into_iter()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("malmald: {message}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };
    let listener = match listen(&args.socket) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("malmald: {}: {error}", args.socket.display());
            return ExitCode::FAILURE;
        }
    };
    let scanner = match args.common.scanner() {
        Ok(scanner) => scanner,
        Err(message) => {
            eprintln!("malmald: {message}");
            return ExitCode::FAILURE;
        }
    };

    // The socket is open; the file system is not needed again.
    match sandbox::enter(args.common.sandbox, &[], options::MEMORY_LIMIT) {
        Ok(status) => eprintln!(
            "malmald: listening on {} (sandbox: file system {}, system calls {})",
            args.socket.display(),
            if status.filesystem { "on" } else { "off" },
            if status.syscalls { "on" } else { "off" },
        ),
        Err(message) => {
            eprintln!("malmald: {message}");
            return ExitCode::FAILURE;
        }
    }

    let max_size = Limits::default().max_file_size;
    let mut handles = Vec::new();
    for _ in 0..args.workers {
        let Ok(listener) = listener.try_clone() else {
            eprintln!("malmald: cannot share the listening socket");
            return ExitCode::FAILURE;
        };
        let scanner = scanner.clone();
        handles.push(thread::spawn(move || {
            worker(listener, scanner, args.timeout, max_size)
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    ExitCode::FAILURE
}
