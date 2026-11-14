//! Scanning daemon. It listens on any of four endpoints, each with its own
//! protocol; see [`malmal_cli::serve`] and [`malmal_cli::icap`] for what
//! they carry.

#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use malmal_cli::icap;
use malmal_cli::input::{MAP_FROM, Reserve, Spool};
use malmal_cli::options::{self, Common};
use malmal_cli::sandbox;
use malmal_cli::serve::{self, Pace, Service, Slots};

const USAGE: &str = "\
Usage: malmald (--socket <PATH> | --http <ADDR> | --clamd <ADDR> | --icap <ADDR>)...
               [OPTIONS]

An ADDR is host:port, or the path of a Unix socket.

Options:
  --socket <PATH>      Unix socket for the JSON protocol (created with mode 0660)
  --http <ADDR>        HTTP: POST /scan, GET /metrics, GET /healthz
  --clamd <ADDR>       ClamAV daemon protocol (PING, VERSION, INSTREAM)
  --icap <ADDR>        ICAP for proxies (OPTIONS, REQMOD, RESPMOD)
  --workers <N>        Files scanned at once [default: 4]
  --connections <N>    Connections kept open at once [default: 256]
  --file-budget <BYTES>
                       Most that the files of requests held at once may come
                       to, as they arrive and while they are scanned; a file
                       waits for room [default: --workers times --max-size]
  --timeout <SECONDS>  Idle time before a connection is dropped [default: 30]
  --min-rate <BYTES>   Once --timeout has passed, the bytes a second a request
                       has to arrive at, and its answer leave at, or the
                       connection is dropped; 0 for any rate [default: 1024]
  --spool-dir <DIR>    Keep files of 1 MiB and more in unnamed files in DIR
                       while they are scanned, and not in memory; DIR must
                       be on a disk [default: every file in memory]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Json,
    Http,
    Clamd,
    Icap,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Http => "http",
            Self::Clamd => "clamd",
            Self::Icap => "icap",
        }
    }
}

struct Args {
    endpoints: Vec<(Protocol, String)>,
    workers: usize,
    connections: usize,
    file_budget: u64,
    timeout: Duration,
    min_rate: u64,
    spool_dir: Option<PathBuf>,
    common: Common,
}

fn usage() -> String {
    format!(
        "{USAGE}\n{}\n  -h, --help           Print this help",
        options::HELP
    )
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut endpoints = Vec::new();
    let mut workers = 4;
    let mut connections = 256;
    let mut timeout = 30;
    let mut file_budget = None;
    let mut min_rate = 1024;
    let mut spool_dir = None;
    let mut common = Common::default();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--socket" => endpoints.push((Protocol::Json, value("--socket")?)),
            "--http" => endpoints.push((Protocol::Http, value("--http")?)),
            "--clamd" => endpoints.push((Protocol::Clamd, value("--clamd")?)),
            "--icap" => endpoints.push((Protocol::Icap, value("--icap")?)),
            "--workers" => {
                workers = value("--workers")?
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or("--workers needs a positive number")?
            }
            "--connections" => {
                connections = value("--connections")?
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or("--connections needs a positive number")?
            }
            "--timeout" => {
                timeout = value("--timeout")?
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or("--timeout needs a positive number of seconds")?
            }
            "--file-budget" => {
                file_budget = Some(
                    value("--file-budget")?
                        .parse()
                        .ok()
                        .filter(|&n: &u64| n > 0)
                        .ok_or("--file-budget needs a positive number of bytes")?,
                )
            }
            "--min-rate" => {
                min_rate = value("--min-rate")?
                    .parse()
                    .map_err(|_| "--min-rate needs a number of bytes")?
            }
            "--spool-dir" => spool_dir = Some(PathBuf::from(value("--spool-dir")?)),
            other => {
                if !common.parse(other, &mut args)? {
                    return Err(format!("unknown option {other:?}"));
                }
            }
        }
    }
    if endpoints.is_empty() {
        return Err("one of --socket, --http, --clamd or --icap is required".into());
    }
    let max_size = common.limits.max_file_size;
    let file_budget = file_budget.unwrap_or(max_size.saturating_mul(workers as u64));
    // Otherwise a file the size limit allows could never be held.
    if file_budget < max_size {
        return Err("--file-budget has to be at least --max-size".into());
    }
    Ok(Args {
        endpoints,
        workers,
        connections,
        file_budget,
        timeout: Duration::from_secs(timeout),
        min_rate,
        spool_dir,
        common,
    })
}

enum Listener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Listener {
    /// `--socket` always names a path; the other endpoints do when the
    /// address has a slash in it.
    fn bind(protocol: Protocol, address: &str) -> io::Result<(Self, String)> {
        if protocol != Protocol::Json && !address.contains('/') {
            let listener = TcpListener::bind(address)?;
            // The port may have been chosen by the system.
            let bound = listener.local_addr()?.to_string();
            return Ok((Self::Tcp(listener), bound));
        }
        let path = Path::new(address);
        // A socket left behind by a previous run would make bind fail.
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket()) {
            fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        Ok((Self::Unix(listener), address.to_string()))
    }

    fn accept(&self) -> io::Result<Stream> {
        Ok(match self {
            Self::Unix(listener) => Stream::Unix(listener.accept()?.0),
            Self::Tcp(listener) => Stream::Tcp(listener.accept()?.0),
        })
    }
}

impl Stream {
    fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Unix(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))
            }
            Self::Tcp(stream) => {
                // Replies are small and written whole; do not wait to batch them.
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))
            }
        }
    }
}

impl Read for &Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(stream) => (&*stream).read(buffer),
            Stream::Tcp(stream) => (&*stream).read(buffer),
        }
    }
}

impl Write for &Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(stream) => (&*stream).write(buffer),
            Stream::Tcp(stream) => (&*stream).write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Unix(stream) => (&*stream).flush(),
            Stream::Tcp(stream) => (&*stream).flush(),
        }
    }
}

/// How long a request may take to arrive and its answer to leave: `grace`,
/// and past that as long as it takes at `min_rate` bytes a second. Only the
/// time spent waiting on the client counts, not the time spent scanning, so
/// a client that sends a byte now and then cannot keep its connection, and
/// the file it is sending, for as long as it likes.
struct Clock {
    grace: Duration,
    min_rate: u64,
    running: Cell<bool>,
    waited: Cell<Duration>,
    moved: Cell<u64>,
}

impl Clock {
    fn time(&self, io: impl FnOnce() -> io::Result<usize>) -> io::Result<usize> {
        if !self.running.get() {
            return io();
        }
        if self.min_rate > 0 {
            let earned = Duration::from_secs_f64(self.moved.get() as f64 / self.min_rate as f64);
            if self.waited.get() > self.grace.saturating_add(earned) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the client is too slow",
                ));
            }
        }
        let started = Instant::now();
        let outcome = io();
        self.waited.set(self.waited.get() + started.elapsed());
        if let Ok(count) = &outcome {
            self.moved.set(self.moved.get() + *count as u64);
        }
        outcome
    }
}

/// A connection, read and written on the clock of its request.
#[derive(Clone, Copy)]
struct Paced<'a> {
    stream: &'a Stream,
    clock: &'a Clock,
}

impl Read for Paced<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream;
        self.clock.time(|| stream.read(buffer))
    }
}

impl Write for Paced<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut stream = self.stream;
        self.clock.time(|| stream.write(buffer))
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

impl Pace for Paced<'_> {
    fn idle(&mut self) {
        self.clock.running.set(false);
    }

    fn start(&mut self) {
        self.clock.running.set(true);
        self.clock.waited.set(Duration::ZERO);
        self.clock.moved.set(0);
    }
}

/// Serve one connection to its end.
fn serve(stream: &Stream, protocol: Protocol, service: &Service, timeout: Duration, min_rate: u64) {
    if stream.set_timeout(timeout).is_err() {
        return;
    }
    let clock = Clock {
        grace: timeout,
        min_rate,
        running: Cell::new(false),
        waited: Cell::new(Duration::ZERO),
        moved: Cell::new(0),
    };
    let paced = Paced {
        stream,
        clock: &clock,
    };
    let mut reader = BufReader::new(paced);
    // Errors here are the peer's: a timeout, a reset, a short body.
    let _ = match protocol {
        Protocol::Json => serve::json(&mut reader, paced, service),
        Protocol::Http => serve::http(&mut reader, paced, service),
        Protocol::Clamd => serve::clamd(&mut reader, paced, service),
        Protocol::Icap => icap::icap(&mut reader, paced, service),
    };
}

/// Give every connection to an endpoint a thread of its own. A thread that
/// waits for a client's next request costs little; the work is bounded by
/// the service, and the number of connections by `connections`, past which
/// they wait to be accepted.
fn accept(
    listener: Listener,
    protocol: Protocol,
    service: Arc<Service>,
    connections: Arc<Slots>,
    timeout: Duration,
    min_rate: u64,
) {
    loop {
        let place = connections.take();
        let Ok(stream) = listener.accept() else {
            // Out of descriptors, most likely; they come back as connections end.
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let service = Arc::clone(&service);
        // If no thread can be had, the connection is dropped with the closure.
        let _ = thread::Builder::new().spawn(move || {
            let _place = place;
            serve(&stream, protocol, &service, timeout, min_rate);
        });
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
    let mut listeners = Vec::new();
    for (protocol, address) in &args.endpoints {
        match Listener::bind(*protocol, address) {
            Ok((listener, bound)) => listeners.push((*protocol, listener, bound)),
            Err(error) => {
                eprintln!("malmald: {address}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    let scanner = match args.common.scanner() {
        Ok(scanner) => scanner,
        Err(message) => {
            eprintln!("malmald: {message}");
            return ExitCode::FAILURE;
        }
    };

    // As many files as there can be bodies in them at once, opened here and
    // used over and over: the sandbox has no directory to allow.
    let spooled = (args.file_budget / MAP_FROM).clamp(1, args.connections as u64);
    let spool = match &args.spool_dir {
        Some(dir) => match Spool::open(dir, spooled as usize) {
            Ok(spool) => Some(spool),
            Err(error) => {
                eprintln!("malmald: {}: {error}", dir.display());
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // The sockets are open; the file system is not needed again, and the
    // sandbox forbids opening any more of them. Every request worked on
    // has its file mapped or held whole.
    let memory = options::memory_limit(scanner.limits(), args.workers as u64, args.file_budget);
    match sandbox::enter(args.common.sandbox, &[], memory) {
        Ok(status) => {
            let endpoints: Vec<String> = listeners
                .iter()
                .map(|(protocol, _, bound)| format!("{bound} ({})", protocol.name()))
                .collect();
            eprintln!(
                "malmald: listening on {} (sandbox: file system {}, system calls {})",
                endpoints.join(", "),
                if status.filesystem { "on" } else { "off" },
                if status.syscalls { "on" } else { "off" },
            );
        }
        Err(message) => {
            eprintln!("malmald: {message}");
            return ExitCode::FAILURE;
        }
    }

    let watchdog = args.common.watchdog("malmald");
    let service = Service::new(scanner).watched_by(watchdog);
    let service = match spool {
        Some(spool) => service.spooling_to(spool),
        None => service,
    };
    let reserve = Reserve::new(args.file_budget, args.timeout);
    let service = Arc::new(service.at_once(args.workers).holding(reserve));
    let connections = Slots::new(args.connections);
    let mut handles = Vec::new();
    for (protocol, listener, _) in listeners {
        let (service, connections) = (Arc::clone(&service), Arc::clone(&connections));
        let (timeout, min_rate) = (args.timeout, args.min_rate);
        handles.push(thread::spawn(move || {
            accept(listener, protocol, service, connections, timeout, min_rate)
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    ExitCode::FAILURE
}
