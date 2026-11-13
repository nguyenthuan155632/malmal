use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MALMAL: &str = env!("CARGO_BIN_EXE_malmal");
const MALMALD: &str = env!("CARGO_BIN_EXE_malmald");

const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0";

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A structurally valid 1x1 PNG.
fn valid_png() -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunks: [(&[u8; 4], &[u8]); 3] = [
        (b"IHDR", b"\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0"),
        (b"IDAT", b"\x78\x9c\x63\x00\x00\x00\x01\x00\x01"),
        (b"IEND", b""),
    ];
    for (kind, body) in chunks {
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        let start = data.len();
        data.extend_from_slice(kind);
        data.extend_from_slice(body);
        let crc = crc32(&data[start..]);
        data.extend_from_slice(&crc.to_be_bytes());
    }
    data
}

/// A 1x1 PNG a decoder accepts, carrying a comment.
#[cfg(feature = "cdr")]
fn commented_png() -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunks: [(&[u8; 4], &[u8]); 4] = [
        (b"IHDR", b"\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0"),
        (b"tEXt", b"Comment\0taken on holiday"),
        // One stored block: a filter byte and a transparent pixel.
        (b"IDAT", b"\x78\x01\x01\x05\0\xFA\xFF\0\0\0\0\0\0\x05\0\x01"),
        (b"IEND", b""),
    ];
    for (kind, body) in chunks {
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        let start = data.len();
        data.extend_from_slice(kind);
        data.extend_from_slice(body);
        let crc = crc32(&data[start..]);
        data.extend_from_slice(&crc.to_be_bytes());
    }
    data
}

/// A fresh directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("malmal-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether this kernel and environment let a process sandbox itself.
fn sandbox_available(dir: &Path) -> bool {
    let probe = dir.join("probe.png");
    fs::write(&probe, valid_png()).unwrap();
    Command::new(MALMAL)
        .args(["scan", "--require-sandbox"])
        .arg(&probe)
        .output()
        .unwrap()
        .status
        .code()
        == Some(0)
}

#[test]
fn types_option_replaces_the_accepted_types() {
    let dir = scratch("types");
    let (png, eps) = (dir.join("ok.png"), dir.join("art.eps"));
    fs::write(&png, valid_png()).unwrap();
    fs::write(
        &eps,
        "%!PS-Adobe-3.0 EPSF-3.0\n0 0 moveto 1 1 lineto stroke\n",
    )
    .unwrap();

    let scan = |types: &str, file: &Path| {
        let output = Command::new(MALMAL)
            .args(["scan", "--json", "--types", types])
            .arg(file)
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8(output.stdout).unwrap(),
        )
    };
    assert_eq!(scan("png,postscript", &eps).0, Some(0));
    let (code, report) = scan("png, pdf", &eps);
    assert_eq!(code, Some(1));
    assert!(report.contains("type.not_allowed"), "{report}");
    assert_eq!(scan("png,pdf", &png).0, Some(0));
    assert_eq!(scan("png,docx", &png).0, Some(3));
}

#[test]
fn help_works_after_the_command_and_stays_aligned() {
    for args in [
        &["--help"][..],
        &["scan", "--help"][..],
        &["scan", "-h"][..],
    ] {
        let output = Command::new(MALMAL).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        // Every option line is indented by the same two spaces.
        for line in [
            "  --json ",
            "  --policy ",
            "  --require-sandbox ",
            "  -h, --help ",
        ] {
            assert!(
                text.contains(line),
                "{line:?} missing or misaligned in:\n{text}"
            );
        }
    }
}

#[test]
fn scans_files_and_reports_the_worst_verdict() {
    let dir = scratch("scan");
    let (png, elf) = (dir.join("ok.png"), dir.join("photo.jpg"));
    fs::write(&png, valid_png()).unwrap();
    fs::write(&elf, ELF).unwrap();

    let output = Command::new(MALMAL).arg("scan").arg(&png).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("CLEAN (png)"));

    let output = Command::new(MALMAL)
        .args(["scan", "--json"])
        .args([&png, &elf])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["report"]["verdict"], "clean");
    assert_eq!(lines[1]["report"]["verdict"], "malicious");
    assert_eq!(lines[1]["report"]["detected_type"], "elf");

    let output = Command::new(MALMAL)
        .arg("scan")
        .arg(dir.join("missing.png"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reads_standard_input() {
    let mut child = Command::new(MALMAL)
        .args(["scan", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(ELF).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn sandbox_confines_the_scanner_to_its_inputs() {
    let dir = scratch("sandbox");
    if !sandbox_available(&dir) {
        eprintln!("skipped: sandbox not available here");
        return;
    }
    // The blocklist is read before the sandbox closes; files are read after.
    let (png, list) = (dir.join("ok.png"), dir.join("block.txt"));
    fs::write(&png, valid_png()).unwrap();
    fs::write(&list, "# empty\n").unwrap();
    let output = Command::new(MALMAL)
        .args(["scan", "--require-sandbox", "--hashlist"])
        .arg(&list)
        .arg(&png)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    fs::remove_dir_all(dir).unwrap();
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(stream: &mut UnixStream, header: &str, body: &[u8]) -> serde_json::Value {
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.write_all(body).unwrap();
    let mut line = String::new();
    BufReader::new(&*stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn daemon_scans_over_a_unix_socket() {
    let dir = scratch("daemon");
    let socket = dir.join("malmal.sock");
    let _daemon = Daemon(
        Command::new(MALMALD)
            .arg("--socket")
            .arg(&socket)
            .args(["--workers", "2", "--timeout", "5"])
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    let mut stream = loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => break stream,
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => panic!("daemon did not start: {error}"),
        }
    };

    // Several requests on one connection.
    let image = valid_png();
    let header = format!(
        r#"{{"size": {}, "filename": "ok.png", "content_type": "image/png"}}"#,
        image.len()
    );
    let reply = request(&mut stream, &header, &image);
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["report"]["verdict"], "clean", "{reply}");

    let header = format!(r#"{{"size": {}, "filename": "photo.jpg"}}"#, ELF.len());
    let reply = request(&mut stream, &header, ELF);
    assert_eq!(reply["report"]["verdict"], "malicious");

    let reply = request(&mut stream, r#"{"size": 0}"#, b"");
    assert_eq!(reply["report"]["verdict"], "suspicious");

    // A second client is served while the first is still connected.
    let mut second = UnixStream::connect(&socket).unwrap();
    let reply = request(&mut second, "not json", b"");
    assert_eq!(reply["ok"], false);

    let mut third = UnixStream::connect(&socket).unwrap();
    let reply = request(&mut third, r#"{"size": 99999999999}"#, b"");
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"], "file exceeds the size limit");
    drop(stream);
    fs::remove_dir_all(dir).unwrap();
}

/// Start the daemon on a system-chosen TCP port and return that address.
fn daemon_on_tcp(option: &str) -> (Daemon, String) {
    let mut child = Command::new(MALMALD)
        .args([option, "127.0.0.1:0", "--timeout", "5"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut banner = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut banner)
        .unwrap();
    let address = banner
        .strip_prefix("malmald: listening on ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("unexpected banner {banner:?}"))
        .to_string();
    (Daemon(child), address)
}

#[test]
fn daemon_scans_over_http() {
    use std::io::Read;
    use std::net::TcpStream;

    let (_daemon, address) = daemon_on_tcp("--http");
    let exchange = |request: Vec<u8>| {
        let mut stream = TcpStream::connect(&address).unwrap();
        stream.write_all(&request).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    };
    let post = |name: &str, body: &[u8]| {
        let mut request = format!(
            "POST /scan?filename={name} HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        exchange(request)
    };

    let reply = post("ok.png", &valid_png());
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert!(reply.contains(r#""verdict":"clean""#), "{reply}");
    let reply = post("photo.jpg", ELF);
    assert!(reply.contains(r#""verdict":"malicious""#), "{reply}");

    let metrics = exchange(b"GET /metrics HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec());
    assert!(
        metrics.contains("malmal_scans_total{verdict=\"malicious\"} 1"),
        "{metrics}"
    );
}

#[cfg(feature = "cdr")]
#[test]
fn sanitize_rebuilds_clean_images_only() {
    let dir = scratch("sanitize");
    let (input, output) = (dir.join("in.png"), dir.join("out.png"));
    fs::write(&input, commented_png()).unwrap();
    let run = |input: &Path, output: &Path| {
        let result = Command::new(MALMAL)
            .arg("sanitize")
            .args([input, output])
            .output()
            .unwrap();
        (
            result.status.code(),
            String::from_utf8(result.stderr).unwrap(),
        )
    };

    let (code, message) = run(&input, &output);
    assert_eq!(code, Some(0), "{message}");
    assert!(
        message.contains("rebuilt as png (1x1, 1 frame"),
        "{message}"
    );
    let rebuilt = fs::read(&output).unwrap();
    assert!(rebuilt.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert!(!rebuilt.windows(7).any(|window| window == b"holiday"));

    // What is not clean, or not an image, leaves the output as it was.
    let executable = dir.join("photo.png");
    fs::write(&executable, ELF).unwrap();
    let (code, message) = run(&executable, &output);
    assert_eq!(code, Some(2), "{message}");
    assert!(message.contains("type.executable"), "{message}");
    let document = dir.join("page.pdf");
    fs::write(
        &document,
        b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF\n",
    )
    .unwrap();
    assert_eq!(run(&document, &output).0, Some(3));
    assert_eq!(fs::read(&output).unwrap(), rebuilt);
    // And an output that was not there is still not there.
    let absent = dir.join("absent.png");
    assert_eq!(run(&executable, &absent).0, Some(2));
    assert_eq!(run(&dir.join("no-such-input.png"), &absent).0, Some(3));
    assert!(!absent.exists());

    // A file that is replaced keeps its permissions, and nothing is left
    // beside it. Options may follow the files.
    use std::os::unix::fs::PermissionsExt;
    fs::write(&output, b"what was here before").unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o640)).unwrap();
    let replaced = Command::new(MALMAL)
        .arg("sanitize")
        .args([&input, &output])
        .args(["--policy", "strict", "--require-sandbox"])
        .status()
        .unwrap();
    if sandbox_available(&dir) {
        assert_eq!(replaced.code(), Some(0));
    } else {
        assert_eq!(run(&input, &output).0, Some(0));
    }
    assert_eq!(fs::read(&output).unwrap(), rebuilt);
    let mode = fs::metadata(&output).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    let left_behind = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .any(|name| name.ends_with(".tmp"));
    assert!(!left_behind);

    // A device is written to, not replaced.
    assert_eq!(run(&input, Path::new("/dev/null")).0, Some(0));
    assert!(!fs::metadata("/dev/null").unwrap().is_file());

    // Standard input to standard output.
    let mut child = Command::new(MALMAL)
        .args(["sanitize", "--jpeg-quality", "80", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&commented_png())
        .unwrap();
    let piped = child.wait_with_output().unwrap();
    assert_eq!(piped.status.code(), Some(0));
    assert_eq!(piped.stdout, rebuilt);

    let wrong = Command::new(MALMAL)
        .args(["sanitize", "one-file-only"])
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(3));
}

#[cfg(feature = "cdr")]
#[test]
fn daemon_rebuilds_over_http() {
    use std::io::Read;
    use std::net::TcpStream;

    let (_daemon, address) = daemon_on_tcp("--http");
    let post = |body: &[u8]| {
        let mut stream = TcpStream::connect(&address).unwrap();
        let head = format!(
            "POST /sanitize HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        let end = reply.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (
            String::from_utf8_lossy(&reply[..end]).into_owned(),
            reply[end..].to_vec(),
        )
    };

    let (head, body) = post(&commented_png());
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(head.contains("Content-Type: image/png\r\n"), "{head}");
    assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert!(!body.windows(7).any(|window| window == b"holiday"));

    let (head, body) = post(ELF);
    assert!(head.starts_with("HTTP/1.1 422 "), "{head}");
    assert!(String::from_utf8_lossy(&body).contains("type.executable"));
    let (head, _) = post(b"<svg xmlns='http://www.w3.org/2000/svg'/>");
    assert!(head.starts_with("HTTP/1.1 415 "), "{head}");
}

#[test]
fn daemon_answers_clamd_clients() {
    use std::io::Read;
    use std::net::TcpStream;

    let (_daemon, address) = daemon_on_tcp("--clamd");
    let instream = |body: &[u8]| {
        let mut stream = TcpStream::connect(&address).unwrap();
        stream.write_all(b"zINSTREAM\0").unwrap();
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(body).unwrap();
        stream.write_all(&[0; 4]).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    };
    assert_eq!(instream(&valid_png()), "stream: OK\0");
    assert_eq!(
        instream(ELF),
        "stream: Malmal.Malicious.type.executable FOUND\0"
    );
}

#[test]
fn daemon_answers_icap_clients() {
    use std::io::Read;
    use std::net::{Shutdown, TcpStream};

    let (_daemon, address) = daemon_on_tcp("--icap");
    let respmod = |body: &[u8]| {
        let head = "HTTP/1.1 200 OK\r\n\r\n";
        let mut stream = TcpStream::connect(&address).unwrap();
        let request = format!(
            "RESPMOD icap://{address}/scan ICAP/1.0\r\nAllow: 204\r\n\
             Encapsulated: res-hdr=0, res-body={}\r\n\r\n{head}{:x}\r\n",
            head.len(),
            body.len()
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    };
    let clean = respmod(&valid_png());
    assert!(
        clean.starts_with("ICAP/1.0 204 No Modifications"),
        "{clean}"
    );
    let blocked = respmod(ELF);
    assert!(blocked.contains("Threat=Malmal.Malicious.type.executable"));
    assert!(blocked.contains("HTTP/1.1 403 Forbidden"), "{blocked}");
}

/// A proxy keeps its connections open between requests. With a thread
/// held by each, a handful of them once kept every other client waiting.
#[test]
fn idle_connections_do_not_keep_others_waiting() {
    use std::io::Read;
    use std::net::TcpStream;

    let (_daemon, address) = daemon_on_tcp("--http");
    let request = b"GET /healthz HTTP/1.1\r\n\r\n";
    let answered = |stream: &mut TcpStream| {
        stream.write_all(request).unwrap();
        let mut reply = [0; 15];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"HTTP/1.1 200 OK");
    };
    // Three times as many as requests are worked on at once.
    let mut kept: Vec<TcpStream> = (0..12)
        .map(|_| TcpStream::connect(&address).unwrap())
        .collect();
    kept.iter_mut().for_each(answered);

    let started = Instant::now();
    let mut late = TcpStream::connect(&address).unwrap();
    late.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    answered(&mut late);
    // Well inside the five seconds after which an idle connection is dropped.
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(kept);
}

#[test]
fn daemon_needs_an_endpoint() {
    let output = Command::new(MALMALD).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(
        text.contains("--socket, --http, --clamd or --icap"),
        "{text}"
    );
}

/// Landlock and seccomp bind the calling thread, so the restrictions can be
/// observed from inside a thread without affecting the other tests.
#[test]
fn sandboxed_thread_loses_files_programs_and_sockets() {
    use malmal_cli::sandbox::{self, Mode};

    let dir = scratch("confine");
    if !sandbox_available(&dir) {
        eprintln!("skipped: sandbox not available here");
        return;
    }
    let (allowed, other) = (dir.join("allowed.png"), dir.join("other.png"));
    fs::write(&allowed, valid_png()).unwrap();
    fs::write(&other, valid_png()).unwrap();

    let (allowed_in, other_in, dir_in) = (allowed.clone(), other.clone(), dir.clone());
    thread::spawn(move || {
        let status = sandbox::enter(Mode::Require, &[&allowed_in], None).unwrap();
        assert!(status.filesystem && status.syscalls);

        assert!(fs::read(&allowed_in).is_ok());
        let denied = std::io::ErrorKind::PermissionDenied;
        assert_eq!(fs::read(&other_in).unwrap_err().kind(), denied);
        assert_eq!(fs::read("/etc/hostname").unwrap_err().kind(), denied);
        assert_eq!(fs::write(&allowed_in, b"x").unwrap_err().kind(), denied);
        assert_eq!(
            fs::write(dir_in.join("new"), b"x").unwrap_err().kind(),
            denied
        );
        assert!(Command::new("/bin/true").status().is_err());
        assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err_and(|e| e.kind() == denied));
        assert!(UnixStream::connect(dir_in.join("none.sock")).is_err_and(|e| e.kind() == denied));
    })
    .join()
    .unwrap();

    // The test's own thread is untouched.
    assert!(fs::read(&other).is_ok());
    fs::remove_dir_all(dir).unwrap();
}
