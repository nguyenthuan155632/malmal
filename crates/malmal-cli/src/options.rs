//! Command-line options both binaries accept.

use std::fs;
use std::time::Duration;

use malmal::{FileType, HashList, Limits, Policy, Scanner, Severity};

use crate::sandbox::Mode;
use crate::watchdog::Watchdog;

// The literals start on the quote's own line: a `"\` continuation would strip
// the leading spaces of the first line and misalign it from the rest.
#[cfg(not(feature = "yara"))]
pub const HELP: &str = "  --policy <NAME>      default or strict [default: default]
  --types <LIST>       Accepted file types, comma-separated
                       [default: jpeg,png,gif,webp,bmp,tiff,psd,heif,avif,jxl,ico,
                       svg,pdf,postscript]
  --allow <CODES>      Finding codes that do not count against a file,
                       separated by commas or |: pdf.xfa,pdf.embedded_file
                       (repeatable; codes are in docs/findings.md)
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
  --no-hash            Do not compute the SHA-256 of a file, unless a
                       blocklist needs it; the slowest part on large files
  --pdf-passwords <FILE>
                       Passwords to try on encrypted PDFs, one per line
  --max-size <BYTES>   Largest file analyzed in full [default: 67108864]
  --max-decompressed <BYTES>
                       Most that the compressed data in one file may expand
                       to, and that the pixels of an image rebuilt may take;
                       what a request costs in memory follows from it
                       [default: 268435456]
  --max-pixels <N>     Most pixels an image may declare [default: 268435456]
  --scan-timeout <S>   Seconds one scan may take [default: 10]
  --hard-timeout <S>   Seconds after which a scan still running ends the
                       process; 0 for never [default: six times --scan-timeout]
  --no-sandbox         Do not restrict the process
  --require-sandbox    Exit with an error if the sandbox cannot be applied";

#[cfg(feature = "yara")]
pub const HELP: &str = "  --policy <NAME>      default or strict [default: default]
  --types <LIST>       Accepted file types, comma-separated
                       [default: jpeg,png,gif,webp,bmp,tiff,psd,heif,avif,jxl,ico,
                       svg,pdf,postscript]
  --allow <CODES>      Finding codes that do not count against a file,
                       separated by commas or |: pdf.xfa,pdf.embedded_file
                       (repeatable; codes are in docs/findings.md)
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
  --no-hash            Do not compute the SHA-256 of a file, unless a
                       blocklist needs it; the slowest part on large files
  --pdf-passwords <FILE>
                       Passwords to try on encrypted PDFs, one per line
  --max-size <BYTES>   Largest file analyzed in full [default: 67108864]
  --max-decompressed <BYTES>
                       Most that the compressed data in one file may expand
                       to, and that the pixels of an image rebuilt may take;
                       what a request costs in memory follows from it
                       [default: 268435456]
  --max-pixels <N>     Most pixels an image may declare [default: 268435456]
  --scan-timeout <S>   Seconds one scan may take [default: 10]
  --hard-timeout <S>   Seconds after which a scan still running ends the
                       process; 0 for never [default: six times --scan-timeout]
  --yara <PATH>        YARA rule file, or directory of .yar/.yara files (repeatable)
  --no-sandbox         Do not restrict the process
  --require-sandbox    Exit with an error if the sandbox cannot be applied";

/// Address space the scanning process may use once sandboxed, besides the
/// file it scans. The YARA engine reserves far more address space than it
/// touches, so no limit is set when it is compiled in.
const MEMORY_LIMIT: Option<u64> = if cfg!(feature = "yara") {
    None
} else {
    Some(4 << 30)
};

/// The address space limit for a process that works on `at_once` files of
/// up to `limits.max_file_size` bytes at a time. Each file is mapped or held
/// whole, and what is decoded from it comes to a few times
/// `limits.max_decompressed`: a limit below what the options allow would
/// end the process on the files they were raised for, or on as many honest
/// requests as it was told to take at once. The limit is there to stop a
/// decoder that has lost its way, not to do the work of the other limits.
pub fn memory_limit(limits: &Limits, at_once: u64) -> Option<u64> {
    let defaults = Limits::default();
    let files = limits.max_file_size.saturating_mul(at_once);
    let decoded = limits
        .max_decompressed
        .saturating_mul(3)
        .saturating_mul(at_once);
    let beyond_default = files
        .saturating_sub(defaults.max_file_size)
        .saturating_add(decoded.saturating_sub(defaults.max_decompressed * 12));
    MEMORY_LIMIT.map(|limit| limit.saturating_add(beyond_default))
}

pub struct Common {
    pub policy: Policy,
    /// Replaces the policy's accepted types when given.
    pub types: Option<Vec<FileType>>,
    /// Codes given with `--allow`, reported at Info whatever the policy.
    pub allow: Vec<&'static str>,
    pub hashlist: HashList,
    pub no_hash: bool,
    pub pdf_passwords: Vec<String>,
    pub limits: Limits,
    /// Seconds given with `--hard-timeout`; 0 is never.
    pub hard_timeout: Option<u64>,
    pub sandbox: Mode,
    #[cfg(feature = "yara")]
    pub yara_sources: Vec<String>,
}

impl Default for Common {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            types: None,
            allow: Vec::new(),
            hashlist: HashList::default(),
            no_hash: false,
            pdf_passwords: Vec::new(),
            limits: Limits::default(),
            hard_timeout: None,
            sandbox: Mode::BestEffort,
            #[cfg(feature = "yara")]
            yara_sources: Vec::new(),
        }
    }
}

impl Common {
    /// Handle `arg` if it is a shared option, taking its value from `rest`.
    /// Returns whether it was one.
    pub fn parse(
        &mut self,
        arg: &str,
        rest: &mut impl Iterator<Item = String>,
    ) -> Result<bool, String> {
        match arg {
            "--policy" => {
                self.policy = match rest.next().as_deref() {
                    Some("default") => Policy::default(),
                    Some("strict") => Policy::strict(),
                    Some(other) => return Err(format!("unknown policy {other:?}")),
                    None => return Err("--policy needs a value".into()),
                }
            }
            "--types" => {
                let list = rest.next().ok_or("--types needs a value")?;
                let types = list
                    .split(',')
                    .map(|name| {
                        FileType::from_name(name.trim())
                            .ok_or_else(|| format!("unknown file type {name:?}"))
                    })
                    .collect::<Result<_, _>>()?;
                self.types = Some(types);
            }
            "--allow" => {
                let list = rest.next().ok_or("--allow needs a value")?;
                for code in list.split([',', '|']).map(str::trim) {
                    self.allow.push(allowable(code)?);
                }
            }
            "--hashlist" => {
                let path = rest.next().ok_or("--hashlist needs a value")?;
                let text = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                self.hashlist = HashList::parse(&text).map_err(|e| format!("{path}: {e}"))?;
            }
            "--no-hash" => self.no_hash = true,
            "--pdf-passwords" => {
                let path = rest.next().ok_or("--pdf-passwords needs a value")?;
                let text = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                let lines = text.lines().filter(|line| !line.is_empty());
                self.pdf_passwords = lines.map(str::to_owned).collect();
            }
            #[cfg(feature = "yara")]
            "--yara" => {
                let path = rest.next().ok_or("--yara needs a value")?;
                self.yara_sources.extend(read_rules(&path)?);
            }
            "--max-size" => {
                self.limits.max_file_size = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|&bytes: &u64| bytes > 0)
                    .ok_or("--max-size needs a positive number of bytes")?;
            }
            "--max-decompressed" => {
                self.limits.max_decompressed = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|&bytes: &u64| bytes > 0)
                    .ok_or("--max-decompressed needs a positive number of bytes")?;
            }
            "--max-pixels" => {
                self.limits.max_pixels = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|&pixels: &u64| pixels > 0)
                    .ok_or("--max-pixels needs a positive number of pixels")?;
            }
            "--scan-timeout" => {
                let seconds = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|&seconds: &u64| seconds > 0)
                    .ok_or("--scan-timeout needs a positive number of seconds")?;
                self.limits.max_duration = Duration::from_secs(seconds);
            }
            "--hard-timeout" => {
                let seconds = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--hard-timeout needs a number of seconds")?;
                self.hard_timeout = Some(seconds);
            }
            "--no-sandbox" => self.sandbox = Mode::Off,
            "--require-sandbox" => self.sandbox = Mode::Require,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The watchdog `--hard-timeout` asks for. The scan's own time limit is
    /// checked between steps and so overrun a little by an honest file; the
    /// default leaves room for that, and for rebuilding an image afterwards.
    pub fn watchdog(&self, program: &'static str) -> Watchdog {
        let limit = match self.hard_timeout {
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => Some(self.limits.max_duration.saturating_mul(6)),
        };
        Watchdog::start(program, limit)
    }

    pub fn scanner(&self) -> Result<Scanner, String> {
        let policy = match &self.types {
            Some(types) => self
                .policy
                .clone()
                .with_allowed_types(types.iter().copied()),
            None => self.policy.clone(),
        };
        let policy = self.allow.iter().fold(policy, |policy, &code| {
            policy.with_override(code, Severity::Info)
        });
        let builder = Scanner::builder()
            .limits(self.limits.clone())
            .policy(policy)
            .hashlist(self.hashlist.clone())
            .pdf_passwords(self.pdf_passwords.iter().map(String::as_str));
        let builder = if self.no_hash {
            builder.without_hash()
        } else {
            builder
        };
        #[cfg(feature = "yara")]
        let builder = if self.yara_sources.is_empty() {
            builder
        } else {
            let sources = self.yara_sources.iter().map(String::as_str);
            builder.yara(malmal::YaraRules::compile(sources).map_err(|e| e.to_string())?)
        };
        Ok(builder.build())
    }
}

/// The code `--allow` was given, if the scanner reports it. A limit cannot
/// be allowed: a file that was not analyzed to the end is never clean.
fn allowable(code: &str) -> Result<&'static str, String> {
    let known = malmal::report::CODES.iter().find(|&&known| known == code);
    match known {
        Some(code) if code.starts_with("limit.") => Err(format!(
            "--allow {code}: a file that was not analyzed to the end is never clean; \
             raise the limit instead"
        )),
        Some(&code) => Ok(code),
        None => Err(format!(
            "--allow: unknown finding code {code:?}; the codes are listed in docs/findings.md"
        )),
    }
}

/// Rule text from one file, or from every `.yar`/`.yara` file in a directory.
#[cfg(feature = "yara")]
fn read_rules(path: &str) -> Result<Vec<String>, String> {
    let read = |file: &std::path::Path| {
        fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))
    };
    let path = std::path::Path::new(path);
    if !path.is_dir() {
        return Ok(vec![read(path)?]);
    }
    let mut files: Vec<_> = fs::read_dir(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|file| {
            matches!(
                file.extension().and_then(|e| e.to_str()),
                Some("yar" | "yara")
            )
        })
        .collect();
    files.sort();
    files.iter().map(|file| read(file)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Common, String> {
        let mut common = Common::default();
        let mut rest = args.iter().map(|arg| arg.to_string());
        while let Some(arg) = rest.next() {
            assert!(common.parse(&arg, &mut rest)?, "{arg} is not an option");
        }
        Ok(common)
    }

    #[test]
    fn allowed_codes_are_listed_with_either_separator() {
        let common = parse(&[
            "--allow",
            "pdf.xfa|pdf.embedded_file",
            "--allow",
            "pdf.uri, svg.foreign_object",
        ])
        .unwrap();
        assert_eq!(
            common.allow,
            [
                "pdf.xfa",
                "pdf.embedded_file",
                "pdf.uri",
                "svg.foreign_object"
            ]
        );
    }

    #[test]
    fn only_codes_the_scanner_reports_can_be_allowed() {
        let error = parse(&["--allow", "pdf.embeddedfile"]).err().unwrap();
        assert!(
            error.contains("unknown finding code \"pdf.embeddedfile\""),
            "{error}"
        );
        assert!(parse(&["--allow", ""]).is_err());
        assert!(parse(&["--allow"]).is_err());
        let error = parse(&["--allow", "pdf.xfa,limit.complexity"])
            .err()
            .unwrap();
        assert!(error.contains("never clean"), "{error}");
    }

    #[test]
    fn allowed_codes_survive_a_later_policy() {
        let common = parse(&["--allow", "pdf.xfa", "--policy", "strict"]).unwrap();
        let scanner = common.scanner().unwrap();
        let form = b"%PDF-1.7\n1 0 obj << /Type /Catalog /AcroForm << /XFA 2 0 R >> >> endobj\n\
            2 0 obj << /Length 0 >> stream\n\nendstream endobj\n\
            trailer << /Root 1 0 R >>\n%%EOF\n";
        let report = scanner.scan_bytes(form, malmal::ScanHints::default());
        let xfa = report
            .findings
            .iter()
            .find(|f| f.code == "pdf.xfa")
            .expect("no pdf.xfa");
        assert_eq!(xfa.severity, Severity::Info);
    }
}
