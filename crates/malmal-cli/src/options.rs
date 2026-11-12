//! Command-line options both binaries accept.

use std::fs;
use std::time::Duration;

use malmal::{FileType, HashList, Limits, Policy, Scanner};

use crate::sandbox::Mode;

// The literals start on the quote's own line: a `"\` continuation would strip
// the leading spaces of the first line and misalign it from the rest.
#[cfg(not(feature = "yara"))]
pub const HELP: &str = "  --policy <NAME>      default or strict [default: default]
  --types <LIST>       Accepted file types, comma-separated
                       [default: jpeg,png,gif,webp,bmp,tiff,psd,heif,avif,jxl,ico,
                       svg,pdf,postscript]
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
  --max-size <BYTES>   Largest file analyzed in full [default: 67108864]
  --scan-timeout <S>   Seconds one scan may take [default: 10]
  --no-sandbox         Do not restrict the process
  --require-sandbox    Exit with an error if the sandbox cannot be applied";

#[cfg(feature = "yara")]
pub const HELP: &str = "  --policy <NAME>      default or strict [default: default]
  --types <LIST>       Accepted file types, comma-separated
                       [default: jpeg,png,gif,webp,bmp,tiff,psd,heif,avif,jxl,ico,
                       svg,pdf,postscript]
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
  --max-size <BYTES>   Largest file analyzed in full [default: 67108864]
  --scan-timeout <S>   Seconds one scan may take [default: 10]
  --yara <PATH>        YARA rule file, or directory of .yar/.yara files (repeatable)
  --no-sandbox         Do not restrict the process
  --require-sandbox    Exit with an error if the sandbox cannot be applied";

/// Address space the scanning process may use once sandboxed. The YARA
/// engine reserves far more address space than it touches, so no limit is
/// set when it is compiled in.
pub const MEMORY_LIMIT: Option<u64> = if cfg!(feature = "yara") {
    None
} else {
    Some(4 << 30)
};

pub struct Common {
    pub policy: Policy,
    /// Replaces the policy's accepted types when given.
    pub types: Option<Vec<FileType>>,
    pub hashlist: HashList,
    pub limits: Limits,
    pub sandbox: Mode,
    #[cfg(feature = "yara")]
    pub yara_sources: Vec<String>,
}

impl Default for Common {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            types: None,
            hashlist: HashList::default(),
            limits: Limits::default(),
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
            "--hashlist" => {
                let path = rest.next().ok_or("--hashlist needs a value")?;
                let text = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                self.hashlist = HashList::parse(&text).map_err(|e| format!("{path}: {e}"))?;
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
            "--scan-timeout" => {
                let seconds = rest
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|&seconds: &u64| seconds > 0)
                    .ok_or("--scan-timeout needs a positive number of seconds")?;
                self.limits.max_duration = Duration::from_secs(seconds);
            }
            "--no-sandbox" => self.sandbox = Mode::Off,
            "--require-sandbox" => self.sandbox = Mode::Require,
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn scanner(&self) -> Result<Scanner, String> {
        let policy = match &self.types {
            Some(types) => self
                .policy
                .clone()
                .with_allowed_types(types.iter().copied()),
            None => self.policy.clone(),
        };
        let builder = Scanner::builder()
            .limits(self.limits.clone())
            .policy(policy)
            .hashlist(self.hashlist.clone());
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
