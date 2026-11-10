//! Command-line options both binaries accept.

use std::fs;

use malmal::{HashList, Policy, Scanner};

use crate::sandbox::Mode;

#[cfg(not(feature = "yara"))]
pub const HELP: &str = "\
  --policy <NAME>      default or strict [default: default]
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
  --no-sandbox         Do not restrict the process
  --require-sandbox    Exit with an error if the sandbox cannot be applied";

#[cfg(feature = "yara")]
pub const HELP: &str = "\
  --policy <NAME>      default or strict [default: default]
  --hashlist <FILE>    SHA-256 blocklist, one hex digest per line
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
    pub hashlist: HashList,
    pub sandbox: Mode,
    #[cfg(feature = "yara")]
    pub yara_sources: Vec<String>,
}

impl Default for Common {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            hashlist: HashList::default(),
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
            "--no-sandbox" => self.sandbox = Mode::Off,
            "--require-sandbox" => self.sandbox = Mode::Require,
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn scanner(&self) -> Result<Scanner, String> {
        let builder = Scanner::builder()
            .policy(self.policy.clone())
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
