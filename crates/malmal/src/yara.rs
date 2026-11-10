//! Optional YARA rule matching, for signatures maintained outside this crate.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::report::{Finding, Severity};

/// A compiled rule set, cheap to clone and share between scanners.
#[derive(Clone)]
pub struct YaraRules(Arc<yara_x::Rules>);

impl fmt::Debug for YaraRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("YaraRules")
    }
}

/// A rule source that did not compile.
#[derive(Debug)]
pub struct YaraError(String);

impl fmt::Display for YaraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for YaraError {}

impl YaraRules {
    /// Compile rule sources, each the text of one `.yar` file.
    pub fn compile<'a>(sources: impl IntoIterator<Item = &'a str>) -> Result<Self, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        for source in sources {
            compiler
                .add_source(source)
                .map_err(|error| YaraError(error.to_string()))?;
        }
        Ok(Self(Arc::new(compiler.build())))
    }

    /// Report every rule that matches `data`.
    pub(crate) fn scan(&self, data: &[u8], timeout: Duration, findings: &mut Vec<Finding>) {
        let mut scanner = yara_x::Scanner::new(&self.0);
        scanner.set_timeout(timeout);
        match scanner.scan(data) {
            Ok(results) => {
                for rule in results.matching_rules() {
                    findings.push(Finding::new(
                        "yara.match",
                        Severity::Critical,
                        format!("matches YARA rule {}", rule.identifier()),
                    ));
                }
            }
            // Rules that could not finish have not cleared the file.
            Err(error) => findings.push(Finding::new(
                "yara.error",
                Severity::Medium,
                format!("YARA rules could not be evaluated: {error}"),
            )),
        }
    }
}
