use std::time::{Duration, Instant};

use crate::report::{Finding, Severity};

/// Resource limits for one scan. Whatever exceeds one is reported with a
/// `limit.*` finding, so a file that was not analyzed to the end is never
/// clean.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Inputs larger than this are truncated and flagged `limit.size`.
    pub max_file_size: u64,
    /// Total bytes all decoders may produce for one scan.
    pub max_decompressed: u64,
    /// Nesting depth for embedded files scanned recursively.
    pub max_depth: u32,
    /// Time the analyzers may spend on one scan. It is checked between
    /// steps, so a scan can run somewhat longer than this.
    pub max_duration: Duration,
    /// Images declaring more pixels than this are flagged `image.pixel_bomb`.
    pub max_pixels: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 64 << 20,
            max_decompressed: 256 << 20,
            max_depth: 4,
            max_duration: Duration::from_secs(10),
            max_pixels: 1 << 28,
        }
    }
}

/// A limit a scan ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitExceeded {
    Decompression,
    Depth,
    Time,
    /// The file's structure costs more to walk than its size justifies.
    Complexity,
}

impl LimitExceeded {
    pub fn code(self) -> &'static str {
        match self {
            Self::Decompression => "limit.decompression",
            Self::Depth => "limit.depth",
            Self::Time => "limit.time",
            Self::Complexity => "limit.complexity",
        }
    }

    /// A scan that could not finish must never be reported clean.
    pub fn finding(self) -> Finding {
        let message = match self {
            Self::Decompression => "decompressed data exceeds the configured limit",
            Self::Depth => "embedded files are nested deeper than the configured limit",
            Self::Time => "scan exceeded the configured time limit",
            Self::Complexity => "file structure is too complex to analyze completely",
        };
        Finding::new(self.code(), Severity::Medium, message)
    }
}

/// Per-scan resource budget shared by every analyzer and decoder.
#[derive(Debug)]
pub(crate) struct Budget {
    decompressed_left: u64,
    depth_left: u32,
    deadline: Instant,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            decompressed_left: limits.max_decompressed,
            depth_left: limits.max_depth,
            deadline: Instant::now() + limits.max_duration,
        }
    }

    /// Account for `n` bytes of decoder output.
    pub fn consume(&mut self, n: u64) -> Result<(), LimitExceeded> {
        match self.decompressed_left.checked_sub(n) {
            Some(left) => {
                self.decompressed_left = left;
                Ok(())
            }
            None => {
                self.decompressed_left = 0;
                Err(LimitExceeded::Decompression)
            }
        }
    }

    /// Decoder output bytes still available.
    pub fn remaining(&self) -> u64 {
        self.decompressed_left
    }

    pub fn check_time(&self) -> Result<(), LimitExceeded> {
        if Instant::now() > self.deadline {
            Err(LimitExceeded::Time)
        } else {
            Ok(())
        }
    }

    /// Enter one level of embedded content; pair with [`Budget::leave`].
    pub fn enter(&mut self) -> Result<(), LimitExceeded> {
        match self.depth_left.checked_sub(1) {
            Some(left) => {
                self.depth_left = left;
                Ok(())
            }
            None => Err(LimitExceeded::Depth),
        }
    }

    pub fn leave(&mut self) {
        self.depth_left += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompression_budget_is_exhausted_once() {
        let limits = Limits {
            max_decompressed: 10,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        assert_eq!(budget.consume(6), Ok(()));
        assert_eq!(budget.consume(5), Err(LimitExceeded::Decompression));
        assert_eq!(budget.consume(1), Err(LimitExceeded::Decompression));
    }

    #[test]
    fn depth_is_restored_on_leave() {
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        assert_eq!(budget.enter(), Ok(()));
        assert_eq!(budget.enter(), Err(LimitExceeded::Depth));
        budget.leave();
        assert_eq!(budget.enter(), Ok(()));
    }

    #[test]
    fn elapsed_deadline_is_reported() {
        let limits = Limits {
            max_duration: Duration::ZERO,
            ..Limits::default()
        };
        let budget = Budget::new(&limits);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(budget.check_time(), Err(LimitExceeded::Time));
    }
}
