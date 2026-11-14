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
    /// The scan holds more memory than [`MemoryLimit::max`].
    Memory,
}

impl LimitExceeded {
    pub fn code(self) -> &'static str {
        match self {
            Self::Decompression => "limit.decompression",
            Self::Depth => "limit.depth",
            Self::Time => "limit.time",
            Self::Complexity => "limit.complexity",
            Self::Memory => "limit.memory",
        }
    }

    /// A scan that could not finish must never be reported clean.
    pub fn finding(self) -> Finding {
        let message = match self {
            Self::Decompression => "decompressed data exceeds the configured limit",
            Self::Depth => "embedded files are nested deeper than the configured limit",
            Self::Time => "scan exceeded the configured time limit",
            Self::Complexity => "file structure is too complex to analyze completely",
            Self::Memory => "scan exceeded the configured memory limit",
        };
        Finding::new(self.code(), Severity::Medium, message)
    }
}

/// What a scan may hold in memory, as the caller measures it: `measure`
/// returns a count of the bytes the calling thread holds, from any origin,
/// and a scan that comes to hold more than `max` beyond what its thread
/// held when it started stops with `limit.memory`. It is checked where the time limit is, between
/// steps; one step, such as decoding one stream, may take up to
/// [`Limits::max_decompressed`] beyond it before it is noticed.
///
/// The library allocates through the global allocator, which knows what
/// each thread holds; a program that wants the limit installs one that
/// counts and passes its counter here. The scan runs on the thread that
/// calls it, but for the hash and the payload search of a file of 4 MiB
/// or more, which hold little.
#[derive(Debug, Clone, Copy)]
pub struct MemoryLimit {
    /// Bytes a scan may hold beyond what its thread held when it started.
    pub max: u64,
    /// The bytes the calling thread holds now.
    pub measure: fn() -> u64,
}

/// See [`Budget::memory_watch`].
#[derive(Clone, Copy)]
pub(crate) struct MemoryWatch(Option<(MemoryLimit, u64)>);

impl MemoryWatch {
    pub fn is_over(self) -> bool {
        self.0
            .is_some_and(|(limit, start)| (limit.measure)().saturating_sub(start) > limit.max)
    }

    /// What the scan may still hold, if it has a memory limit: the most a
    /// decoder that produces its output at once may be allowed.
    pub fn headroom(self) -> Option<u64> {
        self.0.map(|(limit, start)| {
            let held = (limit.measure)().saturating_sub(start);
            limit.max.saturating_sub(held)
        })
    }
}

/// Per-scan resource budget shared by every analyzer and decoder.
#[derive(Debug)]
pub(crate) struct Budget {
    decompressed_left: u64,
    depth_left: u32,
    deadline: Instant,
    /// The limit, and what the thread held when the scan started.
    memory: Option<(MemoryLimit, u64)>,
    /// The scan has been over its memory: it stays so, though what it held
    /// is let go.
    memory_spent: bool,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            decompressed_left: limits.max_decompressed,
            depth_left: limits.max_depth,
            deadline: Instant::now() + limits.max_duration,
            memory: None,
            memory_spent: false,
        }
    }

    pub fn with_memory(mut self, limit: Option<MemoryLimit>) -> Self {
        self.memory = limit.map(|limit| (limit, (limit.measure)()));
        self
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

    /// Whether the scan is still within its time and its memory.
    pub fn check_time(&self) -> Result<(), LimitExceeded> {
        if Instant::now() > self.deadline {
            return Err(LimitExceeded::Time);
        }
        if self.memory_spent || self.memory_watch().is_over() {
            return Err(LimitExceeded::Memory);
        }
        Ok(())
    }

    /// What a decoder looks at, a block at a time, to stop holding output
    /// once the scan is over its memory. It borrows nothing from the budget.
    pub fn memory_watch(&self) -> MemoryWatch {
        MemoryWatch(self.memory)
    }

    /// A decoder stopped because the scan was over its memory.
    pub fn memory_spent(&mut self) {
        self.memory_spent = true;
    }

    /// The limit that a decoder that stopped short ran into: its output, or
    /// the scan's memory.
    pub fn decode_limit(&self) -> LimitExceeded {
        if self.memory_spent {
            LimitExceeded::Memory
        } else {
            LimitExceeded::Decompression
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

/// How much a decoder below hands over at a time: what it has produced is
/// held to its limit, and to the scan's memory, after each block.
const BLOCK: usize = 64 << 10;

/// Why a decoder below stopped short.
#[derive(Debug, PartialEq)]
pub(crate) enum Unpacked {
    /// The data is not what it claims to be.
    Corrupt,
    /// It came to more than `cap` or what the budget has left, or the scan
    /// held more memory than its limit; [`Budget::decode_limit`] tells which.
    Limit,
}

/// What `read` produces, to at most `cap` bytes and what `budget` has left,
/// counted against it. It is read a block at a time and stops as soon as
/// it goes over either, or the scan is over its memory.
pub(crate) fn read_all(
    mut read: impl std::io::Read,
    cap: u64,
    budget: &mut Budget,
) -> Result<Vec<u8>, Unpacked> {
    let limit = budget.remaining().min(cap);
    let watch = budget.memory_watch();
    let mut output = Vec::new();
    let mut block = vec![0; BLOCK];
    loop {
        let read = match read.read(&mut block) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Unpacked::Corrupt),
        };
        output.extend_from_slice(&block[..read]);
        held_to(output.len(), limit, watch, budget)?;
    }
    let _ = budget.consume(output.len() as u64);
    Ok(output)
}

/// A Deflate stream, wrapped in zlib when `zlib`, inflated as [`read_all`]
/// reads.
pub(crate) fn inflate(
    data: &[u8],
    zlib: bool,
    cap: u64,
    budget: &mut Budget,
) -> Result<Vec<u8>, Unpacked> {
    use miniz_oxide::inflate::stream::{InflateState, inflate};
    use miniz_oxide::{DataFormat, MZFlush, MZStatus};

    let format = if zlib {
        DataFormat::Zlib
    } else {
        DataFormat::Raw
    };
    let limit = budget.remaining().min(cap);
    let watch = budget.memory_watch();
    let mut state = InflateState::new_boxed(format);
    let mut input = data;
    let mut output = Vec::new();
    let mut block = vec![0; BLOCK];
    loop {
        let result = inflate(&mut state, input, &mut block, MZFlush::None);
        input = &input[result.bytes_consumed..];
        output.extend_from_slice(&block[..result.bytes_written]);
        held_to(output.len(), limit, watch, budget)?;
        match result.status {
            Ok(MZStatus::StreamEnd) => break,
            // A stream that ends before its last block, or makes no progress.
            Ok(_) if result.bytes_consumed == 0 && result.bytes_written == 0 => {
                return Err(Unpacked::Corrupt);
            }
            Ok(_) => {}
            Err(_) => return Err(Unpacked::Corrupt),
        }
    }
    let _ = budget.consume(output.len() as u64);
    Ok(output)
}

/// See [`read_all`]: `held` bytes produced so far.
fn held_to(
    held: usize,
    limit: u64,
    watch: MemoryWatch,
    budget: &mut Budget,
) -> Result<(), Unpacked> {
    if held as u64 > limit {
        let _ = budget.consume(limit);
        return Err(Unpacked::Limit);
    }
    if watch.is_over() {
        budget.memory_spent();
        return Err(Unpacked::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_measured_from_the_start_of_the_scan() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static HELD: AtomicU64 = AtomicU64::new(1000);
        let limit = MemoryLimit {
            max: 100,
            measure: || HELD.load(Ordering::Relaxed),
        };
        let budget = Budget::new(&Limits::default()).with_memory(Some(limit));
        HELD.store(1100, Ordering::Relaxed);
        assert_eq!(budget.check_time(), Ok(()));
        HELD.store(1101, Ordering::Relaxed);
        assert_eq!(budget.check_time(), Err(LimitExceeded::Memory));
        // Less than at the start is within it.
        HELD.store(10, Ordering::Relaxed);
        assert_eq!(budget.check_time(), Ok(()));
    }

    #[test]
    fn decoders_stop_at_their_limit_and_at_the_scans_memory() {
        use miniz_oxide::deflate::{compress_to_vec, compress_to_vec_zlib};
        use std::cell::Cell;

        let text = b"block after block ".repeat(40_000);
        let zlib = compress_to_vec_zlib(&text, 6);
        let mut budget = Budget::new(&Limits::default());
        assert_eq!(
            inflate(&zlib, true, u64::MAX, &mut budget).as_deref(),
            Ok(&text[..])
        );
        assert_eq!(
            budget.remaining(),
            Limits::default().max_decompressed - text.len() as u64
        );
        let raw = compress_to_vec(&text, 6);
        assert_eq!(
            inflate(&raw, false, u64::MAX, &mut budget).as_deref(),
            Ok(&text[..])
        );
        // Too much for the cap; cut short; not Deflate at all.
        assert_eq!(
            inflate(&zlib, true, 1000, &mut budget),
            Err(Unpacked::Limit)
        );
        assert_eq!(budget.decode_limit(), LimitExceeded::Decompression);
        let cut = &zlib[..zlib.len() / 2];
        assert_eq!(
            inflate(cut, true, u64::MAX, &mut budget),
            Err(Unpacked::Corrupt)
        );
        assert_eq!(
            inflate(b"\xFF\xFF\xFF", true, u64::MAX, &mut budget),
            Err(Unpacked::Corrupt)
        );
        assert_eq!(read_all(&text[..], 10, &mut budget), Err(Unpacked::Limit));

        // A scan whose memory grows by a block each time it is looked at
        // is stopped a few blocks in, not at the end of the output.
        thread_local!(static LOOKS: Cell<u64> = const { Cell::new(0) });
        let limit = MemoryLimit {
            max: 4 * BLOCK as u64,
            measure: || {
                LOOKS.with(|looks| {
                    looks.set(looks.get() + 1);
                    looks.get() * BLOCK as u64
                })
            },
        };
        let mut budget = Budget::new(&Limits::default()).with_memory(Some(limit));
        assert_eq!(
            inflate(&zlib, true, u64::MAX, &mut budget),
            Err(Unpacked::Limit)
        );
        assert_eq!(budget.decode_limit(), LimitExceeded::Memory);
        assert!(LOOKS.with(Cell::get) < 8);
        assert_eq!(budget.memory_watch().headroom(), Some(0));
    }

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
