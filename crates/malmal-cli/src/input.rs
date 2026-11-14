//! A file to scan, without a copy of it: the file is mapped, so that its
//! pages stay the kernel's, to drop and read again as memory allows. What a
//! scan of a large file costs in memory is then what the analysis keeps, not
//! the size of the file.
//!
//! The daemon is sent its files over a connection. With a [`Spool`] it
//! writes the large ones to files of its own and maps those, to the same
//! end.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, Write};
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Below this a copy costs less than a mapping.
pub const MAP_FROM: u64 = 1 << 20;
/// What a body takes of the [`Reserve`] at a time, as it arrives.
const PIECE: u64 = 256 << 10;
/// Writes to the spool are gathered up to this; a client that sends its
/// file a byte at a time would otherwise cost a system call a byte.
const SPOOL_BUFFER: usize = 64 << 10;

pub enum Input {
    Mapped(memmap2::Mmap),
    Read(Vec<u8>),
}

impl Deref for Input {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(map) => map,
            Self::Read(data) => data,
        }
    }
}

impl Input {
    /// The file at `path`, or standard input for `-`, up to `limit` bytes.
    pub fn open(path: &str, limit: u64) -> io::Result<Self> {
        let mut data = Vec::new();
        if path == "-" {
            io::stdin().lock().take(limit).read_to_end(&mut data)?;
            return Ok(Self::Read(data));
        }
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let length = metadata.len().min(limit);
        if metadata.is_file()
            && length >= MAP_FROM
            && let Ok(length) = usize::try_from(length)
            && let Some(map) = map(&file, length)
        {
            return Ok(Self::Mapped(map));
        }
        file.take(limit).read_to_end(&mut data)?;
        Ok(Self::Read(data))
    }
}

/// The first `length` bytes of `file`, or `None` where it cannot be mapped
/// and has to be read.
#[allow(unsafe_code)]
fn map(file: &File, length: usize) -> Option<memmap2::Mmap> {
    // SAFETY: the mapping is private and read-only, and nothing here writes
    // to the file. Another process that cut the file short during the scan
    // would end this one with a signal, which is no verdict and so cannot
    // be taken for a clean one.
    let map = unsafe { memmap2::MmapOptions::new().len(length).map(file) }.ok()?;
    // Every pass goes through the file from its start to its end.
    #[cfg(unix)]
    let _ = map.advise(memmap2::Advice::Sequential);
    Some(map)
}

/// Files without names for the daemon to keep request bodies in. They are
/// opened before the sandbox closes, as many as there are requests worked on
/// at once, and used again and again: the sandbox need not allow a file to
/// be created, and no directory stays open to the process. A file that has
/// no name is gone when the process is, however it ends.
#[derive(Debug)]
pub struct Spool {
    files: Mutex<Vec<File>>,
}

impl Spool {
    /// Open `count` files in the directory `dir`, which should be on a disk:
    /// a file in a memory file system is memory.
    pub fn open(dir: &Path, count: usize) -> io::Result<Arc<Self>> {
        let files = (0..count).map(|index| unnamed(dir, index));
        let files = Mutex::new(files.collect::<io::Result<_>>()?);
        Ok(Arc::new(Self { files }))
    }

    fn take(&self) -> Option<File> {
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        files.pop()
    }

    /// Take a file back, emptied. One that cannot be emptied is closed,
    /// which empties it.
    fn give(&self, mut file: File) {
        if file.set_len(0).is_ok() && file.rewind().is_ok() {
            let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
            files.push(file);
        }
    }
}

/// A file in `dir` that has no name, or has lost it by the time this
/// returns.
fn unnamed(dir: &Path, index: usize) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        let options = options.read(true).write(true).mode(0o600);
        if let Ok(file) = options.custom_flags(libc::O_TMPFILE).open(dir) {
            return Ok(file);
        }
    }
    // Where the file system cannot make a file without a name.
    let path = dir.join(format!(".malmald-{}-{index}.spool", std::process::id()));
    let mut options = OpenOptions::new();
    let options = options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    let options = std::os::unix::fs::OpenOptionsExt::mode(options, 0o600);
    let file = options.open(&path)?;
    std::fs::remove_file(&path)?;
    Ok(file)
}

/// Bytes of request bodies that may be held at once, as they arrive and
/// while they are scanned, in memory or in the spool. A body takes its share
/// a piece at a time as it arrives, so a client holds no more than it has
/// sent, however much it said it would.
///
/// A body that finds no room waits for it, for as long as a connection may
/// stay idle. Bodies that are all still arriving and all waiting would wait
/// for each other: then the one that started last gives up its share and
/// is refused, and the others go on.
#[derive(Debug)]
pub struct Reserve {
    state: Mutex<Shares>,
    changed: Condvar,
    total: u64,
    patience: Duration,
}

#[derive(Debug, Default)]
struct Shares {
    free: u64,
    next: u64,
    /// Bodies that hold some of the reserve and are still arriving, and are
    /// not waiting for more.
    arriving: usize,
    /// Bodies that have arrived and hold some of the reserve: it comes back
    /// when their scan is over.
    arrived: usize,
    /// Bodies waiting for room, and whether they hold some already.
    waiting: Vec<(u64, bool)>,
}

impl Reserve {
    pub fn new(total: u64, patience: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Shares {
                free: total,
                ..Shares::default()
            }),
            changed: Condvar::new(),
            total,
            patience,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Shares> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn share(self: &Arc<Self>) -> Share {
        let mut state = self.lock();
        state.next += 1;
        Share {
            reserve: Arc::clone(self),
            id: state.next,
            held: 0,
            arrived: false,
        }
    }
}

/// What one body holds of a [`Reserve`]; dropping it gives that back.
#[derive(Debug)]
struct Share {
    reserve: Arc<Reserve>,
    id: u64,
    held: u64,
    arrived: bool,
}

/// The error a body that finds no room ends with; see [`is_refused`].
fn no_room() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, "no room for the file")
}

/// Whether `error` says that a body could not be held, as opposed to the
/// connection failing: the client is told so before the connection ends.
pub fn is_refused(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
}

impl Share {
    /// Take `count` more bytes of the reserve, waiting for them if need be.
    fn grow(&mut self, count: u64) -> io::Result<()> {
        let reserve = Arc::clone(&self.reserve);
        if count > reserve.total {
            return Err(no_room());
        }
        let deadline = Instant::now() + reserve.patience;
        let mut state = reserve.lock();
        let mut waiting = false;
        let outcome = loop {
            if state.free >= count {
                break Ok(());
            }
            if !waiting {
                waiting = true;
                if self.held > 0 {
                    state.arriving -= 1;
                }
                state.waiting.push((self.id, self.held > 0));
                // Those already waiting look again: this may be a deadlock.
                reserve.changed.notify_all();
            }
            // Nothing will come back to the reserve while every body that
            // holds some of it waits for more: the latest of them gives up.
            let stuck = state.arriving == 0 && state.arrived == 0;
            let latest = state
                .waiting
                .iter()
                .filter(|(_, holds)| *holds)
                .map(|(id, _)| *id)
                .max();
            if stuck && latest == Some(self.id) {
                break Err(no_room());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(no_room());
            }
            state = reserve
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        };
        if waiting {
            state.waiting.retain(|(id, _)| *id != self.id);
            if self.held > 0 {
                state.arriving += 1;
            }
        }
        if outcome.is_ok() {
            state.free -= count;
            if self.held == 0 {
                state.arriving += 1;
            }
            self.held += count;
        }
        outcome
    }

    /// The body has arrived; what it holds comes back when it is dropped.
    fn arrive(&mut self) {
        if self.held > 0 && !self.arrived {
            let mut state = self.reserve.lock();
            state.arriving -= 1;
            state.arrived += 1;
            self.reserve.changed.notify_all();
        }
        self.arrived = true;
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        if self.held == 0 {
            return;
        }
        let mut state = self.reserve.lock();
        state.free += self.held;
        if self.arrived {
            state.arrived -= 1;
        } else {
            state.arriving -= 1;
        }
        self.reserve.changed.notify_all();
    }
}

/// A request body as it arrives: in memory while it is small, and in a file
/// of the spool from [`MAP_FROM`] bytes on, if there is a spool.
#[derive(Debug)]
pub struct Incoming<'s> {
    spool: Option<&'s Arc<Spool>>,
    share: Option<Share>,
    memory: Vec<u8>,
    spooled: Option<Spooled>,
    length: u64,
}

impl<'s> Incoming<'s> {
    /// A body to keep in `spool` once it is large, holding its share of
    /// `reserve` as it arrives.
    pub fn new(spool: Option<&'s Arc<Spool>>, reserve: Option<&Arc<Reserve>>) -> Self {
        Self {
            spool,
            share: reserve.map(Reserve::share),
            memory: Vec::new(),
            spooled: None,
            length: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Append the next `count` bytes of `reader`, all of them or none: a
    /// reader that ends before is an error, and so is a body that finds no
    /// room in the reserve.
    pub fn read_from(&mut self, reader: &mut impl Read, count: u64) -> io::Result<()> {
        // A body in memory gets its size and no more, in memory that is not
        // touched until it is read into.
        let spooling = self.spooled.is_some()
            || self.spool.is_some() && self.length.saturating_add(count) >= MAP_FROM;
        if !spooling && let Ok(count) = usize::try_from(count) {
            self.memory.reserve_exact(count);
        }
        let mut left = count;
        while left > 0 {
            let piece = left.min(PIECE);
            if let Some(share) = &mut self.share {
                share.grow(piece)?;
            }
            self.read_piece(reader, piece)?;
            left -= piece;
        }
        Ok(())
    }

    fn read_piece(&mut self, reader: &mut impl Read, count: u64) -> io::Result<()> {
        let total = self.length.saturating_add(count);
        if self.spooled.is_none() && total >= MAP_FROM {
            // No file to be had means more requests at once than the spool
            // was opened for; the body stays in memory as it would have.
            let file = self.spool.and_then(|spool| Some((spool, spool.take()?)));
            if let Some((spool, file)) = file {
                let mut file = BufWriter::with_capacity(SPOOL_BUFFER, file);
                let moved = file.write_all(&self.memory);
                self.spooled = Some(Spooled {
                    map: None,
                    file: Some(file),
                    spool: Arc::clone(spool),
                });
                moved?;
                self.memory = Vec::new();
            }
        }
        match self
            .spooled
            .as_mut()
            .and_then(|spooled| spooled.file.as_mut())
        {
            Some(file) => {
                if io::copy(&mut reader.take(count), file)? != count {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            None => {
                let count = usize::try_from(count).map_err(|_| no_room())?;
                let start = self.memory.len();
                self.memory.resize(start + count, 0);
                reader.read_exact(&mut self.memory[start..])?;
            }
        }
        self.length = total;
        Ok(())
    }

    /// The whole body, to scan. It keeps its share of the reserve until it
    /// is dropped.
    pub fn finish(mut self) -> io::Result<Body> {
        if let Some(share) = &mut self.share {
            share.arrive();
        }
        let held = Held {
            kept: Kept::Memory(Vec::new()),
            _share: self.share,
        };
        let Some(mut spooled) = self.spooled else {
            return Ok(held.with(Kept::Memory(self.memory)));
        };
        let Some(writer) = spooled.file.as_mut() else {
            return Ok(held.with(Kept::Memory(self.memory)));
        };
        writer.flush()?;
        let file = writer.get_mut();
        // The file has no name and is this process's alone, which cuts it
        // short only once the mapping is gone.
        let mapped = usize::try_from(self.length)
            .ok()
            .and_then(|length| map(file, length));
        match mapped {
            Some(map) => {
                spooled.map = Some(map);
                Ok(held.with(Kept::Spooled(spooled)))
            }
            // Where the file cannot be mapped it is read back.
            None => {
                let mut memory = Vec::new();
                file.rewind()?;
                file.read_to_end(&mut memory)?;
                Ok(held.with(Kept::Memory(memory)))
            }
        }
    }
}

/// A request body, whole.
#[derive(Debug)]
pub struct Body(Held);

#[derive(Debug)]
struct Held {
    kept: Kept,
    _share: Option<Share>,
}

impl Held {
    fn with(mut self, kept: Kept) -> Body {
        self.kept = kept;
        Body(self)
    }
}

#[derive(Debug)]
enum Kept {
    Memory(Vec<u8>),
    Spooled(Spooled),
}

impl Body {
    /// Whether the body is in a file of the spool.
    pub fn is_spooled(&self) -> bool {
        matches!(self.0.kept, Kept::Spooled(_))
    }
}

impl Deref for Body {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.0.kept {
            Kept::Memory(data) => data,
            Kept::Spooled(spooled) => spooled.map.as_deref().unwrap_or_default(),
        }
    }
}

/// A file of the spool with a body in it. Dropping it empties the file and
/// gives it back: no body is on the disk for longer than its request.
#[derive(Debug)]
struct Spooled {
    map: Option<memmap2::Mmap>,
    file: Option<BufWriter<File>>,
    spool: Arc<Spool>,
}

impl Drop for Spooled {
    fn drop(&mut self) {
        // The mapping goes before the file is cut short under it.
        self.map = None;
        // A file whose last writes cannot be made is closed, which empties it.
        if let Some(Ok(file)) = self.file.take().map(BufWriter::into_inner) {
            self.spool.give(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("malmal-spool-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn small_bodies_stay_in_memory() {
        let dir = scratch("small");
        let spool = Spool::open(&dir, 1).unwrap();
        let mut incoming = Incoming::new(Some(&spool), None);
        incoming.read_from(&mut &b"abc"[..], 3).unwrap();
        incoming.read_from(&mut &b"defgh"[..], 2).unwrap();
        assert_eq!(incoming.len(), 5);
        let body = incoming.finish().unwrap();
        assert!(!body.is_spooled());
        assert_eq!(&*body, b"abcde");
        // A reader that ends early is an error, not a shorter body.
        let mut short = Incoming::new(Some(&spool), None);
        assert!(short.read_from(&mut &b"abc"[..], 4).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bodies_wait_for_room_and_never_for_each_other() {
        use std::thread;

        let piece = PIECE as usize;
        let data = vec![7; 2 * piece + 1];
        let reserve = Reserve::new(2 * PIECE, Duration::from_secs(10));
        let take = |reserve: &Arc<Reserve>, count: usize| {
            let mut body = Incoming::new(None, Some(reserve));
            body.read_from(&mut &data[..count], count as u64)
                .map(|()| body)
        };

        // A body that fills the reserve keeps the next one waiting until
        // its scan is over.
        let first = take(&reserve, 2 * piece).unwrap().finish().unwrap();
        let waiting = thread::scope(|scope| {
            let next = scope.spawn(|| {
                let started = Instant::now();
                take(&reserve, piece).map(|_| started.elapsed())
            });
            thread::sleep(Duration::from_millis(200));
            drop(first);
            next.join().unwrap().unwrap()
        });
        assert!(waiting >= Duration::from_millis(150), "{waiting:?}");

        // Two bodies still arriving that fill the reserve between them and
        // each want more: the later one gives way at once.
        let mut early = take(&reserve, piece).unwrap();
        let mut late = take(&reserve, piece).unwrap();
        thread::scope(|scope| {
            let data = &data;
            let early = scope.spawn(move || early.read_from(&mut &data[..piece], PIECE));
            thread::sleep(Duration::from_millis(100));
            let started = Instant::now();
            let refused = late.read_from(&mut &data[..piece], PIECE).unwrap_err();
            assert!(is_refused(&refused));
            assert!(started.elapsed() < Duration::from_secs(5));
            drop(late);
            early.join().unwrap().unwrap();
        });

        // More than there is, or room that does not come back in time.
        assert!(is_refused(&take(&reserve, 2 * piece + 1).unwrap_err()));
        let patient = Reserve::new(PIECE, Duration::from_millis(100));
        let kept = take(&patient, piece).unwrap().finish().unwrap();
        assert!(is_refused(&take(&patient, 1).unwrap_err()));
        drop(kept);
        assert!(take(&patient, piece).is_ok());
    }

    #[test]
    fn large_bodies_go_through_the_spool_and_leave_nothing() {
        let dir = scratch("large");
        let spool = Spool::open(&dir, 1).unwrap();
        // Nothing in the directory has a name.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

        let data: Vec<u8> = (0..MAP_FROM as usize + 4096)
            .map(|i| (i % 251) as u8)
            .collect();
        for round in 0..3 {
            let mut incoming = Incoming::new(Some(&spool), None);
            // In pieces, the first of them small.
            let mut reader = &data[..];
            for piece in [100, 70_000, data.len() as u64 - 70_100] {
                incoming.read_from(&mut reader, piece).unwrap();
            }
            let body = incoming.finish().unwrap();
            assert!(body.is_spooled(), "round {round}");
            assert_eq!(&*body, &data[..]);

            // The one file is taken: a second body stays in memory.
            let mut second = Incoming::new(Some(&spool), None);
            second.read_from(&mut &data[..], data.len() as u64).unwrap();
            assert!(!second.finish().unwrap().is_spooled());

            drop(body);
            let file = spool.take().unwrap();
            assert_eq!(file.metadata().unwrap().len(), 0);
            spool.give(file);
        }

        // Without a spool everything is in memory.
        let mut incoming = Incoming::new(None, None);
        incoming
            .read_from(&mut &data[..], data.len() as u64)
            .unwrap();
        assert!(!incoming.finish().unwrap().is_spooled());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
