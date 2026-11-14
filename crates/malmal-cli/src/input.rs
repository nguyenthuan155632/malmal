//! A file to scan, without a copy of it: the file is mapped, so that its
//! pages stay the kernel's, to drop and read again as memory allows. What a
//! scan of a large file costs in memory is then what the analysis keeps, not
//! the size of the file.
//!
//! The daemon is sent its files over a connection. With a [`Spool`] it
//! writes the large ones to files of its own and maps those, to the same
//! end.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

/// Below this a copy costs less than a mapping.
const MAP_FROM: u64 = 1 << 20;

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

/// A request body as it arrives: in memory while it is small, and in a file
/// of the spool from [`MAP_FROM`] bytes on, if there is a spool.
#[derive(Debug)]
pub struct Incoming<'s> {
    spool: Option<&'s Arc<Spool>>,
    memory: Vec<u8>,
    spooled: Option<Spooled>,
    length: u64,
}

impl<'s> Incoming<'s> {
    pub fn new(spool: Option<&'s Arc<Spool>>) -> Self {
        Self {
            spool,
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
    /// reader that ends before is an error.
    pub fn read_from(&mut self, reader: &mut impl Read, count: u64) -> io::Result<()> {
        let total = self.length.saturating_add(count);
        if self.spooled.is_none() && total >= MAP_FROM {
            // No file to be had means more requests at once than the spool
            // was opened for; the body stays in memory as it would have.
            let file = self.spool.and_then(|spool| Some((spool, spool.take()?)));
            if let Some((spool, mut file)) = file {
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
                let count = usize::try_from(count).map_err(|_| io::ErrorKind::OutOfMemory)?;
                let start = self.memory.len();
                if start == 0 {
                    // A body that comes in one piece gets its size and no
                    // more, in memory that is not touched until it is read
                    // into.
                    self.memory = vec![0; count];
                } else {
                    self.memory.resize(start + count, 0);
                }
                reader.read_exact(&mut self.memory[start..])?;
            }
        }
        self.length = total;
        Ok(())
    }

    /// The whole body, to scan.
    pub fn finish(self) -> io::Result<Body> {
        let Some(mut spooled) = self.spooled else {
            return Ok(Body::Memory(self.memory));
        };
        let Some(file) = spooled.file.as_mut() else {
            return Ok(Body::Memory(self.memory));
        };
        file.flush()?;
        // The file has no name and is this process's alone, which cuts it
        // short only once the mapping is gone.
        let mapped = usize::try_from(self.length)
            .ok()
            .and_then(|length| map(file, length));
        match mapped {
            Some(map) => {
                spooled.map = Some(map);
                Ok(Body::Spooled(spooled))
            }
            // Where the file cannot be mapped it is read back.
            None => {
                let mut memory = Vec::new();
                file.rewind()?;
                file.read_to_end(&mut memory)?;
                Ok(Body::Memory(memory))
            }
        }
    }
}

/// A request body, whole.
#[derive(Debug)]
pub enum Body {
    Memory(Vec<u8>),
    Spooled(Spooled),
}

impl Deref for Body {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Memory(data) => data,
            Self::Spooled(spooled) => spooled.map.as_deref().unwrap_or_default(),
        }
    }
}

/// A file of the spool with a body in it. Dropping it empties the file and
/// gives it back: no body is on the disk for longer than its request.
#[derive(Debug)]
pub struct Spooled {
    map: Option<memmap2::Mmap>,
    file: Option<File>,
    spool: Arc<Spool>,
}

impl Drop for Spooled {
    fn drop(&mut self) {
        // The mapping goes before the file is cut short under it.
        self.map = None;
        if let Some(file) = self.file.take() {
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
        let mut incoming = Incoming::new(Some(&spool));
        incoming.read_from(&mut &b"abc"[..], 3).unwrap();
        incoming.read_from(&mut &b"defgh"[..], 2).unwrap();
        assert_eq!(incoming.len(), 5);
        let body = incoming.finish().unwrap();
        assert!(matches!(body, Body::Memory(_)));
        assert_eq!(&*body, b"abcde");
        // A reader that ends early is an error, not a shorter body.
        let mut short = Incoming::new(Some(&spool));
        assert!(short.read_from(&mut &b"abc"[..], 4).is_err());
        std::fs::remove_dir_all(dir).unwrap();
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
            let mut incoming = Incoming::new(Some(&spool));
            // In pieces, the first of them small.
            let mut reader = &data[..];
            for piece in [100, 70_000, data.len() as u64 - 70_100] {
                incoming.read_from(&mut reader, piece).unwrap();
            }
            let body = incoming.finish().unwrap();
            assert!(matches!(body, Body::Spooled(_)), "round {round}");
            assert_eq!(&*body, &data[..]);

            // The one file is taken: a second body stays in memory.
            let mut second = Incoming::new(Some(&spool));
            second.read_from(&mut &data[..], data.len() as u64).unwrap();
            assert!(matches!(second.finish().unwrap(), Body::Memory(_)));

            drop(body);
            let file = spool.take().unwrap();
            assert_eq!(file.metadata().unwrap().len(), 0);
            spool.give(file);
        }

        // Without a spool everything is in memory.
        let mut incoming = Incoming::new(None);
        incoming
            .read_from(&mut &data[..], data.len() as u64)
            .unwrap();
        assert!(matches!(incoming.finish().unwrap(), Body::Memory(_)));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
