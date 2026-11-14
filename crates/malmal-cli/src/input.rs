//! A file to scan, without a copy of it: the file is mapped, so that its
//! pages stay the kernel's, to drop and read again as memory allows. What a
//! scan of a large file costs in memory is then what the analysis keeps, not
//! the size of the file.

use std::fs::File;
use std::io::{self, Read};
use std::ops::Deref;

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
