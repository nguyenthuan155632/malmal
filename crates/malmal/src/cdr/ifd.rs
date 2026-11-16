//! The directories of a TIFF file, read and changed in a copy of it.
//!
//! The `tiff` crate reads the first image of a file it takes as it is. To
//! read every page, and pages it refuses, a copy of the file is changed
//! here: the header points to the page, and entries are rewritten so that
//! the crate reads what is stored, which is then made sense of elsewhere.

/// How a file writes its numbers.
#[derive(Clone, Copy)]
pub(super) struct Form {
    little: bool,
    /// BigTIFF, with 8-byte counts and offsets.
    pub(super) wide: bool,
}

/// An entry of a directory.
#[derive(Clone, Copy, Debug)]
pub(super) struct Entry {
    /// Where the entry starts.
    at: usize,
    pub(super) tag: u16,
    pub(super) kind: u16,
    pub(super) count: u64,
}

pub(super) const SHORT: u16 = 3;
pub(super) const LONG: u16 = 4;
pub(super) const LONG8: u16 = 16;

/// Most entries a directory is read with.
const ENTRIES: usize = 4096;
/// Most pages a file is read with.
const PAGES: usize = 1 << 14;

impl Form {
    pub(super) fn of(data: &[u8]) -> Option<Self> {
        let little = match data.get(..2)? {
            b"II" => true,
            b"MM" => false,
            _ => return None,
        };
        let form = Self {
            little,
            wide: false,
        };
        let wide = match form.u16(data, 2)? {
            42 => false,
            43 => true,
            _ => return None,
        };
        Some(Self { little, wide })
    }

    pub(super) fn u16(self, data: &[u8], at: usize) -> Option<u16> {
        let bytes: [u8; 2] = data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    pub(super) fn u32(self, data: &[u8], at: usize) -> Option<u32> {
        let bytes: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    pub(super) fn u64(self, data: &[u8], at: usize) -> Option<u64> {
        let bytes: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    /// An offset or a count: 4 bytes, or 8 in a BigTIFF.
    fn word(self, data: &[u8], at: usize) -> Option<u64> {
        if self.wide {
            self.u64(data, at)
        } else {
            self.u32(data, at).map(u64::from)
        }
    }

    fn put(self, data: &mut [u8], at: usize, value: u64, size: usize) {
        let bytes = if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        let bytes = if self.little {
            &bytes[..size]
        } else {
            &bytes[8 - size..]
        };
        data[at..at + size].copy_from_slice(bytes);
    }

    /// Bytes an entry holds its values in.
    fn inline(self) -> usize {
        if self.wide { 8 } else { 4 }
    }

    /// The offsets of the directories of the main sequence, in order.
    pub(super) fn pages(self, data: &[u8]) -> Vec<usize> {
        let mut pages = Vec::new();
        let mut next = self.word(data, if self.wide { 8 } else { 4 });
        while let Some(offset) = next.and_then(|o| usize::try_from(o).ok()) {
            // A chain that comes back on itself ends there.
            if offset == 0 || pages.len() == PAGES || pages.contains(&offset) {
                break;
            }
            let Some((_, after)) = self.directory(data, offset) else {
                break;
            };
            pages.push(offset);
            next = after;
        }
        pages
    }

    /// The entries of the directory at `offset`, and the offset of the next.
    pub(super) fn directory(self, data: &[u8], offset: usize) -> Option<(Vec<Entry>, Option<u64>)> {
        let (count, first, size) = if self.wide {
            (self.u64(data, offset)? as usize, offset + 8, 20)
        } else {
            (self.u16(data, offset)? as usize, offset + 2, 12)
        };
        let count = count.min(ENTRIES);
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let at = first + index * size;
            entries.push(Entry {
                at,
                tag: self.u16(data, at)?,
                kind: self.u16(data, at + 2)?,
                count: self.word(data, at + 4)?,
            });
        }
        let next = self.word(data, first + count * size);
        Some((entries, next))
    }

    fn value_at(self, entry: &Entry) -> usize {
        entry.at + if self.wide { 12 } else { 8 }
    }

    /// The unsigned values of an entry of bytes, shorts, longs or long8s,
    /// if it has no more than `most`.
    pub(super) fn values(self, data: &[u8], entry: &Entry, most: usize) -> Option<Vec<u64>> {
        let size = match entry.kind {
            1 => 1,
            SHORT => 2,
            LONG => 4,
            LONG8 => 8,
            _ => return None,
        };
        let count = usize::try_from(entry.count).ok().filter(|&c| c <= most)?;
        let start = if size * count <= self.inline() {
            self.value_at(entry)
        } else {
            usize::try_from(self.word(data, self.value_at(entry))?).ok()?
        };
        (0..count)
            .map(|i| {
                let at = start.checked_add(i * size)?;
                match size {
                    1 => data.get(at).map(|&b| u64::from(b)),
                    2 => self.u16(data, at).map(u64::from),
                    4 => self.u32(data, at).map(u64::from),
                    _ => self.u64(data, at),
                }
            })
            .collect()
    }

    /// The first value of an entry.
    pub(super) fn value(self, data: &[u8], entry: &Entry) -> Option<u64> {
        self.values(data, entry, 1 << 20)?.first().copied()
    }

    /// Make the directory at `offset` the first of `data`.
    pub(super) fn point_to(self, data: &mut [u8], offset: usize) {
        if self.wide {
            self.put(data, 8, offset as u64, 8);
        } else {
            self.put(data, 4, offset as u64, 4);
        }
    }

    /// Give an entry another tag number, which hides it from a reader that
    /// looks for the one it had.
    pub(super) fn rename(self, data: &mut [u8], entry: &Entry, tag: u16) {
        self.put(data, entry.at, tag.into(), 2);
    }

    /// Replace the values of an entry with `values`, of `kind`: in the
    /// entry where they fit, after the end of `data` where they do not.
    pub(super) fn set(self, data: &mut Vec<u8>, entry: &Entry, kind: u16, values: &[u64]) {
        let size = match kind {
            SHORT => 2,
            LONG => 4,
            _ => 8,
        };
        self.put(data, entry.at + 2, kind.into(), 2);
        let count_size = if self.wide { 8 } else { 4 };
        self.put(data, entry.at + 4, values.len() as u64, count_size);
        let value_at = self.value_at(entry);
        let start = if size * values.len() <= self.inline() {
            data[value_at..value_at + self.inline()].fill(0);
            value_at
        } else {
            // Values start on a word.
            if data.len() % 2 == 1 {
                data.push(0);
            }
            let start = data.len();
            data.resize(start + size * values.len(), 0);
            self.put(data, value_at, start as u64, self.inline());
            start
        };
        for (i, &value) in values.iter().enumerate() {
            self.put(data, start + i * size, value, size);
        }
    }

    /// The kind of entry an offset into a file this large is written as.
    pub(super) fn offset_kind(self, length: usize) -> Option<u16> {
        if self.wide {
            Some(LONG8)
        } else {
            (length <= u32::MAX as usize).then_some(LONG)
        }
    }
}
