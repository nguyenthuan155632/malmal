//! What the tests count of the work a scan does: the bytes read, and the
//! steps taken, by the loops whose length the file decides. A file made of
//! one structure repeated, each of which made such a loop read everything
//! after it, used to cost the square of its size; the tests that keep it
//! from happening again compare this count with the file, which no clock
//! or shared runner changes. Nothing is counted outside the tests.

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static DONE: Cell<u64> = const { Cell::new(0) };
}

/// `units` more bytes read, or steps taken.
#[inline(always)]
pub(crate) fn done(units: usize) {
    #[cfg(test)]
    DONE.with(|done| done.set(done.get().saturating_add(units as u64)));
    #[cfg(not(test))]
    let _ = units;
}

/// A search of `haystack` that stopped at `found`, if it found anything,
/// for something `needle` bytes long.
#[inline(always)]
pub(crate) fn searched(haystack: usize, found: Option<usize>, needle: usize) {
    done(found.map_or(haystack, |at| (at + needle).min(haystack)));
}

/// What `run` returns, and the work it took on this thread.
#[cfg(test)]
pub(crate) fn counted<T>(run: impl FnOnce() -> T) -> (T, u64) {
    let before = DONE.with(Cell::get);
    let value = run();
    (value, DONE.with(Cell::get) - before)
}
