//! A global allocator that counts what each thread holds, for the memory
//! limit of a scan: see [`malmal::MemoryLimit`].

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// The system allocator, counting.
pub struct Counting;

thread_local! {
    /// Bytes allocated on this thread less those freed on it. Memory freed
    /// on another thread than the one that allocated it, as a buffer handed
    /// over, makes one count high and the other low, never what one scan
    /// holds of its own.
    static HELD: Cell<i64> = const { Cell::new(0) };
}

fn count(bytes: i64) {
    // The thread's storage is gone while the thread ends; what is freed
    // then is not counted.
    let _ = HELD.try_with(|held| held.set(held.get().wrapping_add(bytes)));
}

/// What the calling thread holds now, from 2^63: a thread that has freed
/// more than it allocated is below it. Only the difference between two
/// readings means anything, and it is exact.
pub fn held() -> u64 {
    let held = HELD.try_with(Cell::get).unwrap_or(0);
    (held as u64) ^ (1 << 63)
}

// SAFETY: every method forwards to the system allocator with the arguments
// it was given and returns what that returned, so the contract of
// `GlobalAlloc` is the system allocator's. The counter is a thread-local
// cell initialized at compile time: touching it neither allocates nor
// panics, and a failed `try_with` is ignored.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            count(layout.size() as i64);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            count(layout.size() as i64);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(pointer, layout) };
        count(-(layout.size() as i64));
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as above.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            count(new_size as i64 - layout.size() as i64);
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_thread_holds_is_counted() {
        // Called as the library calls it, through a pointer: a call the
        // compiler sees into may be moved across an allocation, which it
        // takes to touch nothing else.
        let held = std::hint::black_box(held as fn() -> u64);
        let before = held();
        let block = std::hint::black_box(vec![0u8; 1 << 20]);
        let now = held();
        assert!(now >= before + (1 << 20), "before {before} now {now}");
        // Another thread's allocations are its own.
        std::thread::spawn(|| drop(std::hint::black_box(vec![0u8; 8 << 20])))
            .join()
            .unwrap();
        assert!(held() < before + (2 << 20));
        drop(block);
        assert!(held() < before + (1 << 20));
    }
}
