//! Shared pieces of the `malmal` and `malmald` binaries.

#![deny(unsafe_code)]

#[global_allocator]
static ALLOCATOR: memory::Counting = memory::Counting;

pub mod icap;
pub mod input;
pub mod memory;
pub mod options;
pub mod sandbox;
pub mod serve;
#[cfg(feature = "tls")]
pub mod tls;
pub mod watchdog;
