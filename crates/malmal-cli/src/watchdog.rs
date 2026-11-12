//! The last resort against a scan that does not end. The scanner checks its
//! own time limit between steps, and a step that never finishes never gets
//! to the check; a thread cannot be stopped from outside either. So a scan
//! still running long past its limit ends the process: the one reply that
//! cannot be taken for "clean", and a supervisor starts the daemon again.

use std::process;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// Exit status of a process its watchdog ended.
pub const EXIT_STATUS: i32 = 3;

#[derive(Debug, Default)]
struct State {
    next: u64,
    /// The scans in progress and when each has to be over.
    running: Vec<(u64, Instant)>,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    /// A panic elsewhere must not disarm the watchdog.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Default)]
pub struct Watchdog {
    limit: Option<Duration>,
    shared: Arc<Shared>,
}

/// One scan in progress; dropping it says the scan is over.
#[derive(Debug)]
pub struct Guard<'a> {
    watchdog: &'a Watchdog,
    id: u64,
}

impl Watchdog {
    /// A watchdog that ends the process, with a message that starts with
    /// `program`, once something it watches has run for `limit`. Without a
    /// limit it watches nothing.
    pub fn start(program: &'static str, limit: Option<Duration>) -> Self {
        let shared = Arc::new(Shared::default());
        if let Some(limit) = limit {
            let shared = Arc::clone(&shared);
            thread::spawn(move || wait(program, limit, &shared));
        }
        Self { limit, shared }
    }

    /// Start the clock on one scan.
    pub fn watch(&self) -> Guard<'_> {
        let mut state = self.shared.lock();
        let id = state.next;
        state.next += 1;
        if let Some(over) = self
            .limit
            .and_then(|limit| Instant::now().checked_add(limit))
        {
            state.running.push((id, over));
            self.shared.changed.notify_one();
        }
        Guard { watchdog: self, id }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let mut state = self.watchdog.shared.lock();
        state.running.retain(|(id, _)| *id != self.id);
    }
}

fn wait(program: &str, limit: Duration, shared: &Shared) {
    let mut state = shared.lock();
    loop {
        let earliest = state.running.iter().map(|(_, over)| *over).min();
        state = match earliest {
            None => shared
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner),
            Some(over) => {
                let left = over.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    eprintln!(
                        "{program}: a scan was still running after {} seconds; exiting",
                        limit.as_secs()
                    );
                    process::exit(EXIT_STATUS);
                }
                let waited = shared.changed.wait_timeout(state, left);
                waited.unwrap_or_else(PoisonError::into_inner).0
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run in a process of its own: the test starts itself over, and the
    /// copy with the variable set is the one that hangs.
    #[test]
    fn a_scan_that_does_not_end_ends_the_process() {
        const HANG: &str = "MALMAL_WATCHDOG_TEST_HANGS";
        if std::env::var_os(HANG).is_some() {
            let watchdog = Watchdog::start("test", Some(Duration::from_millis(50)));
            let _scan = watchdog.watch();
            thread::sleep(Duration::from_secs(60));
            return;
        }
        let name = "watchdog::tests::a_scan_that_does_not_end_ends_the_process";
        let started = Instant::now();
        let hung = process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(HANG, "1")
            .output()
            .unwrap();
        assert_eq!(hung.status.code(), Some(EXIT_STATUS));
        assert!(started.elapsed() < Duration::from_secs(30));
        let message = String::from_utf8_lossy(&hung.stderr);
        assert!(
            message.contains("test: a scan was still running"),
            "{message}"
        );
    }

    #[test]
    fn finished_scans_are_forgotten() {
        let watchdog = Watchdog::start("test", Some(Duration::from_millis(50)));
        for _ in 0..3 {
            let _scan = watchdog.watch();
        }
        let idle = Watchdog::default();
        let _scan = idle.watch();
        // Had a scan above still counted, the process would be gone by now.
        thread::sleep(Duration::from_millis(150));
        assert!(watchdog.shared.lock().running.is_empty());
        assert!(idle.shared.lock().running.is_empty());
    }
}
