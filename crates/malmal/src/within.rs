//! A time limit the caller can count on: [`Scanner::scan_within`].

use std::panic;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use crate::limits::LimitExceeded;
use crate::{Finding, Report, ScanHints, Scanner, Severity, detect};

/// The scans that [`Scanner::scan_within`] stopped waiting for and that
/// are still running, at most, for a scanner and its clones together. Past
/// it, files are refused at once with `limit.time` until one of them ends.
pub const MAX_OVERDUE: usize = 4;

/// Whether the scan has ended, and whether its caller has stopped waiting.
#[derive(Default)]
struct State {
    ended: bool,
    abandoned: bool,
}

impl Scanner {
    /// Scan a file, and answer within `wait` whatever the file does.
    ///
    /// The scan runs on a thread of its own. Its own limit,
    /// [`Limits::max_duration`](crate::Limits::max_duration), is checked
    /// between steps, so a step that does not end (a bug in a parser, say)
    /// would hold [`Scanner::scan_bytes`] for as long. Here the caller
    /// stops waiting after `wait` and gets a report with `limit.time`,
    /// which is never clean.
    ///
    /// A thread cannot be stopped from outside, so the scan goes on running
    /// in the background, holding its memory and a processor. At most
    /// [`MAX_OVERDUE`] such scans are left running; past that, every file
    /// is refused at once, also with `limit.time`, until one of them ends.
    /// [`Scanner::overdue`] counts them: a service that sees it above zero
    /// should be restarted when it can be. Choose `wait` well above
    /// `max_duration`, which is what ends nearly every slow scan.
    ///
    /// The data is shared with the thread, hence the [`Arc`]. A thread that
    /// cannot be started is answered as a scan that did not finish.
    pub fn scan_within(&self, data: Arc<[u8]>, hints: ScanHints<'_>, wait: Duration) -> Report {
        let scanner = self.clone();
        let filename = hints.filename.map(str::to_owned);
        let content_type = hints.content_type.map(str::to_owned);
        let shared = Arc::clone(&data);
        self.within(&data, wait, move || {
            let hints = ScanHints {
                filename: filename.as_deref(),
                content_type: content_type.as_deref(),
            };
            scanner.scan_bytes(&shared, hints)
        })
    }

    /// The scans [`Scanner::scan_within`] stopped waiting for that are still
    /// running, for this scanner and its clones.
    pub fn overdue(&self) -> usize {
        self.overdue.load(Ordering::Acquire)
    }

    /// Run `job` on a thread and wait for it up to `wait`.
    fn within(
        &self,
        data: &[u8],
        wait: Duration,
        job: impl FnOnce() -> Report + Send + 'static,
    ) -> Report {
        if self.overdue() >= MAX_OVERDUE {
            return self.unfinished(
                data,
                "refused at once: too many earlier scans are still running past their time",
            );
        }
        let state = Arc::new(Mutex::new(State::default()));
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread_state = Arc::clone(&state);
        let overdue = Arc::clone(&self.overdue);
        let spawned = thread::Builder::new()
            .name("malmal-scan".into())
            .spawn(move || {
                let report = job();
                let mut state = thread_state.lock().unwrap_or_else(PoisonError::into_inner);
                state.ended = true;
                if state.abandoned {
                    overdue.fetch_sub(1, Ordering::AcqRel);
                }
                // The caller may have stopped listening; that is fine.
                let _ = sender.send(report);
            });
        let Ok(handle) = spawned else {
            return self.unfinished(data, "no thread could be started for the scan");
        };
        match receiver.recv_timeout(wait) {
            Ok(report) => report,
            Err(RecvTimeoutError::Disconnected) => match handle.join() {
                // The job panicked: as `scan_bytes` would have, here.
                Err(payload) => panic::resume_unwind(payload),
                Ok(()) => self.unfinished(data, "the scan ended without a report"),
            },
            Err(RecvTimeoutError::Timeout) => {
                let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
                if state.ended {
                    // It ended as the wait did.
                    drop(state);
                    if let Ok(report) = receiver.recv() {
                        return report;
                    }
                    return self.unfinished(data, "the scan ended without a report");
                }
                state.abandoned = true;
                self.overdue.fetch_add(1, Ordering::AcqRel);
                self.unfinished(
                    data,
                    &format!(
                        "scan did not end within {} ms; it was left running",
                        wait.as_millis()
                    ),
                )
            }
        }
    }

    /// The report on a file whose scan did not end: `limit.time`, and only
    /// what can be told at once.
    fn unfinished(&self, data: &[u8], message: &str) -> Report {
        let mut findings = vec![Finding::new(
            LimitExceeded::Time.code(),
            Severity::Medium,
            message,
        )];
        let verdict = self.policy.apply(&mut findings);
        Report {
            verdict,
            detected_type: detect::detect(data),
            declared_types: Vec::new(),
            size: data.len() as u64,
            sha256: String::new(),
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Sender;
    use std::time::Instant;

    use super::*;
    use crate::Verdict;

    const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B";

    /// A job that runs until it is told to end.
    fn stuck(scanner: &Scanner) -> (impl FnOnce() -> Report + Send + 'static, Sender<()>) {
        let (release, wait) = mpsc::channel::<()>();
        let scanner = scanner.clone();
        let job = move || {
            let _ = wait.recv();
            scanner.scan_bytes(GIF, ScanHints::default())
        };
        (job, release)
    }

    #[test]
    fn a_scan_that_ends_in_time_is_its_own_report() {
        let scanner = Scanner::default();
        let report = scanner.scan_within(
            Arc::from(GIF),
            ScanHints {
                filename: Some("a.gif"),
                content_type: None,
            },
            Duration::from_secs(30),
        );
        assert_eq!(report.verdict, Verdict::Clean, "{report:?}");
        assert!(!report.sha256.is_empty());
        assert_eq!(report.declared_types, [crate::FileType::Gif]);
        assert_eq!(scanner.overdue(), 0);
    }

    #[test]
    fn a_scan_that_does_not_end_is_not_waited_for() {
        let scanner = Scanner::default();
        let mut releases = Vec::new();
        for _ in 0..MAX_OVERDUE {
            let (job, release) = stuck(&scanner);
            releases.push(release);
            let started = Instant::now();
            let report = scanner.within(GIF, Duration::from_millis(20), job);
            assert!(started.elapsed() < Duration::from_secs(5));
            assert_eq!(report.verdict, Verdict::Suspicious);
            assert!(report.has("limit.time"), "{report:?}");
            assert!(report.findings[0].message.contains("left running"));
            assert_eq!(report.detected_type, crate::FileType::Gif);
        }
        // The clone shares the count.
        let clone = scanner.clone();
        assert_eq!(clone.overdue(), MAX_OVERDUE);
        let report = clone.scan_within(
            Arc::from(GIF),
            ScanHints::default(),
            Duration::from_secs(30),
        );
        assert!(report.has("limit.time"));
        assert!(report.findings[0].message.contains("refused at once"));

        // Once they end, files are scanned again.
        drop(releases);
        let started = Instant::now();
        while scanner.overdue() > 0 {
            assert!(started.elapsed() < Duration::from_secs(10), "still overdue");
            thread::sleep(Duration::from_millis(5));
        }
        let report = scanner.scan_within(
            Arc::from(GIF),
            ScanHints::default(),
            Duration::from_secs(30),
        );
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    #[should_panic(expected = "a bug")]
    fn a_panic_reaches_the_caller() {
        Scanner::default().within(GIF, Duration::from_secs(30), || panic!("a bug"));
    }
}
