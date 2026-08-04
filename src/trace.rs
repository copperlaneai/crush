//! Local, metadata-only diagnostic tracing.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

const TRACE_QUEUE_CAPACITY: usize = 256;
const TRACE_VALUE_CAPACITY: usize = 8;

pub(crate) struct Trace {
    sender: Option<SyncSender<TraceEvent>>,
    worker: Option<JoinHandle<()>>,
    started: Instant,
    dropped: Arc<AtomicU64>,
}

#[derive(Clone, Copy)]
struct TraceValue {
    key: &'static str,
    value: u64,
}

#[derive(Clone, Copy)]
struct TraceEvent {
    at_us: u64,
    name: &'static str,
    values: [Option<TraceValue>; TRACE_VALUE_CAPACITY],
}

impl TraceEvent {
    fn new(at_us: u64, name: &'static str, values: &[(&'static str, u64)]) -> Option<Self> {
        if values.len() > TRACE_VALUE_CAPACITY || !valid_label(name) {
            return None;
        }

        let mut stored_values = [None; TRACE_VALUE_CAPACITY];
        for (slot, &(key, value)) in stored_values.iter_mut().zip(values) {
            if !valid_label(key) {
                return None;
            }
            *slot = Some(TraceValue { key, value });
        }

        Some(Self {
            at_us,
            name,
            values: stored_values,
        })
    }
}

impl Trace {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trace destination must be a regular file",
            ));
        }
        // SAFETY: `geteuid` has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trace destination must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trace destination must not be accessible by group or other users",
            ));
        }
        Self::start(file)
    }

    fn start<W>(writer: W) -> io::Result<Self>
    where
        W: Write + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(TRACE_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let worker = thread::Builder::new()
            .name("crush-trace".to_owned())
            .spawn(move || trace_worker(writer, &receiver, &worker_dropped))?;

        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            started: Instant::now(),
            dropped,
        })
    }

    pub(crate) fn event(&self, name: &'static str, values: &[(&'static str, u64)]) {
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let Some(event) = TraceEvent::new(elapsed, name, values) else {
            increment_saturating(&self.dropped);
            return;
        };
        let Some(sender) = &self.sender else {
            return;
        };

        if matches!(sender.try_send(event), Err(TrySendError::Full(_))) {
            increment_saturating(&self.dropped);
        }
    }

    #[cfg(test)]
    fn close_and_join(mut self) {
        let _ = self.sender.take();
        if let Some(worker) = self.worker.take() {
            worker.join().expect("trace worker must not panic");
        }
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        // Disconnect the queue, but never join here: the writer may be blocked
        // in the kernel. Dropping a JoinHandle detaches the worker so terminal
        // cleanup and process teardown cannot wait on diagnostic I/O.
        let _ = self.sender.take();
        let _ = self.worker.take();
    }
}

fn trace_worker<W>(mut writer: W, receiver: &Receiver<TraceEvent>, dropped: &AtomicU64)
where
    W: Write,
{
    let mut last_at_us = 0;
    while let Ok(event) = receiver.recv() {
        last_at_us = event.at_us;
        if write_dropped(&mut writer, dropped, event.at_us).is_err()
            || write_event(&mut writer, event).is_err()
        {
            return;
        }
    }

    let _ = write_dropped(&mut writer, dropped, last_at_us);
    let _ = writer.flush();
}

fn write_dropped(writer: &mut impl Write, dropped: &AtomicU64, at_us: u64) -> io::Result<()> {
    let count = dropped.swap(0, Ordering::Relaxed);
    if count == 0 {
        return Ok(());
    }

    let event = TraceEvent::new(at_us, "trace_dropped", &[("count", count)])
        .expect("built-in trace labels are valid");
    write_event(writer, event)
}

fn write_event(writer: &mut impl Write, event: TraceEvent) -> io::Result<()> {
    let mut line = format!("{{\"at_us\":{},\"event\":\"{}\"", event.at_us, event.name);
    for value in event.values.into_iter().flatten() {
        let _ = write!(line, ",\"{}\":{}", value.key, value.value);
    }
    line.push_str("}\n");
    writer.write_all(line.as_bytes())
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn increment_saturating(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    struct GateWriter {
        contents: Arc<Mutex<Vec<u8>>>,
        entered: Option<mpsc::Sender<()>>,
        release: Option<mpsc::Receiver<()>>,
    }

    impl Write for GateWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
                self.release
                    .take()
                    .expect("release receiver is present")
                    .recv()
                    .expect("test releases blocked writer");
            }
            self.contents
                .lock()
                .expect("trace output lock is not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trace_contains_only_named_metadata() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("crush-trace-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let trace = Trace::open(&path).unwrap();
        trace.event("relay", &[("bytes", 42)]);
        trace.close_and_join();
        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().expect("one trace event");
        assert!(line.starts_with("{\"at_us\":"));
        assert!(line.contains("\"event\":\"relay\""));
        assert!(line.contains("\"bytes\":42"));
        assert!(line.ends_with('}'));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn full_queue_drops_without_waiting_for_the_writer() {
        let contents = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer = GateWriter {
            contents: Arc::clone(&contents),
            entered: Some(entered_tx),
            release: Some(release_rx),
        };
        let trace = Trace::start(writer).unwrap();

        trace.event("blocked", &[]);
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("trace writer entered its blocking write");
        for sequence in 0..TRACE_QUEUE_CAPACITY {
            trace.event("queued", &[("sequence", sequence as u64)]);
        }
        for _ in 0..5 {
            trace.event("overflow", &[]);
        }
        assert_eq!(trace.dropped.load(Ordering::Relaxed), 5);

        release_tx.send(()).unwrap();
        trace.close_and_join();
        let contents = contents.lock().expect("trace output lock is not poisoned");
        let output = std::str::from_utf8(&contents).unwrap();
        assert!(output.contains("\"event\":\"trace_dropped\""));
        assert!(output.contains("\"count\":5"));
    }

    #[test]
    fn trace_rejects_an_existing_file_with_broad_permissions() {
        let path = std::env::temp_dir().join(format!(
            "crush-trace-permissions-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"existing").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = Trace::open(&path)
            .err()
            .expect("broad mode must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_file(path);
    }
}
