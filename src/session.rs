//! Top-level dispatch and interactive OpenSSH relay.

use std::collections::VecDeque;
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use signal_hook::consts::signal::{SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGWINCH};
use signal_hook::iterator::{Handle as SignalHandle, Signals};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Action, Config, Mode, Prediction, strip_crush_env};
use crate::invocation::classify_ssh_invocation;
use crate::prediction::{
    ConfirmationResult, ConfirmedEcho, EchoConfirmation, ExpectedEcho, InputEffect,
    PredictionEngine, TerminalTrust,
};
use crate::pty::{PhysicalOutput, PhysicalTerminal, PtyChild, exec_ssh};
use crate::render::OverlayRenderer;
use crate::shadow::{CursorSnapshot, OutputObservation, ShadowTerminal, TerminalSize};
use crate::trace::Trace;

const INTERNAL_ERROR: u8 = 125;
const CONFIG_ERROR: u8 = 2;
const INPUT_QUEUE_DEPTH: usize = 256;
const INPUT_OBSERVER_EVENTS_PER_TICK: usize = 4;
const INPUT_OBSERVER_BYTES_PER_TICK: usize = 4 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const CHILD_TERMINATION_GRACE: Duration = Duration::from_millis(500);
const CHILD_KILL_GRACE: Duration = Duration::from_millis(500);
const OUTPUT_SETTLEMENT_GRACE: Duration = Duration::from_millis(100);
const SHADOW_BACKLOG_LIMIT: usize = 256 * 1024;
const SHADOW_PARSE_BYTES_PER_TICK: usize = 16 * 1024;
const REMOTE_READ_SIZE: usize = 64 * 1024;
const OUTPUT_QUEUE_HIGH_WATER: usize = 256 * 1024;
const OUTPUT_QUEUE_LIMIT: usize = 512 * 1024;

struct QueuedOutput {
    physical: PhysicalOutput,
    chunks: VecDeque<OutputChunk>,
    pending_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputKind {
    Authoritative,
    Synthetic,
}

struct OutputChunk {
    kind: OutputKind,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl OutputChunk {
    fn new(kind: OutputKind, bytes: &[u8]) -> Self {
        Self {
            kind,
            bytes: Zeroizing::new(bytes.to_vec()),
            offset: 0,
        }
    }

    fn pending(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn pending_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn compact(&mut self) {
        if self.offset == 0 {
            return;
        }
        let remaining = self.pending_len();
        self.bytes.copy_within(self.offset.., 0);
        self.bytes[remaining..].zeroize();
        self.bytes.truncate(remaining);
        self.offset = 0;
    }
}

impl QueuedOutput {
    fn new(physical: PhysicalOutput) -> Self {
        Self {
            physical,
            chunks: VecDeque::new(),
            pending_len: 0,
        }
    }

    fn pending_len(&self) -> usize {
        self.pending_len
    }

    fn has_pending(&self) -> bool {
        self.pending_len() != 0
    }

    fn can_accept_remote(&self) -> bool {
        self.pending_len() < OUTPUT_QUEUE_HIGH_WATER
    }

    fn remote_read_gate_open(&self) -> bool {
        remote_read_gate_open(&self.chunks)
    }

    fn as_raw_fd(&self) -> libc::c_int {
        self.physical.as_raw_fd()
    }

    fn make_nonblocking(&mut self) -> io::Result<()> {
        self.physical.make_nonblocking()
    }

    fn restore(&mut self) -> io::Result<()> {
        self.physical.restore()
    }

    /// Drain as much as the physical terminal currently accepts. A full
    /// terminal is ordinary backpressure, not an error.
    fn drain_nonblocking(&mut self) -> io::Result<()> {
        drain_output_chunks(&mut self.physical, &mut self.chunks, &mut self.pending_len)
    }

    fn drain_nonblocking_until(&mut self, deadline: Instant) -> io::Result<bool> {
        drain_output_chunks_inner(
            &mut self.physical,
            &mut self.chunks,
            &mut self.pending_len,
            Some(deadline),
        )
    }

    fn enqueue(&mut self, kind: OutputKind, bytes: &[u8]) -> io::Result<()> {
        enqueue_output_chunk(&mut self.chunks, &mut self.pending_len, kind, bytes)
    }

    fn enqueue_authoritative(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.enqueue(OutputKind::Authoritative, bytes)
    }

    /// Discard speculative bytes that have not reached the terminal while
    /// retaining every authoritative byte in its original relative order.
    /// Synthetic rendering is deliberately made from independent one-byte
    /// operations, so dropping the unwritten suffix of a partially drained
    /// chunk cannot strand the terminal inside an escape sequence.
    fn discard_pending_synthetic(&mut self) {
        discard_pending_synthetic_chunks(&mut self.chunks, &mut self.pending_len);
    }
}

fn drain_output_chunks(
    physical: &mut impl Write,
    chunks: &mut VecDeque<OutputChunk>,
    pending_len: &mut usize,
) -> io::Result<()> {
    let _ = drain_output_chunks_inner(physical, chunks, pending_len, None)?;
    Ok(())
}

fn drain_output_chunks_inner(
    physical: &mut impl Write,
    chunks: &mut VecDeque<OutputChunk>,
    pending_len: &mut usize,
    deadline: Option<Instant>,
) -> io::Result<bool> {
    while let Some(front) = chunks.front() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(false);
        }
        match physical.write(front.pending()) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "physical terminal accepted no output",
                ));
            }
            Ok(count) => {
                let front = chunks
                    .front_mut()
                    .expect("the written output chunk remains queued");
                let end = front.offset.saturating_add(count).min(front.bytes.len());
                let consumed = end.saturating_sub(front.offset);
                front.bytes[front.offset..end].zeroize();
                front.offset = end;
                *pending_len = pending_len.saturating_sub(consumed);
                if front.offset == front.bytes.len() {
                    let _ = chunks.pop_front();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn enqueue_output_chunk(
    chunks: &mut VecDeque<OutputChunk>,
    pending_len: &mut usize,
    kind: OutputKind,
    bytes: &[u8],
) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if kind == OutputKind::Authoritative
        && chunks
            .iter()
            .any(|chunk| chunk.kind == OutputKind::Synthetic)
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "authoritative output cannot follow pending synthetic output",
        ));
    }
    if bytes.len() > OUTPUT_QUEUE_LIMIT.saturating_sub(*pending_len) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "physical output queue reached its hard limit",
        ));
    }

    if let Some(back) = chunks.back_mut().filter(|chunk| chunk.kind == kind) {
        back.compact();
        back.bytes.extend_from_slice(bytes);
    } else {
        chunks.push_back(OutputChunk::new(kind, bytes));
    }
    *pending_len = pending_len.saturating_add(bytes.len());
    Ok(())
}

fn remote_read_gate_open(chunks: &VecDeque<OutputChunk>) -> bool {
    chunks
        .iter()
        .all(|chunk| chunk.kind == OutputKind::Authoritative)
}

fn discard_pending_synthetic_chunks(chunks: &mut VecDeque<OutputChunk>, pending_len: &mut usize) {
    let mut retained = VecDeque::with_capacity(chunks.len());
    while let Some(mut chunk) = chunks.pop_front() {
        if chunk.kind == OutputKind::Synthetic {
            *pending_len = pending_len.saturating_sub(chunk.pending_len());
            chunk.bytes[chunk.offset..].zeroize();
        } else {
            retained.push_back(chunk);
        }
    }
    *chunks = retained;
}

impl Write for QueuedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.enqueue(OutputKind::Synthetic, bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct SessionDisplay {
    output: QueuedOutput,
    renderer: OverlayRenderer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputSettlement {
    Complete,
    TimedOut,
}

impl SessionDisplay {
    fn new(output: PhysicalOutput) -> Self {
        Self {
            output: QueuedOutput::new(output),
            renderer: OverlayRenderer::default(),
        }
    }

    fn write_remote(&mut self, remote: &[u8]) -> io::Result<()> {
        self.output.enqueue_authoritative(remote)
    }

    /// Prepare the physical terminal for authoritative PTY bytes. Remote input
    /// must remain unread until every speculative erase has reached stdout;
    /// otherwise lifecycle invalidation could discard an erase suffix while
    /// retaining authoritative bytes that assume the erase completed.
    fn prepare_remote_read(&mut self) -> io::Result<bool> {
        self.renderer.clear(&mut self.output)?;
        self.output.drain_nonblocking()?;
        Ok(self.output.remote_read_gate_open())
    }

    fn replace(&mut self, desired: &[u8]) -> io::Result<()> {
        self.renderer.replace(&mut self.output, desired)
    }

    fn clear(&mut self) -> io::Result<()> {
        self.renderer.clear(&mut self.output)
    }

    fn abandon_pending_synthetic(&mut self) {
        self.renderer.abandon();
        self.output.discard_pending_synthetic();
    }

    fn drain_nonblocking(&mut self) -> io::Result<()> {
        self.output.drain_nonblocking()
    }

    fn has_pending(&self) -> bool {
        self.output.has_pending()
    }

    fn can_accept_remote(&self) -> bool {
        self.output.can_accept_remote()
    }

    fn remote_read_gate_open(&self) -> bool {
        self.output.remote_read_gate_open()
    }

    fn pending_len(&self) -> usize {
        self.output.pending_len()
    }

    fn needs_synthetic_settlement(&self) -> bool {
        self.renderer.has_displayed_overlay() || !self.output.remote_read_gate_open()
    }

    /// Try to finish every queued frame before the parent shell takes ownership
    /// of the terminal. A permanently unwritable tty makes exact cleanup
    /// physically impossible, so the handoff is bounded and retains (but never
    /// reorders) authoritative bytes while abandoning stale synthetic suffixes.
    fn settle_for_suspend(&mut self) -> io::Result<OutputSettlement> {
        self.settle_with_final_clear(Instant::now() + OUTPUT_SETTLEMENT_GRACE)
    }

    /// A terminating session may abandon an authoritative-only backlog, but a
    /// partially applied speculative frame must be completed and erased first
    /// so termios restoration does not expose a ghost or displaced cursor.
    fn settle_synthetic_for_termination(&mut self) -> io::Result<OutputSettlement> {
        if !self.needs_synthetic_settlement() {
            return Ok(OutputSettlement::Complete);
        }
        self.settle_with_final_clear(Instant::now() + OUTPUT_SETTLEMENT_GRACE)
    }

    fn settle_with_final_clear(&mut self, deadline: Instant) -> io::Result<OutputSettlement> {
        let settled =
            self.enqueue_final_clear_until(deadline)? && self.drain_to_empty_until(deadline)?;
        if settled {
            Ok(OutputSettlement::Complete)
        } else {
            self.abandon_pending_synthetic();
            Ok(OutputSettlement::TimedOut)
        }
    }

    fn enqueue_final_clear_until(&mut self, deadline: Instant) -> io::Result<bool> {
        loop {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            match self.clear() {
                Ok(()) => return Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !self.make_bounded_output_progress(deadline)? {
                        return Ok(false);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn drain_to_empty_until(&mut self, deadline: Instant) -> io::Result<bool> {
        while self.has_pending() {
            if !self.make_bounded_output_progress(deadline)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn make_bounded_output_progress(&mut self, deadline: Instant) -> io::Result<bool> {
        let before = self.pending_len();
        if !self.output.drain_nonblocking_until(deadline)? {
            return Ok(false);
        }
        if self.pending_len() < before {
            return Ok(true);
        }
        if before == 0 {
            return Err(io::Error::other(
                "synthetic output could not be queued into an empty FIFO",
            ));
        }
        wait_for_output_writable_until(self.output_fd(), deadline)
    }

    fn output_fd(&self) -> libc::c_int {
        self.output.as_raw_fd()
    }

    fn make_output_nonblocking(&mut self) -> io::Result<()> {
        self.output.make_nonblocking()
    }

    fn restore_output(&mut self) -> io::Result<()> {
        self.output.restore()
    }
}

#[must_use]
pub fn run_from_env() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(Failure { code, message }) => {
            eprintln!("crush: {message}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<u8, Failure> {
    let config = Config::from_env().map_err(|error| Failure::config(error.to_string()))?;
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    if let Some(action) = config.action {
        return Ok(run_action(action, &config));
    }

    ensure_not_recursive(&config.ssh_program)?;
    let all_streams_are_ttys =
        io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal();
    let one_physical_tty = all_streams_are_ttys && same_terminal_device().unwrap_or(false);
    let local_tty = all_streams_are_ttys && one_physical_tty;
    let classification = classify_ssh_invocation(&args, local_tty);

    match config.mode {
        Mode::Passthrough => exec_or_fail(&config.ssh_program, &args),
        Mode::Auto if !classification.is_interactive() => exec_or_fail(&config.ssh_program, &args),
        Mode::Force if !all_streams_are_ttys => Err(Failure::config(
            "CRUSH_MODE=force requires stdin, stdout, and stderr to be terminals",
        )),
        Mode::Force if !one_physical_tty => Err(Failure::config(
            "CRUSH_MODE=force requires stdin, stdout, and stderr to use the same terminal",
        )),
        Mode::Force if !classification.is_interactive() => Err(Failure::config(format!(
            "CRUSH_MODE=force cannot wrap this invocation: {}",
            classification.reason
        ))),
        Mode::Auto | Mode::Force => run_interactive(&config, &args).map_err(Failure::internal),
    }
}

fn run_action(action: Action, config: &Config) -> u8 {
    match action {
        Action::Version => {
            println!("crush {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Action::Doctor => doctor(config),
    }
}

fn doctor(config: &Config) -> u8 {
    println!("crush {}", env!("CARGO_PKG_VERSION"));
    println!("ssh: {:?}", config.ssh_program);
    println!(
        "tty: stdin={} stdout={} stderr={}",
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        io::stderr().is_terminal()
    );
    println!("TERM: {:?}", env::var_os("TERM"));

    let mut command = Command::new(&config.ssh_program);
    command.arg("-V");
    strip_crush_env(&mut command);
    match command.output() {
        Ok(output) => {
            let version = if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            };
            print!("OpenSSH: {}", String::from_utf8_lossy(version));
            if !version.ends_with(b"\n") {
                println!();
            }
            u8::from(!output.status.success())
        }
        Err(error) => {
            println!("OpenSSH: unavailable ({error})");
            1
        }
    }
}

fn exec_or_fail(ssh_program: &OsStr, args: &[OsString]) -> Result<u8, Failure> {
    let error = exec_ssh(ssh_program, args);
    Err(Failure::internal(error))
}

enum SessionOutcome {
    Child(ExitStatus),
    Signal(libc::c_int),
}

#[allow(clippy::too_many_lines)]
fn run_interactive(config: &Config, args: &[OsString]) -> io::Result<u8> {
    let terminal = PhysicalTerminal::capture()?;
    let initial_size = terminal.winsize()?;
    // Install dispositions before raw mode is possible. `Signals` retains
    // arrivals until the relay thread starts after the child-side `fork`.
    let signals = Signals::new([SIGWINCH, SIGHUP, SIGTERM, SIGINT, SIGQUIT, SIGTSTP, SIGCONT])?;
    let prediction_enabled =
        config.prediction == Prediction::Auto && terminal_supports_prediction();
    let (input_tx, input_rx) = mpsc::sync_channel(INPUT_QUEUE_DEPTH);
    let (mut wake_reader, wake_writer) = std::os::unix::net::UnixStream::pair()?;
    wake_reader.set_nonblocking(true)?;
    wake_writer.set_nonblocking(true)?;
    let input_event_wake = wake_writer.try_clone()?;
    let (input_control_tx, input_control_rx) = mpsc::channel();
    let (input_control_reader, input_control_writer) = std::os::unix::net::UnixStream::pair()?;
    input_control_reader.set_nonblocking(true)?;
    input_control_writer.set_nonblocking(true)?;
    let overflowed = Arc::new(AtomicBool::new(false));
    let mut pty = PtyChild::spawn(&config.ssh_program, args, &terminal)?;
    // Trace owns a worker thread, so it must start only after the child-side
    // `fork`/`pre_exec` path has completed.
    let mut trace = match config.trace.as_deref().map(Trace::open).transpose() {
        Ok(trace) => trace,
        Err(error) => {
            terminate_child(&mut pty);
            return Err(error);
        }
    };
    let observe_input = prediction_enabled || trace.is_some();
    if let Some(trace) = &mut trace {
        trace.event("session_start", &[]);
    }

    if let Err(error) = pty.make_controller_nonblocking() {
        terminate_child(&mut pty);
        return Err(error);
    }

    let pty_writer = match pty.writer.try_clone() {
        Ok(writer) => writer,
        Err(error) => {
            terminate_child(&mut pty);
            return Err(error);
        }
    };
    let physical_input = match terminal.duplicate_input() {
        Ok(input) => input,
        Err(error) => {
            terminate_child(&mut pty);
            return Err(error);
        }
    };

    let input_worker = match spawn_input_relay(
        InputRelayFiles {
            physical_input,
            pty_writer,
        },
        observe_input.then_some(input_tx),
        input_event_wake,
        Arc::clone(&overflowed),
        input_control_reader,
        input_control_rx,
        prediction_enabled,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            terminate_child(&mut pty);
            return Err(error);
        }
    };
    let mut input_control = InputController {
        commands: input_control_tx,
        wake: input_control_writer,
        worker: Some(input_worker),
    };
    let mut signal_relay = match spawn_signal_relay(signals, wake_writer) {
        Ok(relay) => relay,
        Err(error) => {
            let _ = input_control.shutdown();
            terminate_child(&mut pty);
            return Err(error);
        }
    };

    let mut terminal_mode = match terminal.enter_raw() {
        Ok(guard) => guard,
        Err(error) => {
            let _ = input_control.shutdown();
            let _ = signal_relay.shutdown();
            terminate_child(&mut pty);
            return Err(error);
        }
    };
    let physical_output = match PhysicalOutput::capture_nonblocking() {
        Ok(output) => output,
        Err(error) => {
            let _ = input_control.shutdown();
            let _ = signal_relay.shutdown();
            let _ = terminal_mode.restore();
            terminate_child(&mut pty);
            return Err(error);
        }
    };

    let mut display = SessionDisplay::new(physical_output);
    // Move worker ownership into bindings created after the terminal guards.
    // On an unwind, signal and input workers are therefore stopped before the
    // physical output flags and termios guards restore shared terminal state.
    let mut session_input = input_control;
    let mut session_signals = signal_relay;
    let mut desired_overlay = Zeroizing::new(Vec::new());
    let mut terminal_size = TerminalSize::new(initial_size.ws_col, initial_size.ws_row);
    let mut shadow =
        prediction_enabled.then(|| ShadowTerminal::at_application_entry(terminal_size));
    let mut predictor = PredictionEngine::new();
    let mut echo_anchor = None;
    let mut rearm_after_output = true;
    let mut controller_closed = false;
    let mut child_status = None;
    let mut remote_buffer = Zeroizing::new(vec![0_u8; REMOTE_READ_SIZE].into_boxed_slice());
    let mut shadow_backlog = Zeroizing::new(Vec::with_capacity(SHADOW_BACKLOG_LIMIT));
    let mut shadow_lagged = false;
    let mut input_observer_pending = false;
    let mut input_resumed = false;
    let mut prediction_backpressured = false;
    let mut final_cleanup_queued = false;

    let session_result = (|| -> io::Result<SessionOutcome> {
        loop {
            let mut poll_fds = [
                libc::pollfd {
                    // A negative descriptor is ignored by `poll`. Keep
                    // servicing signals and child state after PTY EOF instead
                    // of entering an uninterruptible blocking `wait`.
                    fd: if controller_closed
                        || !input_resumed
                        || !display.can_accept_remote()
                        || !display.remote_read_gate_open()
                    {
                        -1
                    } else {
                        pty.controller.as_raw_fd()
                    },
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if display.has_pending() {
                        display.output_fd()
                    } else {
                        -1
                    },
                    events: libc::POLLOUT | libc::POLLHUP,
                    revents: 0,
                },
            ];
            let timeout = if !input_resumed
                || (final_cleanup_queued && !display.has_pending())
                || input_observer_pending
                || (prediction_enabled && !shadow_backlog.is_empty())
            {
                0
            } else {
                i32::try_from(POLL_INTERVAL.as_millis()).unwrap_or(25)
            };
            // SAFETY: `poll_fds` is a valid mutable array for the duration of the
            // call, and its exact element count is supplied.
            let poll_result = unsafe {
                libc::poll(
                    poll_fds.as_mut_ptr(),
                    libc::nfds_t::try_from(poll_fds.len()).unwrap_or(3),
                    timeout,
                )
            };
            if poll_result == -1 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }

            if poll_fds[1].revents & libc::POLLIN != 0 {
                drain_wake(&mut wake_reader)?;
            }
            // Lifecycle signals take priority over a simultaneously readable
            // PTY. In particular, once SIGWINCH is observable, no erase may be
            // emitted using coordinates from before the physical reflow.
            let pending_signals = session_signals.take_pending();
            let coalesced_signals = coalesced_signals(pending_signals);
            let mut lifecycle_transition = false;
            for signal in coalesced_signals.into_iter().flatten() {
                match signal {
                    SIGWINCH => {
                        // The terminal emulator has already reflowed by the time
                        // SIGWINCH arrives. An old-coordinate erase could destroy
                        // authoritative cells, so wait for the remote redraw.
                        let shadow_was_current = shadow_backlog.is_empty() && !shadow_lagged;
                        display.abandon_pending_synthetic();
                        desired_overlay.zeroize();
                        shadow_backlog.zeroize();
                        shadow_lagged = false;
                        echo_anchor = None;
                        let size = pty.resize_from(&terminal)?;
                        terminal_size = TerminalSize::new(size.ws_col, size.ws_row);
                        if let Some(shadow) = &mut shadow {
                            if shadow_was_current {
                                shadow.resize(terminal_size);
                            } else {
                                *shadow = ShadowTerminal::new(terminal_size);
                            }
                        }
                        if prediction_enabled {
                            let _ = predictor.set_terminal_trust(TerminalTrust::Unknown);
                        }
                        if let Some(trace) = &mut trace {
                            trace.event(
                                "resize",
                                &[
                                    ("columns", u64::from(size.ws_col)),
                                    ("rows", u64::from(size.ws_row)),
                                ],
                            );
                        }
                        lifecycle_transition = true;
                    }
                    SIGHUP | SIGTERM | SIGINT | SIGQUIT => {
                        session_input.pause()?;
                        let settlement = display.settle_synthetic_for_termination()?;
                        if settlement == OutputSettlement::TimedOut {
                            if let Some(trace) = &mut trace {
                                trace.event("output_settlement_timeout", &[]);
                            }
                        }
                        return Ok(SessionOutcome::Signal(signal));
                    }
                    SIGTSTP => {
                        let suspended_status = suspend_session(
                            &mut display,
                            &mut terminal_mode,
                            &pty,
                            &mut session_input,
                            false,
                            child_status.is_some(),
                        )?;
                        if let Some(status) = suspended_status {
                            child_status = Some(status);
                        }
                        terminal_size = invalidate_after_resume(
                            &terminal,
                            &pty,
                            shadow.as_mut(),
                            &mut predictor,
                            &mut desired_overlay,
                            &mut echo_anchor,
                        )?;
                        shadow_backlog.zeroize();
                        shadow_lagged = false;
                        finish_resume(&pty, &mut session_input);
                        lifecycle_transition = true;
                    }
                    SIGCONT => {
                        terminal_mode.make_raw()?;
                        display.make_output_nonblocking()?;
                        let _ = pty.signal_group(SIGCONT);
                        lifecycle_transition = true;
                    }
                    _ => {}
                }
            }
            if lifecycle_transition {
                continue;
            }

            if poll_fds[2].revents & (libc::POLLOUT | libc::POLLHUP) != 0 {
                display.drain_nonblocking()?;
            }
            if !input_resumed && !display.has_pending() {
                session_input.resume();
                input_resumed = true;
            }
            if final_cleanup_queued && !display.has_pending() {
                let status = child_status
                    .take()
                    .expect("final cleanup requires an observed child status");
                return Ok(SessionOutcome::Child(status));
            }

            if input_resumed && display.has_pending() && !prediction_backpressured {
                prediction_backpressured = true;
                if prediction_enabled {
                    let effect = predictor.authoritative_change();
                    desired_overlay.zeroize();
                    echo_anchor = None;
                    shadow_backlog.zeroize();
                    shadow_lagged = true;
                    // Preserve already queued bytes and append any required
                    // overlay erasure after them in the same FIFO.
                    display.clear()?;
                    if let Some(trace) = &mut trace {
                        trace.event(
                            "output_backpressure",
                            &[("rollback", effect.rollback_chars as u64)],
                        );
                    }
                }
            } else if !display.has_pending() {
                prediction_backpressured = false;
            }

            let remote_event =
                !controller_closed && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0;
            // Never consume PTY bytes until speculative overlay cleanup has
            // physically completed. This prevents authoritative bytes from
            // entering the queue behind a discardable synthetic suffix.
            let remote_ready = if remote_event {
                display.prepare_remote_read()?
            } else {
                false
            };
            // Once prepared, authoritative bytes win arbitration over
            // prediction, tracing, signals, and lifecycle bookkeeping.
            if remote_ready {
                match pty.controller.read(&mut remote_buffer) {
                    Ok(0) => controller_closed = true,
                    Ok(count) => {
                        let remote = &remote_buffer[..count];
                        display.write_remote(remote)?;
                        display.drain_nonblocking()?;
                        if let Some(trace) = &mut trace {
                            trace.event("remote_output", &[("bytes", count as u64)]);
                        }
                        if prediction_enabled {
                            if shadow_lagged
                                || shadow_backlog.len().saturating_add(count) > SHADOW_BACKLOG_LIMIT
                            {
                                if !shadow_lagged {
                                    let effect = predictor.authoritative_change();
                                    desired_overlay.zeroize();
                                    echo_anchor = None;
                                    shadow_backlog.zeroize();
                                    display.clear()?;
                                    if let Some(trace) = &mut trace {
                                        trace.event(
                                            "shadow_lag",
                                            &[("rollback", effect.rollback_chars as u64)],
                                        );
                                    }
                                }
                                shadow_lagged = true;
                            } else {
                                shadow_backlog.extend_from_slice(remote);
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    #[cfg(target_os = "linux")]
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                        controller_closed = true;
                    }
                    Err(error) => return Err(error),
                }
            }

            let observer_overflowed = overflowed.swap(false, Ordering::AcqRel);
            if observer_overflowed && prediction_enabled {
                let _ = predictor.set_terminal_trust(TerminalTrust::Tainted);
                shadow = Some(ShadowTerminal::new(terminal_size));
                desired_overlay.zeroize();
                echo_anchor = None;
                display.clear()?;
                if let Some(trace) = &mut trace {
                    trace.event("prediction_overflow", &[]);
                }
            }

            // Observation never delays forwarding input, and its bounded slice
            // prevents a full observer queue from starving the next output read.
            input_observer_pending = drain_input_events(
                &input_rx,
                prediction_enabled
                    && !observer_overflowed
                    && !display.has_pending()
                    && shadow_backlog.is_empty()
                    && !shadow_lagged,
                shadow.as_ref(),
                &mut predictor,
                &mut echo_anchor,
                &mut desired_overlay,
                &mut rearm_after_output,
                &mut display,
                &mut trace,
            )?;

            // Parse output only once the PTY is momentarily quiescent and all
            // causally earlier input observations have had their bounded turn.
            if prediction_enabled
                && !remote_ready
                && !input_observer_pending
                && !display.has_pending()
            {
                if shadow_lagged {
                    shadow = Some(ShadowTerminal::new(terminal_size));
                    shadow_lagged = false;
                } else if !shadow_backlog.is_empty() {
                    let shadow = shadow
                        .as_mut()
                        .expect("prediction requires a shadow terminal");
                    let parse_len = shadow_backlog.len().min(SHADOW_PARSE_BYTES_PER_TICK);
                    update_prediction_after_output(
                        shadow,
                        &shadow_backlog[..parse_len],
                        &mut predictor,
                        &mut echo_anchor,
                        &mut desired_overlay,
                        &mut rearm_after_output,
                        &mut display,
                    )?;
                    zeroize_prefix(&mut shadow_backlog, parse_len);
                }
            }

            if child_status.is_none() {
                match poll_child_state(&pty.child)? {
                    ChildState::Running | ChildState::Continued => {}
                    ChildState::Stopped => {
                        // OpenSSH implements its `~^Z` escape by stopping itself.
                        // Suspend the wrapper too so the invoking shell regains a
                        // cooked physical terminal, then resume SSH after `fg`.
                        let suspended_status = suspend_session(
                            &mut display,
                            &mut terminal_mode,
                            &pty,
                            &mut session_input,
                            true,
                            false,
                        )?;
                        if let Some(status) = suspended_status {
                            child_status = Some(status);
                        }
                        terminal_size = invalidate_after_resume(
                            &terminal,
                            &pty,
                            shadow.as_mut(),
                            &mut predictor,
                            &mut desired_overlay,
                            &mut echo_anchor,
                        )?;
                        shadow_backlog.zeroize();
                        shadow_lagged = false;
                        finish_resume(&pty, &mut session_input);
                    }
                    ChildState::Exited(status) => child_status = Some(status),
                }
            }

            if prediction_enabled && !display.has_pending() {
                if let Some(effect) = predictor.expire_stale(Instant::now()) {
                    desired_overlay.zeroize();
                    echo_anchor = None;
                    rearm_after_output = true;
                    display.clear()?;
                    if let Some(trace) = &mut trace {
                        trace.event(
                            "prediction_stale",
                            &[("rollback", effect.rollback_chars as u64)],
                        );
                    }
                }
            }

            if controller_closed && child_status.is_some() && !final_cleanup_queued {
                display.clear()?;
                final_cleanup_queued = true;
                display.drain_nonblocking()?;
            }
        }
    })();

    let input_cleanup = session_input.shutdown();
    match &session_result {
        Ok(SessionOutcome::Signal(signal)) => terminate_child_with_signal(&mut pty, *signal),
        Err(_) => terminate_child(&mut pty),
        Ok(SessionOutcome::Child(_)) => {}
    }
    let signal_cleanup = session_signals.shutdown();
    if !matches!(&session_result, Ok(SessionOutcome::Child(_)))
        && display.make_output_nonblocking().is_ok()
    {
        if display.needs_synthetic_settlement() {
            let _ = display.settle_synthetic_for_termination();
        } else {
            let _ = display.drain_nonblocking();
        }
    }
    let output_cleanup = display.restore_output();
    let terminal_cleanup = terminal_mode.restore();
    let cleanup_error = input_cleanup
        .err()
        .or_else(|| signal_cleanup.err())
        .or_else(|| output_cleanup.err())
        .or_else(|| terminal_cleanup.err());

    match session_result {
        Err(error) => Err(error),
        Ok(_) if cleanup_error.is_some() => Err(cleanup_error.expect("checked above")),
        Ok(SessionOutcome::Child(status)) => {
            if let Some(trace) = &mut trace {
                trace.event("session_end", &[]);
            }
            Ok(propagate_child_status(status))
        }
        Ok(SessionOutcome::Signal(signal)) => {
            let _ = signal_hook::low_level::emulate_default_handler(signal);
            Ok(signal_exit_code(signal))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn update_prediction_after_output(
    shadow: &mut ShadowTerminal,
    remote: &[u8],
    predictor: &mut PredictionEngine,
    echo_anchor: &mut Option<CursorSnapshot>,
    desired_overlay: &mut Vec<u8>,
    rearm_after_output: &mut bool,
    display: &mut SessionDisplay,
) -> io::Result<()> {
    let observation = shadow.advance(remote);
    reconcile_output(
        shadow,
        observation,
        predictor,
        echo_anchor,
        desired_overlay,
        rearm_after_output,
    );
    sync_prediction_trust(
        shadow,
        predictor,
        desired_overlay,
        echo_anchor,
        *rearm_after_output,
    );
    if shadow.can_overlay(desired_overlay.len()) {
        display.replace(desired_overlay)
    } else {
        desired_overlay.zeroize();
        display.clear()
    }
}

fn zeroize_prefix(bytes: &mut Vec<u8>, count: usize) {
    let count = count.min(bytes.len());
    let remaining = bytes.len() - count;
    bytes.copy_within(count.., 0);
    bytes[remaining..].zeroize();
    bytes.truncate(remaining);
}

#[allow(clippy::too_many_arguments)]
fn drain_input_events(
    input_rx: &Receiver<InputEvent>,
    prediction_enabled: bool,
    shadow: Option<&ShadowTerminal>,
    predictor: &mut PredictionEngine,
    echo_anchor: &mut Option<CursorSnapshot>,
    desired_overlay: &mut Vec<u8>,
    rearm_after_output: &mut bool,
    display: &mut SessionDisplay,
    trace: &mut Option<Trace>,
) -> io::Result<bool> {
    let mut events = 0;
    let mut bytes = 0;
    while events < INPUT_OBSERVER_EVENTS_PER_TICK && bytes < INPUT_OBSERVER_BYTES_PER_TICK {
        let Ok(event) = input_rx.try_recv() else {
            return Ok(false);
        };
        events += 1;
        bytes += event.byte_count;
        if let Some(trace) = trace {
            trace.event(
                "input_forwarded",
                &[
                    ("bytes", event.byte_count as u64),
                    (
                        "latency_us",
                        u64::try_from(event.forward_latency.as_micros()).unwrap_or(u64::MAX),
                    ),
                ],
            );
        }
        if !prediction_enabled {
            continue;
        }
        let shadow = shadow.expect("prediction requires a shadow terminal");
        let event_bytes = event
            .bytes
            .as_deref()
            .expect("prediction input events retain their payload");

        sync_prediction_trust(
            shadow,
            predictor,
            desired_overlay,
            echo_anchor,
            *rearm_after_output,
        );
        for &byte in event_bytes {
            let decision = predictor.observe_input(byte, event.forwarded_at);
            match decision.effect {
                InputEffect::ForwardOnly => {}
                InputEffect::Probe { .. } => {
                    *echo_anchor = Some(shadow.cursor());
                }
                InputEffect::DrawAppend { byte } => {
                    desired_overlay.push(byte);
                    if !shadow.can_overlay(desired_overlay.len()) {
                        let _ = predictor.authoritative_change();
                        desired_overlay.zeroize();
                        *echo_anchor = None;
                    } else if echo_anchor.is_none() {
                        *echo_anchor = Some(shadow.cursor());
                    }
                }
                InputEffect::DrawBackspace { .. } => {
                    let _ = desired_overlay.pop();
                }
                InputEffect::Suspend(_) => {
                    desired_overlay.zeroize();
                    *echo_anchor = None;
                    *rearm_after_output = false;
                }
            }
        }

        if shadow.can_overlay(desired_overlay.len()) {
            display.replace(desired_overlay)?;
        } else {
            desired_overlay.zeroize();
            display.clear()?;
        }
    }
    // Hitting either budget is treated as a possible backlog. A single extra
    // zero-time poll will clear this flag if the channel was exactly drained.
    Ok(true)
}

fn reconcile_output(
    shadow: &ShadowTerminal,
    observation: OutputObservation,
    predictor: &mut PredictionEngine,
    echo_anchor: &mut Option<CursorSnapshot>,
    desired_overlay: &mut Vec<u8>,
    rearm_after_output: &mut bool,
) {
    let mut matched_any = false;
    let mut expected_cursor = *echo_anchor;
    while let Some(anchor) = *echo_anchor {
        let Some(expected) = predictor.expected_echo() else {
            *echo_anchor = None;
            break;
        };

        let confirmation = match expected {
            ExpectedEcho::Printable { byte, .. }
                if shadow.confirmed_prefix(anchor, &[byte]) == 1 =>
            {
                Some(EchoConfirmation::Printable(byte))
            }
            ExpectedEcho::Backspace
                if observation.after.line == observation.before.line
                    && observation.after.column < observation.before.column =>
            {
                Some(EchoConfirmation::Backspace)
            }
            _ => None,
        };
        let Some(confirmation) = confirmation else {
            break;
        };

        match predictor.confirm_echo(confirmation, Instant::now()) {
            ConfirmationResult::Matched { echo, .. } => {
                matched_any = true;
                match echo {
                    ConfirmedEcho::Printable {
                        was_visible: true, ..
                    } => {
                        if !desired_overlay.is_empty() {
                            desired_overlay.remove(0);
                        }
                    }
                    ConfirmedEcho::Backspace => {
                        anchor_column_back(echo_anchor);
                        expected_cursor = *echo_anchor;
                        continue;
                    }
                    ConfirmedEcho::Probe | ConfirmedEcho::Printable { .. } => {}
                }
                if let Some(anchor) = echo_anchor {
                    anchor.column = anchor.column.saturating_add(1);
                    expected_cursor = Some(*anchor);
                }
            }
            ConfirmationResult::Mismatch(_) => {
                desired_overlay.zeroize();
                *echo_anchor = None;
                break;
            }
            ConfirmationResult::NothingPending => {
                *echo_anchor = None;
                break;
            }
        }
    }

    let cursor_changed = observation.before != observation.after;
    let unexpected_final_cursor = matched_any && expected_cursor != Some(observation.after);
    if observation.had_control || (!matched_any && cursor_changed) || unexpected_final_cursor {
        let _ = predictor.authoritative_change();
        desired_overlay.zeroize();
        *echo_anchor = None;
    }
    if predictor.pending_operations() == 0 {
        *echo_anchor = None;
    }
    *rearm_after_output = observation.safe_after;
}

fn anchor_column_back(anchor: &mut Option<CursorSnapshot>) {
    if let Some(anchor) = anchor {
        anchor.column = anchor.column.saturating_sub(1);
    }
}

fn sync_prediction_trust(
    shadow: &ShadowTerminal,
    predictor: &mut PredictionEngine,
    desired_overlay: &mut Vec<u8>,
    echo_anchor: &mut Option<CursorSnapshot>,
    allow_rearm: bool,
) {
    let trust = if shadow.can_overlay(1) {
        TerminalTrust::Safe
    } else if shadow.is_safe() {
        TerminalTrust::Unknown
    } else {
        TerminalTrust::Tainted
    };
    if predictor.set_terminal_trust(trust).is_some() {
        desired_overlay.zeroize();
        *echo_anchor = None;
    }
    if allow_rearm && trust == TerminalTrust::Safe {
        let _ = predictor.rearm_at_safe_anchor();
    }
}

enum InputControl {
    Pause(SyncSender<()>),
    Resume,
    Shutdown(SyncSender<()>),
}

struct InputController {
    commands: mpsc::Sender<InputControl>,
    wake: std::os::unix::net::UnixStream,
    worker: Option<JoinHandle<()>>,
}

struct InputRelayFiles {
    physical_input: std::fs::File,
    pty_writer: std::fs::File,
}

impl InputController {
    fn pause(&mut self) -> io::Result<()> {
        let (acknowledge, acknowledged) = mpsc::sync_channel(1);
        if self
            .commands
            .send(InputControl::Pause(acknowledge))
            .is_err()
        {
            return Ok(());
        }
        notify(&mut self.wake);
        acknowledged
            .recv_timeout(Duration::from_secs(1))
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
    }

    fn resume(&mut self) {
        if self.commands.send(InputControl::Resume).is_ok() {
            notify(&mut self.wake);
        }
    }

    fn shutdown(&mut self) -> io::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (acknowledge, acknowledged) = mpsc::sync_channel(1);
        let command_sent = self
            .commands
            .send(InputControl::Shutdown(acknowledge))
            .is_ok();
        notify(&mut self.wake);

        let acknowledgement_error = if command_sent {
            match acknowledged.recv_timeout(Duration::from_secs(1)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => None,
                Err(error @ mpsc::RecvTimeoutError::Timeout) => {
                    Some(io::Error::new(io::ErrorKind::TimedOut, error))
                }
            }
        } else {
            None
        };
        let join_result = worker
            .join()
            .map_err(|_| io::Error::other("input relay thread panicked"));
        if let Some(error) = acknowledgement_error {
            return Err(error);
        }
        join_result
    }
}

impl Drop for InputController {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[allow(clippy::too_many_lines)]
fn spawn_input_relay(
    files: InputRelayFiles,
    input_tx: Option<SyncSender<InputEvent>>,
    mut wake: std::os::unix::net::UnixStream,
    overflowed: Arc<AtomicBool>,
    mut control_wake: std::os::unix::net::UnixStream,
    controls: Receiver<InputControl>,
    capture_payload: bool,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("crush-input".into())
        .spawn(move || {
            let InputRelayFiles {
                physical_input: mut input,
                mut pty_writer,
            } = files;
            let mut buffer = [0_u8; 4096];
            let mut pending = Zeroizing::new(Vec::with_capacity(buffer.len()));
            let mut pending_offset = 0;
            let mut forwarding_started = None;
            let mut paused = true;
            let mut shutdown_acknowledgement = None;
            'relay: loop {
                let mut poll_fds = [
                    libc::pollfd {
                        fd: if !paused && pending.is_empty() {
                            input.as_raw_fd()
                        } else {
                            -1
                        },
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: if !paused && !pending.is_empty() {
                            pty_writer.as_raw_fd()
                        } else {
                            -1
                        },
                        events: libc::POLLOUT | libc::POLLHUP,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: control_wake.as_raw_fd(),
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                ];
                // SAFETY: `poll_fds` remains valid for the blocking call and
                // contains exactly the descriptor count supplied.
                let polled = unsafe {
                    libc::poll(
                        poll_fds.as_mut_ptr(),
                        libc::nfds_t::try_from(poll_fds.len()).unwrap_or(3),
                        -1,
                    )
                };
                if polled == -1 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }

                if poll_fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    if drain_wake(&mut control_wake).is_err() {
                        break;
                    }
                    loop {
                        match controls.try_recv() {
                            Ok(InputControl::Pause(acknowledge)) => {
                                paused = true;
                                let _ = acknowledge.send(());
                            }
                            Ok(InputControl::Resume) => paused = false,
                            Ok(InputControl::Shutdown(acknowledge)) => {
                                shutdown_acknowledgement = Some(acknowledge);
                                break 'relay;
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => break 'relay,
                        }
                    }
                }
                if paused {
                    continue;
                }

                if !pending.is_empty() && poll_fds[1].revents & (libc::POLLOUT | libc::POLLHUP) != 0
                {
                    match pty_writer.write(&pending[pending_offset..]) {
                        Ok(0) => break,
                        Ok(count) => {
                            pending_offset = pending_offset.saturating_add(count);
                            if pending_offset == pending.len() {
                                let completed_at = Instant::now();
                                if let Some(input_tx) = &input_tx {
                                    let forward_latency = forwarding_started
                                        .and_then(|started: Instant| {
                                            completed_at.checked_duration_since(started)
                                        })
                                        .unwrap_or_default();
                                    let event = InputEvent::forwarded(
                                        &pending,
                                        capture_payload,
                                        completed_at,
                                        forward_latency,
                                    );
                                    match input_tx.try_send(event) {
                                        Ok(()) => {}
                                        Err(
                                            TrySendError::Full(_) | TrySendError::Disconnected(_),
                                        ) => {
                                            overflowed.store(true, Ordering::Release);
                                        }
                                    }
                                    notify(&mut wake);
                                }
                                pending.zeroize();
                                pending.clear();
                                pending_offset = 0;
                                forwarding_started = None;
                            }
                        }
                        Err(error)
                            if error.kind() == io::ErrorKind::Interrupted
                                || error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                }
                if !pending.is_empty() || poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) == 0
                {
                    continue;
                }

                let count = match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error)
                        if error.kind() == io::ErrorKind::Interrupted
                            || error.kind() == io::ErrorKind::WouldBlock =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                pending.extend_from_slice(&buffer[..count]);
                buffer[..count].zeroize();
                pending_offset = 0;
                forwarding_started = Some(Instant::now());
            }
            pending.zeroize();
            buffer.zeroize();
            if let Some(acknowledge) = shutdown_acknowledgement {
                let _ = acknowledge.send(());
            }
        })
}

const SIGNAL_WINCH: u8 = 1 << 0;
const SIGNAL_HUP: u8 = 1 << 1;
const SIGNAL_TERM: u8 = 1 << 2;
const SIGNAL_INT: u8 = 1 << 3;
const SIGNAL_QUIT: u8 = 1 << 4;
const SIGNAL_TSTP: u8 = 1 << 5;
const SIGNAL_CONT: u8 = 1 << 6;

struct SignalRelay {
    pending: Arc<AtomicU8>,
    handle: Option<SignalHandle>,
    worker: Option<JoinHandle<()>>,
}

impl SignalRelay {
    fn take_pending(&self) -> u8 {
        self.pending.swap(0, Ordering::AcqRel)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.close();
        }
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| io::Error::other("signal relay thread panicked"))
    }
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn spawn_signal_relay(
    mut signals: Signals,
    mut wake: std::os::unix::net::UnixStream,
) -> io::Result<SignalRelay> {
    let pending = Arc::new(AtomicU8::new(0));
    let relay_pending = Arc::clone(&pending);
    let handle = signals.handle();
    let worker = thread::Builder::new()
        .name("crush-signals".into())
        .spawn(move || {
            for signal in signals.forever() {
                if let Some(bit) = signal_bit(signal) {
                    relay_pending.fetch_or(bit, Ordering::Release);
                    notify(&mut wake);
                }
            }
        })?;
    Ok(SignalRelay {
        pending,
        handle: Some(handle),
        worker: Some(worker),
    })
}

fn signal_bit(signal: libc::c_int) -> Option<u8> {
    match signal {
        SIGWINCH => Some(SIGNAL_WINCH),
        SIGHUP => Some(SIGNAL_HUP),
        SIGTERM => Some(SIGNAL_TERM),
        SIGINT => Some(SIGNAL_INT),
        SIGQUIT => Some(SIGNAL_QUIT),
        SIGTSTP => Some(SIGNAL_TSTP),
        SIGCONT => Some(SIGNAL_CONT),
        _ => None,
    }
}

fn termination_signal(pending: u8) -> Option<libc::c_int> {
    [
        (SIGNAL_HUP, SIGHUP),
        (SIGNAL_TERM, SIGTERM),
        (SIGNAL_INT, SIGINT),
        (SIGNAL_QUIT, SIGQUIT),
    ]
    .into_iter()
    .find_map(|(bit, signal)| (pending & bit != 0).then_some(signal))
}

fn coalesced_signals(pending: u8) -> [Option<libc::c_int>; 4] {
    let continued = pending & SIGNAL_CONT != 0;
    [
        // Resizing invalidates every previously safe overlay coordinate and
        // must precede termination/suspend cleanup when signals are coalesced.
        (pending & SIGNAL_WINCH != 0).then_some(SIGWINCH),
        termination_signal(pending),
        (pending & SIGNAL_TSTP != 0 && !continued).then_some(SIGTSTP),
        continued.then_some(SIGCONT),
    ]
}

fn terminate_child(pty: &mut PtyChild) {
    terminate_child_with_signal(pty, SIGTERM);
}

fn terminate_child_with_signal(pty: &mut PtyChild, signal: libc::c_int) {
    // Signal the process group even when the OpenSSH leader has already been
    // reaped: a descendant may still own the PTY. Continue a stopped group so
    // a catchable termination signal can actually be handled.
    let _ = pty.signal_group(signal);
    let _ = pty.signal_group(SIGCONT);
    if wait_for_process_group_exit(pty, CHILD_TERMINATION_GRACE) {
        return;
    }

    // A configured CRUSH_SSH executable is not assumed to cooperate with the
    // forwarded signal. Escalate after a bounded grace period so terminal
    // restoration and wrapper shutdown cannot hang indefinitely.
    let _ = pty.signal_group(libc::SIGKILL);
    let _ = wait_for_process_group_exit(pty, CHILD_KILL_GRACE);
}

fn wait_for_process_group_exit(pty: &mut PtyChild, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let _ = pty.child.try_wait();
        if let Ok(false) = pty.group_exists() {
            return true;
        }

        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn suspend_session(
    display: &mut SessionDisplay,
    terminal_mode: &mut crate::pty::TerminalModeGuard,
    pty: &PtyChild,
    input_control: &mut InputController,
    child_already_stopped: bool,
    child_exited: bool,
) -> io::Result<Option<ExitStatus>> {
    input_control.pause()?;
    display.settle_for_suspend()?;
    display.restore_output()?;
    terminal_mode.restore()?;
    let child_status = if child_already_stopped {
        None
    } else {
        // Consume the child transition before stopping ourselves, otherwise a
        // stale WIFSTOPPED event can trigger a second suspension after `fg`.
        match pty.signal_group(libc::SIGSTOP) {
            Ok(()) => {}
            Err(error) if child_exited && error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => return Err(error),
        }
        if child_exited {
            None
        } else {
            wait_for_child_stop(&pty.child)?
        }
    };

    // SIGTSTP is caught by signal-hook, so use the uncatchable stop signal to
    // yield the terminal to the parent shell. Execution resumes here on `fg`.
    // SAFETY: `getpid` has no preconditions and SIGSTOP targets this process.
    let result = unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    terminal_mode.make_raw()?;
    display.make_output_nonblocking()?;
    Ok(child_status)
}

fn finish_resume(pty: &PtyChild, input_control: &mut InputController) {
    // The leader may already be reaped while a surviving process-group member
    // still owns the PTY. Always continue the whole group best-effort.
    let _ = pty.signal_group(SIGCONT);
    input_control.resume();
}

fn wait_for_child_stop(child: &std::process::Child) -> io::Result<Option<ExitStatus>> {
    let pid = i32::try_from(child.id())
        .map_err(|_| io::Error::other("SSH child PID does not fit pid_t"))?;
    loop {
        let mut status = 0;
        // SAFETY: `status` is valid and the call waits only for the SSH leader
        // whose process group was just stopped.
        let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WUNTRACED) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if libc::WIFSTOPPED(status) {
            return Ok(None);
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(Some(ExitStatus::from_raw(status)));
        }
    }
}

fn invalidate_after_resume(
    terminal: &PhysicalTerminal,
    pty: &PtyChild,
    shadow: Option<&mut ShadowTerminal>,
    predictor: &mut PredictionEngine,
    desired_overlay: &mut Vec<u8>,
    echo_anchor: &mut Option<CursorSnapshot>,
) -> io::Result<TerminalSize> {
    desired_overlay.zeroize();
    *echo_anchor = None;
    let size = pty.resize_from(terminal)?;
    let size = TerminalSize::new(size.ws_col, size.ws_row);
    if let Some(shadow) = shadow {
        *shadow = ShadowTerminal::new(size);
    }
    let _ = predictor.set_terminal_trust(TerminalTrust::Unknown);
    Ok(size)
}

enum ChildState {
    Running,
    Stopped,
    Continued,
    Exited(ExitStatus),
}

fn poll_child_state(child: &std::process::Child) -> io::Result<ChildState> {
    let pid = i32::try_from(child.id())
        .map_err(|_| io::Error::other("SSH child PID does not fit pid_t"))?;
    let mut status = 0;
    // SAFETY: `status` is a valid output pointer and `pid` names only the SSH
    // child. WNOHANG prevents lifecycle observation from delaying the relay.
    let result = unsafe {
        libc::waitpid(
            pid,
            &raw mut status,
            libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED,
        )
    };
    if result == 0 {
        Ok(ChildState::Running)
    } else if result == -1 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(ChildState::Running)
        } else {
            Err(error)
        }
    } else if libc::WIFSTOPPED(status) {
        Ok(ChildState::Stopped)
    } else if libc::WIFCONTINUED(status) {
        Ok(ChildState::Continued)
    } else {
        Ok(ChildState::Exited(ExitStatus::from_raw(status)))
    }
}

fn notify(wake: &mut std::os::unix::net::UnixStream) {
    let _ = wake.write(&[1]);
}

fn drain_wake(wake: &mut std::os::unix::net::UnixStream) -> io::Result<()> {
    let mut bytes = [0_u8; 256];
    loop {
        match wake.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_output_writable_until(fd: libc::c_int, deadline: Instant) -> io::Result<bool> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(now);
        let timeout_ms = i32::try_from(
            remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0)),
        )
        .unwrap_or(i32::MAX);
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `poll_fd` is a valid single-element poll array for the
        // duration of the call. The monotonic deadline bounds lifecycle handoff
        // if the physical terminal never accepts another byte.
        let result = unsafe { libc::poll(&raw mut poll_fd, 1, timeout_ms) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Ok(false);
        }
        if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "physical terminal closed while settling speculative output",
            ));
        }
        if poll_fd.revents & libc::POLLOUT != 0 {
            return Ok(true);
        }
    }
}

fn exit_status_code(status: std::process::ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        u8::try_from(code).unwrap_or(u8::MAX)
    } else {
        128_u8.saturating_add(
            status
                .signal()
                .and_then(|signal| u8::try_from(signal).ok())
                .unwrap_or(0),
        )
    }
}

fn signal_exit_code(signal: libc::c_int) -> u8 {
    128_u8.saturating_add(u8::try_from(signal).unwrap_or(0))
}

fn propagate_child_status(status: ExitStatus) -> u8 {
    if let Some(signal) = status.signal() {
        // At this point the input/signal workers are joined and both output
        // flags and termios have been restored. Re-raising preserves wait(2)
        // semantics for callers that distinguish WIFSIGNALED from exit 128+N.
        let _ = signal_hook::low_level::emulate_default_handler(signal);
    }
    exit_status_code(status)
}

fn terminal_supports_prediction() -> bool {
    prediction_supported_for_term(env::var_os("TERM").as_deref())
}

fn prediction_supported_for_term(term: Option<&OsStr>) -> bool {
    // Prediction models VT/xterm semantics, not merely the presence of a TERM
    // name. Unknown/custom entries retain the exact raw relay without risking
    // an overlay based on incompatible cursor or erase behavior.
    const VT_FAMILIES: &[&[u8]] = &[
        b"xterm",
        b"screen",
        b"tmux",
        b"rxvt",
        b"alacritty",
        b"wezterm",
        b"foot",
        b"kitty",
        b"contour",
        b"ghostty",
        b"st",
        b"vt100",
        b"vt102",
        b"vt220",
        b"vt320",
        b"vt420",
        b"vt520",
    ];
    let Some(term) = term.map(OsStrExt::as_bytes) else {
        return false;
    };

    VT_FAMILIES.iter().any(|family| {
        term == *family
            || term
                .strip_prefix(*family)
                .is_some_and(|suffix| matches!(suffix.first(), Some(b'-' | b'.')))
    })
}

fn ensure_not_recursive(program: &OsStr) -> Result<(), Failure> {
    let current = env::current_exe()
        .ok()
        .and_then(|path| file_identity(&path));
    let resolved = resolve_program(program).and_then(|path| file_identity(&path));
    if current.is_some() && current == resolved {
        Err(Failure::config(
            "CRUSH_SSH resolves to crush itself; choose the real OpenSSH binary",
        ))
    } else {
        Ok(())
    }
}

fn file_identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

fn is_executable_file(path: &Path) -> bool {
    if !fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is NUL-terminated and remains alive for this call. Crush
    // is not a set-user-ID executable, so `access(X_OK)` mirrors the permission
    // decision made by the subsequent PATH-based `execvp` search.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

fn resolve_program(program: &OsStr) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.components().count() > 1 {
        return Some(path.to_path_buf());
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|directory| directory.join(program))
            .find(|candidate| is_executable_file(candidate))
    })
}

fn same_terminal_device() -> io::Result<bool> {
    fn identity(fd: libc::c_int) -> io::Result<(libc::dev_t, libc::ino_t)> {
        // SAFETY: a zeroed `stat` is valid as an output buffer for `fstat`.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is one of the process's standard descriptors and the
        // metadata pointer is valid for writes.
        if unsafe { libc::fstat(fd, &raw mut metadata) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok((metadata.st_rdev, metadata.st_ino))
        }
    }

    let stdin = identity(libc::STDIN_FILENO)?;
    Ok(stdin == identity(libc::STDOUT_FILENO)? && stdin == identity(libc::STDERR_FILENO)?)
}

#[derive(Debug)]
struct InputEvent {
    bytes: Option<Zeroizing<Vec<u8>>>,
    byte_count: usize,
    forwarded_at: Instant,
    forward_latency: Duration,
}

impl InputEvent {
    fn forwarded(
        bytes: &[u8],
        capture_payload: bool,
        forwarded_at: Instant,
        forward_latency: Duration,
    ) -> Self {
        Self {
            bytes: capture_payload.then(|| Zeroizing::new(bytes.to_vec())),
            byte_count: bytes.len(),
            forwarded_at,
            forward_latency,
        }
    }
}

#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn config(message: impl Into<String>) -> Self {
        Self {
            code: CONFIG_ERROR,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            code: INTERNAL_ERROR,
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[derive(Default)]
    struct BudgetWriter {
        accepted: Vec<u8>,
        budget: usize,
    }

    impl Write for BudgetWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let count = bytes.len().min(self.budget);
            self.accepted.extend_from_slice(&bytes[..count]);
            self.budget -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn resolves_programs_without_lossy_string_conversion() {
        assert_eq!(
            resolve_program(OsStr::new("/bin/sh")),
            Some(PathBuf::from("/bin/sh"))
        );
    }

    #[test]
    fn signal_exit_status_uses_shell_convention() {
        let status = ExitStatus::from_raw(SIGTERM);
        assert_eq!(exit_status_code(status), 143);
    }

    #[test]
    fn resize_precedes_coalesced_termination_and_suspend() {
        let pending = SIGNAL_TERM | SIGNAL_WINCH | SIGNAL_TSTP;
        let signals = coalesced_signals(pending)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(signals, [SIGWINCH, SIGTERM, SIGTSTP]);

        let resumed = coalesced_signals(SIGNAL_TSTP | SIGNAL_CONT)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            resumed,
            [SIGCONT],
            "a final continue must not self-deadlock"
        );
    }

    #[test]
    fn prediction_requires_a_capable_named_terminal() {
        assert!(!prediction_supported_for_term(None));
        assert!(!prediction_supported_for_term(Some(OsStr::new(""))));
        assert!(!prediction_supported_for_term(Some(OsStr::new("dumb"))));
        assert!(prediction_supported_for_term(Some(OsStr::new(
            "xterm-256color"
        ))));
        assert!(prediction_supported_for_term(Some(OsStr::new(
            "tmux-256color"
        ))));
        assert!(prediction_supported_for_term(Some(OsStr::new(
            "screen.xterm-256color"
        ))));
        assert!(!prediction_supported_for_term(Some(OsStr::new(
            "custom-terminal"
        ))));
    }

    #[test]
    fn trace_only_input_observation_does_not_copy_payload() {
        let event = InputEvent::forwarded(b"secret input", false, Instant::now(), Duration::ZERO);
        assert_eq!(event.byte_count, 12);
        assert!(event.bytes.is_none());
    }

    #[test]
    fn lifecycle_invalidation_keeps_only_ordered_authoritative_suffixes() {
        let mut partially_written = OutputChunk::new(OutputKind::Synthetic, b"stale");
        partially_written.bytes[..2].zeroize();
        partially_written.offset = 2;
        let mut chunks = VecDeque::from([
            partially_written,
            OutputChunk::new(OutputKind::Authoritative, b"one"),
            OutputChunk::new(OutputKind::Synthetic, b"xx"),
            OutputChunk::new(OutputKind::Authoritative, b"two"),
        ]);
        let mut pending_len = chunks.iter().map(OutputChunk::pending_len).sum();

        discard_pending_synthetic_chunks(&mut chunks, &mut pending_len);

        assert_eq!(pending_len, 6);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.kind == OutputKind::Authoritative)
        );
        let retained = chunks
            .iter()
            .flat_map(|chunk| chunk.pending().iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(retained, b"onetwo");
    }

    #[test]
    fn tiny_authoritative_writes_coalesce_without_losing_bytes() {
        let mut chunks = VecDeque::new();
        let mut pending_len = 0;
        for expected in 0..10_000 {
            let byte = [u8::try_from(expected % 251).unwrap()];
            enqueue_output_chunk(
                &mut chunks,
                &mut pending_len,
                OutputKind::Authoritative,
                &byte,
            )
            .unwrap();
        }

        assert_eq!(chunks.len(), 1);
        assert_eq!(pending_len, 10_000);
        let retained = chunks.front().expect("one coalesced chunk").pending();
        assert_eq!(retained.len(), 10_000);
        assert!(retained.iter().enumerate().all(|(index, byte)| {
            *byte == u8::try_from(index % 251).expect("modulo fits in u8")
        }));
    }

    #[test]
    fn coalescing_compacts_a_partially_written_authoritative_chunk() {
        let mut partial = OutputChunk::new(OutputKind::Authoritative, b"abcdef");
        partial.bytes[..3].zeroize();
        partial.offset = 3;
        let mut chunks = VecDeque::from([partial]);
        let mut pending_len = 3;

        enqueue_output_chunk(
            &mut chunks,
            &mut pending_len,
            OutputKind::Authoritative,
            b"ghi",
        )
        .unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(pending_len, 6);
        assert_eq!(chunks.front().unwrap().pending(), b"defghi");
    }

    #[test]
    fn authoritative_output_never_queues_behind_synthetic_output() {
        let mut chunks = VecDeque::from([
            OutputChunk::new(OutputKind::Authoritative, b"older"),
            OutputChunk::new(OutputKind::Synthetic, b"erase"),
        ]);
        let mut pending_len = 10;

        assert!(!remote_read_gate_open(&chunks));

        let error = enqueue_output_chunk(
            &mut chunks,
            &mut pending_len,
            OutputKind::Authoritative,
            b"remote",
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(pending_len, 10);
        assert_eq!(chunks.len(), 2);

        discard_pending_synthetic_chunks(&mut chunks, &mut pending_len);
        assert!(remote_read_gate_open(&chunks));
        enqueue_output_chunk(
            &mut chunks,
            &mut pending_len,
            OutputKind::Authoritative,
            b"remote",
        )
        .unwrap();
        assert_eq!(pending_len, 11);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks.front().unwrap().pending(), b"olderremote");
    }

    #[test]
    fn partial_synthetic_frame_completes_before_its_final_clear() {
        let mut renderer = OverlayRenderer::default();
        let mut draw = Vec::new();
        renderer.replace(&mut draw, b"ghost").unwrap();

        let mut chunks = VecDeque::new();
        let mut pending_len = 0;
        enqueue_output_chunk(&mut chunks, &mut pending_len, OutputKind::Synthetic, &draw).unwrap();

        let mut physical = BudgetWriter {
            accepted: Vec::new(),
            budget: 2,
        };
        drain_output_chunks(&mut physical, &mut chunks, &mut pending_len).unwrap();
        assert_eq!(physical.accepted, b"gh");
        assert_eq!(pending_len, 3);

        // Lifecycle cleanup is appended after the unwritten suffix. Completing
        // the FIFO therefore finishes the interrupted draw and then restores
        // the anchor, instead of abandoning the cursor after the `h`.
        let mut final_clear = Vec::new();
        renderer.clear(&mut final_clear).unwrap();
        enqueue_output_chunk(
            &mut chunks,
            &mut pending_len,
            OutputKind::Synthetic,
            &final_clear,
        )
        .unwrap();
        assert!(!renderer.has_displayed_overlay());

        physical.budget = 0;
        drain_output_chunks(&mut physical, &mut chunks, &mut pending_len).unwrap();
        assert_eq!(pending_len, 18);

        physical.budget = usize::MAX;
        drain_output_chunks(&mut physical, &mut chunks, &mut pending_len).unwrap();
        assert_eq!(pending_len, 0);
        assert!(chunks.is_empty());

        let expected = [
            b"ghost".as_slice(),
            b"\x08\x08\x08\x08\x08     \x08\x08\x08\x08\x08".as_slice(),
        ]
        .concat();
        assert_eq!(physical.accepted, expected);

        let mut cells = [b' '; 5];
        let mut cursor = 0_usize;
        for byte in physical.accepted {
            if byte == b'\x08' {
                cursor = cursor.saturating_sub(1);
            } else {
                assert!(cursor < cells.len());
                cells[cursor] = byte;
                cursor += 1;
            }
        }
        assert_eq!(cursor, 0);
        assert_eq!(cells, [b' '; 5]);
    }

    #[test]
    fn output_writability_wait_has_a_monotonic_deadline() {
        let mut raw_fds = [-1; 2];
        // SAFETY: `raw_fds` has room for both descriptors produced by pipe.
        assert_eq!(unsafe { libc::pipe(raw_fds.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` initialized each descriptor and ownership is moved
        // exactly once into these guards.
        let (reader, writer) = unsafe {
            (
                OwnedFd::from_raw_fd(raw_fds[0]),
                OwnedFd::from_raw_fd(raw_fds[1]),
            )
        };
        // SAFETY: F_GETFL/F_SETFL operate on the valid writer descriptor.
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_ne!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );

        let bytes = [0_u8; 4096];
        loop {
            // SAFETY: the byte array is readable for the supplied length and
            // the owned pipe writer stays valid for the duration of the call.
            let written =
                unsafe { libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            if written >= 0 {
                continue;
            }
            assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
            break;
        }

        let started = Instant::now();
        assert!(
            !wait_for_output_writable_until(
                writer.as_raw_fd(),
                started + Duration::from_millis(20)
            )
            .unwrap()
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a permanently full terminal must not block lifecycle handoff"
        );

        let (release_reader, reader_release) = mpsc::sync_channel(1);
        let reader_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let mut drained = [0_u8; 4096];
            // SAFETY: the owned reader and destination remain valid for the
            // duration of this one read.
            let count = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    drained.as_mut_ptr().cast(),
                    drained.len(),
                )
            };
            let _ = reader_release.recv();
            count
        });
        let became_writable = wait_for_output_writable_until(
            writer.as_raw_fd(),
            Instant::now() + Duration::from_millis(200),
        )
        .unwrap();
        let _ = release_reader.send(());
        assert!(
            became_writable,
            "settlement should resume as soon as stdout becomes writable"
        );
        assert!(reader_thread.join().unwrap() > 0);
    }
}
