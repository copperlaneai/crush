use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix_openpty::rustix;
use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::{Winsize, tcsetwinsize};

use crate::config::PortRange;
use crate::config::strip_crush_env;
use crate::protocol::{
    MAX_FRAGMENTS, MAX_PLAINTEXT, PacketKind, SessionCrypto, encode_key, generate_key,
};
use crate::screen::{RemoteScreen, ScreenSize};

pub(crate) const BANNER_PREFIX: &str = "CRUSH/1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const FRAME_QUIET: Duration = Duration::from_millis(8);
const FRAME_INTERVAL: Duration = Duration::from_millis(16);
const CONGESTED_FRAME_INTERVAL: Duration = Duration::from_millis(33);
const FRAME_RETRY: Duration = Duration::from_millis(100);
const CURSOR_SETTLE_QUIET: Duration = Duration::from_millis(80);
const CURSOR_REPEAT_CONFIRMATIONS: u8 = 4;
// A PTY write does not prove that the resulting screen has arrived.
const ECHO_ACK_DELAY: Duration = Duration::from_millis(50);
const MAX_REORDERED_INPUTS: u64 = 64;

pub(crate) fn run_server(port_range: PortRange) -> io::Result<u8> {
    let socket = bind_udp(port_range)?;
    let port = socket.local_addr()?.port();
    let key = generate_key()?;
    let crypto = SessionCrypto::new(&key);
    println!("{BANNER_PREFIX} {port} {}", encode_key(&key));
    io::stdout().flush()?;
    if !detach_from_ssh()? {
        return Ok(0);
    }

    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let (hello, client_address) = receive_hello(&socket, &crypto)?;
    let (size, terminal_name) = parse_hello(&hello.payload)?;
    socket.set_read_timeout(None)?;
    socket.set_nonblocking(true)?;

    let pty = ServerPty::spawn(size, &terminal_name)?;
    pty.make_nonblocking()?;
    let mut screen = RemoteScreen::new(size);
    let mut session = ServerSession {
        socket,
        crypto,
        client_address,
        pty,
        screen: &mut screen,
        expected_input: 1,
        input_ack: 0,
        echo_ack: 0,
        pending_echo_acks: VecDeque::new(),
        reordered_inputs: BTreeMap::new(),
        latest_resize: 0,
        frame_id: 0,
        last_acked_frame: 0,
        last_frame_clipboard: None,
        last_frame: Vec::new(),
        last_frame_sent: Instant::now(),
        last_peer_packet: Instant::now(),
        dirty_since: Some(Instant::now()),
        last_output: Instant::now(),
        cursor_stabilizer: CursorStabilizer::default(),
        cursor_settle_pending: false,
    };
    session.run()
}

/// Leave the short-lived SSH bootstrap without exposing the session key in an
/// argument or environment variable. `run_server` has not started threads yet,
/// so the child can establish its own session before normal Rust work resumes.
fn detach_from_ssh() -> io::Result<bool> {
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    // SAFETY: the server is single-threaded here, owns no PTY child yet, and
    // handles both fork results without sharing mutable application state.
    let process = unsafe { libc::fork() };
    if process == -1 {
        return Err(io::Error::last_os_error());
    }
    if process != 0 {
        return Ok(false);
    }
    // SAFETY: the fork child is not a process-group leader and can establish a
    // new session before it opens any terminal device.
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: both descriptors are live and `dup2` atomically replaces the
        // inherited SSH channel descriptor with the already-open null device.
        if unsafe { libc::dup2(null.as_raw_fd(), descriptor) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(true)
}

fn bind_udp(port_range: PortRange) -> io::Result<UdpSocket> {
    let mut last_error = None;
    for port in port_range.first..=port_range.last {
        match UdpSocket::bind(("0.0.0.0", port)) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Crush UDP port range is empty",
        )
    }))
}

struct ServerSession<'a> {
    socket: UdpSocket,
    crypto: SessionCrypto,
    client_address: SocketAddr,
    pty: ServerPty,
    screen: &'a mut RemoteScreen,
    expected_input: u64,
    input_ack: u64,
    echo_ack: u64,
    pending_echo_acks: VecDeque<(u64, Instant)>,
    reordered_inputs: BTreeMap<u64, Vec<u8>>,
    latest_resize: u64,
    frame_id: u64,
    last_acked_frame: u64,
    last_frame_clipboard: Option<(u64, u64)>,
    last_frame: Vec<Vec<u8>>,
    last_frame_sent: Instant,
    last_peer_packet: Instant,
    dirty_since: Option<Instant>,
    last_output: Instant,
    cursor_stabilizer: CursorStabilizer,
    cursor_settle_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameReadiness {
    Progress,
    Settled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CursorState {
    line: u16,
    column: u16,
    visible: bool,
}

#[derive(Default)]
struct CursorStabilizer {
    presented: Option<CursorState>,
    candidate: Option<(CursorState, u8)>,
}

impl CursorStabilizer {
    fn compose(&mut self, frame: &mut crate::screen::WireFrame, readiness: FrameReadiness) -> bool {
        let current = CursorState::from(&*frame);
        if self.presented.is_none() || readiness == FrameReadiness::Settled {
            self.presented = Some(current);
            self.candidate = None;
            return false;
        }
        if self.presented == Some(current) {
            self.candidate = None;
            return false;
        }

        let repeats = match self.candidate {
            Some((candidate, repeats)) if candidate == current => repeats.saturating_add(1),
            _ => 1,
        };
        self.candidate = Some((current, repeats));
        if repeats >= CURSOR_REPEAT_CONFIRMATIONS {
            self.presented = Some(current);
            self.candidate = None;
            return false;
        }
        if let Some(presented) = self.presented {
            if presented.line != current.line {
                frame.prediction_stable = false;
            }
            presented.apply(frame);
        }
        true
    }
}

impl From<&crate::screen::WireFrame> for CursorState {
    fn from(frame: &crate::screen::WireFrame) -> Self {
        Self {
            line: frame.cursor_line,
            column: frame.cursor_column,
            visible: frame.modes & alacritty_terminal::term::TermMode::SHOW_CURSOR.bits() != 0,
        }
    }
}

impl CursorState {
    fn apply(self, frame: &mut crate::screen::WireFrame) {
        frame.cursor_line = self.line.min(frame.lines.saturating_sub(1));
        frame.cursor_column = self.column.min(frame.columns.saturating_sub(1));
        if self.visible {
            frame.modes |= alacritty_terminal::term::TermMode::SHOW_CURSOR.bits();
        } else {
            frame.modes &= !alacritty_terminal::term::TermMode::SHOW_CURSOR.bits();
        }
    }
}

impl ServerSession<'_> {
    fn run(&mut self) -> io::Result<u8> {
        let mut output = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            if self.receive_packets()? {
                return Ok(0);
            }
            let mut saw_output = false;
            loop {
                match self.pty.controller.read(&mut output) {
                    Ok(0) => break,
                    Ok(count) => {
                        self.screen.advance(&output[..count]);
                        let replies = self.screen.take_pty_writes();
                        if !replies.is_empty() {
                            self.pty.write_all(&replies)?;
                        }
                        saw_output = true;
                        self.last_output = Instant::now();
                        self.dirty_since.get_or_insert(self.last_output);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => return Err(error),
                }
            }

            let now = Instant::now();
            let _ = self.screen.finish_expired_synchronized_update(now);
            self.advance_echo_ack(now);
            if let Some(readiness) = self.frame_readiness(now) {
                self.cursor_settle_pending = self.send_frame(readiness)?;
                self.dirty_since = None;
            } else if !self.last_frame.is_empty()
                && self.last_acked_frame < self.frame_id
                && now.duration_since(self.last_frame_sent) >= FRAME_RETRY
            {
                self.resend_latest_frame()?;
            }

            if let Some(status) = self.pty.child.try_wait()? {
                if saw_output || self.dirty_since.is_some() {
                    self.screen.finish_synchronized_update();
                    let _ = self.send_frame(FrameReadiness::Settled)?;
                }
                let code = exit_status_code(status);
                self.send_close(code);
                return Ok(code);
            }
            if now.duration_since(self.last_peer_packet) >= IDLE_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Crush client was silent for ten minutes",
                ));
            }

            let timeout = self.next_timeout(now);
            poll_readable(
                self.socket.as_raw_fd(),
                self.pty.controller.as_raw_fd(),
                timeout,
            )?;
        }
    }

    fn receive_packets(&mut self) -> io::Result<bool> {
        let mut datagram = [0_u8; 1200];
        loop {
            let (count, address) = match self.socket.recv_from(&mut datagram) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            };
            let Ok(packet) = self.crypto.open(&datagram[..count]) else {
                continue;
            };
            self.client_address = address;
            self.last_peer_packet = Instant::now();
            match packet.kind {
                PacketKind::Input => self.accept_input(packet.sequence, &packet.payload)?,
                PacketKind::Resize => self.accept_resize(packet.sequence, &packet.payload)?,
                PacketKind::FrameAck => {
                    self.last_acked_frame = self.last_acked_frame.max(packet.sequence);
                    if let Some((frame_id, clipboard_id)) = self.last_frame_clipboard {
                        if packet.sequence >= frame_id {
                            self.screen.acknowledge_clipboard(clipboard_id);
                            self.last_frame_clipboard = None;
                        }
                    }
                }
                PacketKind::End => {
                    self.send_close(0);
                    return Ok(true);
                }
                PacketKind::Ping => self.send_pong(packet.sequence),
                PacketKind::Hello | PacketKind::Frame | PacketKind::Close | PacketKind::Pong => {}
            }
        }
    }

    fn accept_input(&mut self, sequence: u64, bytes: &[u8]) -> io::Result<()> {
        if sequence < self.expected_input {
            return Ok(());
        }
        if sequence > self.expected_input.saturating_add(MAX_REORDERED_INPUTS) {
            return Ok(());
        }
        self.reordered_inputs
            .entry(sequence)
            .or_insert_with(|| bytes.to_vec());
        let previous_ack = self.input_ack;
        while let Some(bytes) = self.reordered_inputs.remove(&self.expected_input) {
            self.pty.write_all(&bytes)?;
            self.input_ack = self.expected_input;
            self.pending_echo_acks
                .push_back((self.expected_input, Instant::now()));
            self.expected_input = self.expected_input.saturating_add(1);
        }
        if self.input_ack != previous_ack {
            self.dirty_since.get_or_insert(Instant::now());
        }
        Ok(())
    }

    fn advance_echo_ack(&mut self, now: Instant) {
        let mut advanced = false;
        while self
            .pending_echo_acks
            .front()
            .is_some_and(|(_, accepted)| now.duration_since(*accepted) >= ECHO_ACK_DELAY)
        {
            let (sequence, _) = self
                .pending_echo_acks
                .pop_front()
                .expect("eligible echo acknowledgement remains queued");
            self.echo_ack = self.echo_ack.max(sequence);
            advanced = true;
        }
        if advanced {
            self.dirty_since.get_or_insert(now);
        }
    }

    fn accept_resize(&mut self, sequence: u64, payload: &[u8]) -> io::Result<()> {
        if sequence <= self.latest_resize || payload.len() != 4 {
            return Ok(());
        }
        let columns = u16::from_be_bytes(payload[..2].try_into().expect("resize width"));
        let lines = u16::from_be_bytes(payload[2..].try_into().expect("resize height"));
        let size = ScreenSize::checked(columns, lines)?;
        self.pty.resize(size)?;
        self.screen.resize(size);
        self.latest_resize = sequence;
        self.dirty_since = Some(Instant::now());
        Ok(())
    }

    fn frame_readiness(&self, now: Instant) -> Option<FrameReadiness> {
        if self.screen.synchronized_update_pending() {
            return None;
        }
        let output_quiet = now.duration_since(self.last_output);
        if (self.dirty_since.is_some() || self.cursor_settle_pending)
            && output_quiet >= CURSOR_SETTLE_QUIET
        {
            return Some(FrameReadiness::Settled);
        }
        let dirty_since = self.dirty_since?;
        let congested = self.frame_id.saturating_sub(self.last_acked_frame) > 3;
        let interval = if congested {
            CONGESTED_FRAME_INTERVAL
        } else {
            FRAME_INTERVAL
        };
        if output_quiet >= FRAME_QUIET || now.duration_since(dirty_since) >= interval {
            Some(FrameReadiness::Progress)
        } else {
            None
        }
    }

    fn send_frame(&mut self, readiness: FrameReadiness) -> io::Result<bool> {
        self.frame_id = self.frame_id.saturating_add(1);
        let mut frame = self.screen.snapshot(self.input_ack, self.echo_ack);
        let cursor_settle_pending = self.cursor_stabilizer.compose(&mut frame, readiness);
        self.last_frame_clipboard = frame
            .clipboard
            .as_ref()
            .map(|clipboard| (self.frame_id, clipboard.id));
        let compressed = frame.encode_compressed()?;
        self.last_frame = seal_frame(&self.crypto, self.frame_id, &compressed)?;
        self.resend_latest_frame()?;
        Ok(cursor_settle_pending)
    }

    fn resend_latest_frame(&mut self) -> io::Result<()> {
        for datagram in &self.last_frame {
            match self.socket.send_to(datagram, self.client_address) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.last_frame_sent = Instant::now();
        Ok(())
    }

    fn send_close(&self, code: u8) {
        if let Ok(datagram) = self.crypto.seal(
            PacketKind::Close,
            self.frame_id.saturating_add(1),
            0,
            1,
            &[code],
        ) {
            for _ in 0..3 {
                let _ = self.socket.send_to(&datagram, self.client_address);
            }
        }
    }

    fn send_pong(&self, sequence: u64) {
        if let Ok(datagram) = self.crypto.seal(PacketKind::Pong, sequence, 0, 1, &[]) {
            let _ = self.socket.send_to(&datagram, self.client_address);
        }
    }

    fn next_timeout(&self, now: Instant) -> Duration {
        let frame = self.dirty_since.map_or(FRAME_RETRY, |dirty| {
            FRAME_INTERVAL.saturating_sub(now.duration_since(dirty))
        });
        let echo = self
            .pending_echo_acks
            .front()
            .map_or(FRAME_RETRY, |(_, accepted)| {
                ECHO_ACK_DELAY.saturating_sub(now.duration_since(*accepted))
            });
        let cursor = self
            .cursor_settle_pending
            .then_some(self.last_output)
            .map_or(FRAME_RETRY, |last_output| {
                CURSOR_SETTLE_QUIET.saturating_sub(now.duration_since(last_output))
            });
        frame.min(echo).min(cursor).min(Duration::from_millis(25))
    }
}

fn receive_hello(
    socket: &UdpSocket,
    crypto: &SessionCrypto,
) -> io::Result<(crate::protocol::Packet, SocketAddr)> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut datagram = [0_u8; 1200];
    loop {
        match socket.recv_from(&mut datagram) {
            Ok((count, address)) => {
                if let Ok(packet) = crypto.open(&datagram[..count]) {
                    if packet.kind == PacketKind::Hello {
                        return Ok((packet, address));
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for Crush client handshake",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn parse_hello(payload: &[u8]) -> io::Result<(ScreenSize, String)> {
    if payload.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Crush hello packet is truncated",
        ));
    }
    let columns = u16::from_be_bytes(payload[..2].try_into().expect("hello width"));
    let lines = u16::from_be_bytes(payload[2..4].try_into().expect("hello height"));
    let term_len = usize::from(payload[4]);
    if payload.len() != 5 + term_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Crush hello terminal name is malformed",
        ));
    }
    let terminal = std::str::from_utf8(&payload[5..])
        .ok()
        .filter(|term| {
            !term.is_empty()
                && term
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .unwrap_or("xterm-256color")
        .to_owned();
    Ok((ScreenSize::checked(columns, lines)?, terminal))
}

fn seal_frame(crypto: &SessionCrypto, sequence: u64, frame: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let count = frame.len().div_ceil(MAX_PLAINTEXT);
    let fragments = u16::try_from(count.max(1)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed framebuffer has too many fragments",
        )
    })?;
    if fragments > MAX_FRAGMENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed framebuffer exceeds Crush's datagram window",
        ));
    }
    let mut datagrams = Vec::with_capacity(usize::from(fragments));
    if frame.is_empty() {
        datagrams.push(crypto.seal(PacketKind::Frame, sequence, 0, 1, &[])?);
    } else {
        for (fragment, payload) in frame.chunks(MAX_PLAINTEXT).enumerate() {
            datagrams.push(crypto.seal(
                PacketKind::Frame,
                sequence,
                u16::try_from(fragment).expect("bounded frame fragment"),
                fragments,
                payload,
            )?);
        }
    }
    Ok(datagrams)
}

struct ServerPty {
    controller: File,
    child: Child,
}

impl ServerPty {
    fn spawn(size: ScreenSize, terminal: &str) -> io::Result<Self> {
        let winsize = Winsize {
            ws_row: u16::try_from(size.lines).unwrap_or(u16::MAX),
            ws_col: u16::try_from(size.columns).unwrap_or(u16::MAX),
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pair = rustix_openpty::openpty(None, Some(&winsize)).map_err(errno_to_io)?;
        let stdin = dup(&pair.user).map_err(errno_to_io)?;
        let stdout = dup(&pair.user).map_err(errno_to_io)?;
        let stderr = pair.user;
        let shell = env::var_os("SHELL").unwrap_or_else(|| OsString::from("/bin/sh"));
        let mut command = Command::new(shell);
        command.arg("-l");
        command.env("TERM", terminal);
        command.env("COLORTERM", "truecolor");
        command.env("CRUSH_SESSION", "1");
        command.stdin(Stdio::from(File::from(stdin)));
        command.stdout(Stdio::from(File::from(stdout)));
        command.stderr(Stdio::from(File::from(stderr)));
        strip_crush_env(&mut command);
        unsafe {
            command.pre_exec(|| {
                // SAFETY: only async-signal-safe process/session syscalls run
                // after fork and before exec.
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                #[allow(clippy::cast_lossless)]
                let request = libc::TIOCSCTTY as _;
                if libc::ioctl(libc::STDIN_FILENO, request, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Self {
            controller: File::from(pair.controller),
            child,
        })
    }

    fn make_nonblocking(&self) -> io::Result<()> {
        let fd = self.controller.as_raw_fd();
        // SAFETY: fcntl reads and updates flags for a live PTY descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor remains owned by `self` for this call.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.controller.write(bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "remote PTY closed",
                    ));
                }
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    poll_one(
                        self.controller.as_raw_fd(),
                        libc::POLLOUT,
                        Duration::from_secs(1),
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn resize(&self, size: ScreenSize) -> io::Result<()> {
        tcsetwinsize(
            self.controller.as_fd(),
            Winsize {
                ws_row: u16::try_from(size.lines).unwrap_or(u16::MAX),
                ws_col: u16::try_from(size.columns).unwrap_or(u16::MAX),
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(errno_to_io)
    }
}

impl Drop for ServerPty {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                // SAFETY: the child owns a session/process group with its PID.
                let _ = unsafe { libc::kill(-pid, libc::SIGHUP) };
                let deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < deadline {
                    if !matches!(self.child.try_wait(), Ok(None)) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // SAFETY: the bounded HUP grace expired for the same owned
                // process group.
                let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            let _ = self.child.wait();
        }
    }
}

fn poll_readable(socket: libc::c_int, pty: libc::c_int, timeout: Duration) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: socket,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pty,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    poll(&mut fds, timeout)
}

fn poll_one(fd: libc::c_int, events: libc::c_short, timeout: Duration) -> io::Result<()> {
    poll(
        &mut [libc::pollfd {
            fd,
            events,
            revents: 0,
        }],
        timeout,
    )
}

fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let milliseconds = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `fds` points to initialized pollfd values for the call duration.
    let count = libc::nfds_t::try_from(fds.len()).unwrap_or(libc::nfds_t::MAX);
    let result = unsafe { libc::poll(fds.as_mut_ptr(), count, milliseconds) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(error)
        }
    } else {
        Ok(())
    }
}

fn errno_to_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn exit_status_code(status: std::process::ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        u8::try_from(code).unwrap_or(255)
    } else if let Some(signal) = status.signal() {
        u8::try_from(128_i32.saturating_add(signal)).unwrap_or(255)
    } else {
        255
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor_frame(line: u16, column: u16) -> crate::screen::WireFrame {
        let screen = RemoteScreen::new(ScreenSize::checked(20, 10).unwrap());
        let mut frame = screen.snapshot(0, 0);
        frame.cursor_line = line;
        frame.cursor_column = column;
        frame.modes |= alacritty_terminal::term::TermMode::SHOW_CURSOR.bits();
        frame
    }

    #[test]
    fn hello_validates_dimensions_and_terminal_name() {
        let mut hello = Vec::from([0, 80, 0, 24, 11]);
        hello.extend_from_slice(b"xterm-kitty");
        let (size, term) = parse_hello(&hello).unwrap();
        assert_eq!(size.columns, 80);
        assert_eq!(size.lines, 24);
        assert_eq!(term, "xterm-kitty");
    }

    #[test]
    fn progress_frames_do_not_expose_one_off_internal_cursor_positions() {
        let mut stabilizer = CursorStabilizer::default();
        let mut initial = cursor_frame(2, 4);
        assert!(!stabilizer.compose(&mut initial, FrameReadiness::Settled));
        assert!(initial.prediction_allowed);

        let mut first_partial = cursor_frame(7, 1);
        assert!(stabilizer.compose(&mut first_partial, FrameReadiness::Progress));
        assert_eq!(
            (first_partial.cursor_line, first_partial.cursor_column),
            (2, 4)
        );
        assert!(!first_partial.prediction_stable);

        let mut second_partial = cursor_frame(5, 18);
        assert!(stabilizer.compose(&mut second_partial, FrameReadiness::Progress));
        assert_eq!(
            (second_partial.cursor_line, second_partial.cursor_column),
            (2, 4)
        );
        assert!(!second_partial.prediction_stable);

        let mut repeated = cursor_frame(5, 18);
        assert!(stabilizer.compose(&mut repeated, FrameReadiness::Progress));
        assert!(!repeated.prediction_stable);
        let mut repeated = cursor_frame(5, 18);
        assert!(stabilizer.compose(&mut repeated, FrameReadiness::Progress));
        assert!(!repeated.prediction_stable);
        let mut repeated = cursor_frame(5, 18);
        assert!(!stabilizer.compose(&mut repeated, FrameReadiness::Progress));
        assert_eq!((repeated.cursor_line, repeated.cursor_column), (5, 18));
        assert!(repeated.prediction_stable);

        let mut completed = cursor_frame(8, 3);
        assert!(!stabilizer.compose(&mut completed, FrameReadiness::Settled));
        assert_eq!((completed.cursor_line, completed.cursor_column), (8, 3));
        assert!(completed.prediction_stable);
    }

    #[test]
    fn same_row_echo_motion_remains_prediction_eligible() {
        let mut stabilizer = CursorStabilizer::default();
        let mut initial = cursor_frame(2, 4);
        assert!(!stabilizer.compose(&mut initial, FrameReadiness::Settled));

        let mut echo = cursor_frame(2, 5);
        assert!(stabilizer.compose(&mut echo, FrameReadiness::Progress));
        assert_eq!((echo.cursor_line, echo.cursor_column), (2, 4));
        assert!(echo.prediction_stable);
    }

    #[test]
    fn frames_are_split_below_the_path_mtu() {
        let crypto = SessionCrypto::new(&[3; 32]);
        let bytes = vec![7; MAX_PLAINTEXT * 2 + 5];
        let datagrams = seal_frame(&crypto, 9, &bytes).unwrap();
        assert_eq!(datagrams.len(), 3);
        assert!(datagrams.iter().all(|datagram| datagram.len() <= 1200));
        let joined: Vec<u8> = datagrams
            .iter()
            .flat_map(|datagram| crypto.open(datagram).unwrap().payload.to_vec())
            .collect();
        assert_eq!(joined, bytes);
    }
}
