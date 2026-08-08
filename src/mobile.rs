use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use alacritty_terminal::term::TermMode;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGWINCH};
use zeroize::Zeroizing;

use crate::config::{Config, Prediction, strip_crush_env};
use crate::protocol::{MAX_FRAGMENTS, Packet, PacketKind, SessionCrypto, decode_key};
use crate::pty::{PhysicalOutput, PhysicalTerminal};
use crate::screen::{OverlayCell, ScreenRenderer, WireFrame};
use crate::server::BANNER_PREFIX;
use crate::trace::Trace;

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
const BOOTSTRAP_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const MOBILE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_RETRY: Duration = Duration::from_millis(150);
const INPUT_RETRY: Duration = Duration::from_millis(50);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const CONDITIONAL_MISMATCH_SETTLE: Duration = Duration::from_millis(250);
const CONDITIONAL_MAX_HOLD: Duration = Duration::from_secs(2);
const CURSOR_MOTION_MAX_HOLD: Duration = Duration::from_millis(150);
const MAX_PENDING_INPUTS: usize = 256;
const MAX_NETWORK_DATAGRAMS_PER_TURN: usize = 512;
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const INSTALLER: &[u8] = include_bytes!("../install.sh");

#[allow(clippy::too_many_lines)]
pub(crate) fn run_client(config: &Config, args: &[OsString]) -> io::Result<Option<u8>> {
    let terminal = PhysicalTerminal::capture()?;
    let winsize = terminal.winsize()?;
    let Some((mut bootstrap, banner)) = compatible_bootstrap(config, args) else {
        return Ok(None);
    };
    let Ok(address) = resolve_server(config, args, banner.port) else {
        return Ok(None);
    };
    let key = decode_key(&banner.key)?;
    let crypto = SessionCrypto::new(&key);
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect(address)?;
    socket.set_nonblocking(true)?;
    let trace = config.trace.as_deref().map(Trace::open).transpose()?;
    if let Some(trace) = &trace {
        trace.event("mobile_session_start", &[]);
    }
    let prediction_enabled = config.prediction != Prediction::Off;

    let hello_sequence = random_u64()?;
    let hello = hello_payload(winsize.ws_col, winsize.ws_row, "xterm-256color");
    let hello_packet = crypto.seal(PacketKind::Hello, hello_sequence, 0, 1, &hello)?;
    socket.send(&hello_packet)?;
    let mut assembler = FrameAssembler::default();
    let Ok(initial_frame) = receive_initial_frame(
        &socket,
        &crypto,
        &hello_packet,
        &mut assembler,
        MOBILE_HANDSHAKE_TIMEOUT,
    ) else {
        return Ok(None);
    };

    let mut terminal_mode = terminal.enter_raw()?;
    let mut output = PhysicalOutput::capture_nonblocking()?;
    // O_NONBLOCK may be shared with stdin when stdio descriptors alias one PTY.
    output.restore()?;
    let mut input = terminal.duplicate_input()?;
    let mut renderer = ScreenRenderer::default();
    let mut predictor = OverwritePredictor::default();
    let mut input_parser = InputPredictionParser::default();
    let initial_paint = renderer.render(&initial_frame, &[], None)?;
    output.write_all(&initial_paint)?;
    output.flush()?;
    let mut current_frame = Some(initial_frame);
    let mut pending_inputs = VecDeque::new();
    let mut input_sequence = 0_u64;
    let mut resize_sequence = 0_u64;
    let mut keepalive_sequence = 0_u64;
    let mut last_pong_sequence = 0_u64;
    let mut last_server_at = Instant::now();
    let mut last_keepalive_at = Instant::now();
    let resize = Arc::new(AtomicBool::new(false));
    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGWINCH, Arc::clone(&resize))?;
    for signal in [SIGHUP, SIGTERM, SIGINT, SIGQUIT] {
        signal_hook::flag::register(signal, Arc::clone(&terminate))?;
    }

    let result = (|| -> io::Result<u8> {
        let mut network_buffer = [0_u8; 1200];
        let mut input_buffer = [0_u8; 1024];
        loop {
            if terminate.load(Ordering::Acquire) {
                let end =
                    crypto.seal(PacketKind::End, input_sequence.saturating_add(1), 0, 1, &[])?;
                let _ = socket.send(&end);
                return Ok(130);
            }
            if resize.swap(false, Ordering::AcqRel) {
                let size = terminal.winsize()?;
                resize_sequence = resize_sequence.saturating_add(1);
                let mut payload = [0_u8; 4];
                payload[..2].copy_from_slice(&size.ws_col.max(1).to_be_bytes());
                payload[2..].copy_from_slice(&size.ws_row.max(1).to_be_bytes());
                let packet = crypto.seal(PacketKind::Resize, resize_sequence, 0, 1, &payload)?;
                socket.send(&packet)?;
                renderer.invalidate();
            }

            let now = Instant::now();
            retransmit_inputs(&socket, &mut pending_inputs, now)?;
            if now.duration_since(last_keepalive_at) >= KEEPALIVE_INTERVAL {
                keepalive_sequence = keepalive_sequence.saturating_add(1);
                let ping = crypto.seal(PacketKind::Ping, keepalive_sequence, 0, 1, &[])?;
                let _ = socket.send(&ping);
                last_keepalive_at = now;
            }
            if now.duration_since(last_server_at) >= CONNECTION_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "remote Crush helper stopped responding",
                ));
            }

            let ready = poll_client(
                input.as_raw_fd(),
                socket.as_raw_fd(),
                Duration::from_millis(16),
            )?;
            if ready.input {
                match input.read(&mut input_buffer) {
                    Ok(0) => return Ok(0),
                    Ok(count) => {
                        let input_started = Instant::now();
                        input_sequence = input_sequence.saturating_add(1);
                        let bytes = &input_buffer[..count];
                        let packet = crypto.seal(PacketKind::Input, input_sequence, 0, 1, bytes)?;
                        socket.send(&packet)?;
                        pending_inputs.push_back(PendingInput {
                            sequence: input_sequence,
                            datagram: Zeroizing::new(packet),
                            last_sent: Instant::now(),
                        });
                        while pending_inputs.len() > MAX_PENDING_INPUTS {
                            let _ = pending_inputs.pop_front();
                        }
                        if let Some(frame) = current_frame.as_ref().filter(|_| prediction_enabled) {
                            for action in input_parser.push(bytes) {
                                predictor.apply(action, input_sequence, frame);
                            }
                            let prediction = predictor.overlay(frame);
                            let paint =
                                renderer.render(frame, &prediction.cells, prediction.cursor)?;
                            output.write_all(&paint)?;
                            output.flush()?;
                            if let Some(trace) = &trace {
                                trace.event(
                                    "mobile_local_paint",
                                    &[
                                        ("bytes", u64::try_from(count).unwrap_or(u64::MAX)),
                                        (
                                            "latency_us",
                                            u64::try_from(input_started.elapsed().as_micros())
                                                .unwrap_or(u64::MAX),
                                        ),
                                    ],
                                );
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }

            if ready.network {
                let mut newest_frame = None;
                let mut coalesced_frames = 0_u64;
                let mut close_code = None;
                for _ in 0..MAX_NETWORK_DATAGRAMS_PER_TURN {
                    let count = match socket.recv(&mut network_buffer) {
                        Ok(count) => count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    };
                    let Ok(packet) = crypto.open(&network_buffer[..count]) else {
                        continue;
                    };
                    match packet.kind {
                        PacketKind::Frame => {
                            if let Some(compressed) = assembler.insert(packet)? {
                                last_server_at = Instant::now();
                                let frame = WireFrame::decode_compressed(&compressed)?;
                                if newest_frame
                                    .replace((frame, compressed.len(), assembler.latest_complete))
                                    .is_some()
                                {
                                    coalesced_frames = coalesced_frames.saturating_add(1);
                                }
                            }
                        }
                        PacketKind::Close => {
                            last_server_at = Instant::now();
                            close_code = Some(packet.payload.first().copied().unwrap_or(0));
                            break;
                        }
                        PacketKind::Pong if packet.sequence > last_pong_sequence => {
                            last_pong_sequence = packet.sequence;
                            last_server_at = Instant::now();
                        }
                        _ => {}
                    }
                }

                if let Some((frame, compressed_bytes, frame_id)) = newest_frame {
                    while pending_inputs
                        .front()
                        .is_some_and(|pending| pending.sequence <= frame.input_ack)
                    {
                        let _ = pending_inputs.pop_front();
                    }
                    predictor.reconcile(&frame);
                    let prediction = predictor.overlay(&frame);
                    let paint = renderer.render(&frame, &prediction.cells, prediction.cursor)?;
                    output.write_all(&paint)?;
                    output.flush()?;
                    let ack = crypto.seal(PacketKind::FrameAck, frame_id, 0, 1, &[])?;
                    let _ = socket.send(&ack);
                    current_frame = Some(frame);
                    if let Some(trace) = &trace {
                        trace.event(
                            "mobile_frame",
                            &[
                                (
                                    "compressed_bytes",
                                    u64::try_from(compressed_bytes).unwrap_or(u64::MAX),
                                ),
                                ("frame", frame_id),
                                ("coalesced_frames", coalesced_frames),
                            ],
                        );
                    }
                }
                if let Some(code) = close_code {
                    return Ok(code);
                }
            }
        }
    })();

    let _ = output.write_all(ScreenRenderer::restore_bytes());
    let _ = output.flush();
    let _ = terminal_mode.restore();
    bootstrap.finish();
    if let Some(trace) = &trace {
        trace.event("mobile_session_end", &[]);
    }
    result.map(Some)
}

struct BootstrapBanner {
    port: u16,
    key: String,
    version: Option<String>,
}

struct Bootstrap {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl Bootstrap {
    fn start(config: &Config, args: &[OsString]) -> io::Result<Self> {
        let mut command = Command::new(&config.ssh_program);
        command.args(args);
        command.arg(&config.server_program);
        command.arg("--server");
        command.arg("--port");
        command.arg(config.port_range.argument());
        command.stdin(Stdio::inherit());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::null());
        strip_crush_env(&mut command);
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("failed to capture SSH bootstrap output"))?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
        })
    }

    fn read_banner(&mut self, timeout: Duration) -> io::Result<BootstrapBanner> {
        poll_one(self.stdout.get_ref().as_raw_fd(), libc::POLLIN, timeout)?;
        let mut line = String::new();
        if self.stdout.read_line(&mut line)? == 0 {
            let deadline = Instant::now() + BOOTSTRAP_EXIT_TIMEOUT;
            loop {
                match self.child.try_wait()? {
                    Some(status) if status.code() == Some(127) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "remote Crush helper is not installed",
                        ));
                    }
                    Some(status) => {
                        return Err(io::Error::other(format!(
                            "SSH bootstrap exited with {status}"
                        )));
                    }
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    None => {
                        return Err(io::Error::other(
                            "SSH bootstrap closed its output without exiting",
                        ));
                    }
                }
            }
        }
        let mut words = line.split_whitespace();
        if words.next() != Some(BANNER_PREFIX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "remote command did not return a Crush bootstrap banner",
            ));
        }
        let port = words
            .next()
            .and_then(|word| word.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Crush UDP port"))?;
        let key = words
            .next()
            .filter(|word| word.len() == 64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Crush session key"))?
            .to_owned();
        decode_key(&key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Crush session key"))?;
        let version = words.next().map(str::to_owned);
        if words.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected fields in Crush bootstrap banner",
            ));
        }
        Ok(BootstrapBanner { port, key, version })
    }

    fn finish(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.finish();
    }
}

fn compatible_bootstrap(
    config: &Config,
    args: &[OsString],
) -> Option<(Bootstrap, BootstrapBanner)> {
    let force = match read_bootstrap(config, args) {
        Ok((bootstrap, banner)) if banner.version.as_deref() == Some(CLIENT_VERSION) => {
            return Some((bootstrap, banner));
        }
        Ok((mut bootstrap, _)) if config.auto_install_server => {
            bootstrap.finish();
            true
        }
        Err(error) if config.auto_install_server && error.kind() == io::ErrorKind::NotFound => {
            false
        }
        Ok(_) | Err(_) => return None,
    };

    eprintln!("crush: installing remote helper {CLIENT_VERSION}");
    if let Err(error) = install_remote_helper(config, args, force) {
        eprintln!("crush: automatic remote helper installation failed: {error}");
        return None;
    }

    match read_bootstrap(config, args) {
        Ok((bootstrap, banner)) if banner.version.as_deref() == Some(CLIENT_VERSION) => {
            Some((bootstrap, banner))
        }
        Ok(_) | Err(_) => {
            eprintln!("crush: installed remote helper did not start with the expected version");
            None
        }
    }
}

fn read_bootstrap(config: &Config, args: &[OsString]) -> io::Result<(Bootstrap, BootstrapBanner)> {
    let mut bootstrap = Bootstrap::start(config, args)?;
    let banner = bootstrap.read_banner(BOOTSTRAP_TIMEOUT)?;
    Ok((bootstrap, banner))
}

fn install_remote_helper(config: &Config, args: &[OsString], force: bool) -> io::Result<()> {
    let mut command = Command::new(&config.ssh_program);
    command.args(args);
    command.args([
        "sh",
        "-s",
        "--",
        "--version",
        CLIENT_VERSION,
        "--no-modify-path",
    ]);
    if force {
        command.arg("--force");
    }
    command.stdin(Stdio::piped());
    strip_crush_env(&mut command);
    let mut child = command.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("failed to open remote installer input"))?;
    let write_result = stdin.write_all(INSTALLER);
    drop(stdin);
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "remote installer exited with {status}"
        )));
    }
    write_result
}

fn resolve_server(config: &Config, args: &[OsString], port: u16) -> io::Result<SocketAddr> {
    let mut command = Command::new(&config.ssh_program);
    command.arg("-G");
    command.args(args);
    command.stdin(Stdio::null());
    command.stderr(Stdio::null());
    strip_crush_env(&mut command);
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other("ssh -G could not resolve the destination"));
    }
    let config_text = String::from_utf8_lossy(&output.stdout);
    resolve_server_address(&config_text, port)
}

fn resolve_server_address(config_text: &str, port: u16) -> io::Result<SocketAddr> {
    let hostname = config_text
        .lines()
        .find_map(|line| line.strip_prefix("hostname "))
        .ok_or_else(|| io::Error::other("ssh -G did not report a hostname"))?;
    (hostname, port)
        .to_socket_addrs()?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| io::Error::other("remote host has no IPv4 address for Crush UDP"))
}

fn hello_payload(columns: u16, lines: u16, terminal: &str) -> Vec<u8> {
    let terminal = terminal
        .as_bytes()
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        .take(255)
        .collect::<Vec<_>>();
    let mut payload = Vec::with_capacity(5 + terminal.len());
    payload.extend_from_slice(&columns.max(1).to_be_bytes());
    payload.extend_from_slice(&lines.max(1).to_be_bytes());
    payload.push(u8::try_from(terminal.len()).expect("terminal name is bounded"));
    payload.extend_from_slice(&terminal);
    payload
}

fn random_u64() -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("OS randomness unavailable: {error}")))?;
    Ok(u64::from_be_bytes(bytes))
}

fn receive_initial_frame(
    socket: &UdpSocket,
    crypto: &SessionCrypto,
    hello: &[u8],
    assembler: &mut FrameAssembler,
    timeout: Duration,
) -> io::Result<WireFrame> {
    let deadline = Instant::now() + timeout;
    let mut last_hello = Instant::now();
    let mut datagram = [0_u8; 1200];
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out establishing Crush UDP transport",
            ));
        }
        let ready = poll_client(-1, socket.as_raw_fd(), Duration::from_millis(50))?;
        if ready.network {
            loop {
                let count = match socket.recv(&mut datagram) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                let Ok(packet) = crypto.open(&datagram[..count]) else {
                    continue;
                };
                if packet.kind == PacketKind::Close {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "remote Crush helper closed during handshake",
                    ));
                }
                if let Some(compressed) = assembler.insert(packet)? {
                    let frame = WireFrame::decode_compressed(&compressed)?;
                    let ack =
                        crypto.seal(PacketKind::FrameAck, assembler.latest_complete, 0, 1, &[])?;
                    let _ = socket.send(&ack);
                    return Ok(frame);
                }
            }
        }
        if last_hello.elapsed() >= HANDSHAKE_RETRY {
            socket.send(hello)?;
            last_hello = Instant::now();
        }
    }
}

struct PendingInput {
    sequence: u64,
    datagram: Zeroizing<Vec<u8>>,
    last_sent: Instant,
}

fn retransmit_inputs(
    socket: &UdpSocket,
    pending: &mut VecDeque<PendingInput>,
    now: Instant,
) -> io::Result<()> {
    for input in pending {
        if now.duration_since(input.last_sent) >= INPUT_RETRY {
            socket.send(&input.datagram)?;
            input.last_sent = now;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Assembly {
    fragments: Vec<Option<Zeroizing<Vec<u8>>>>,
    received: usize,
}

#[derive(Default)]
struct FrameAssembler {
    assemblies: BTreeMap<u64, Assembly>,
    latest_complete: u64,
}

impl FrameAssembler {
    fn insert(&mut self, packet: Packet) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        if packet.kind != PacketKind::Frame || packet.sequence <= self.latest_complete {
            return Ok(None);
        }
        let count = usize::from(packet.fragments);
        if packet.fragments == 0 || packet.fragments > MAX_FRAGMENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid framebuffer fragment count",
            ));
        }
        let assembly = self
            .assemblies
            .entry(packet.sequence)
            .or_insert_with(|| Assembly {
                fragments: (0..count).map(|_| None).collect(),
                received: 0,
            });
        if assembly.fragments.len() != count {
            self.assemblies.remove(&packet.sequence);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent framebuffer fragment count",
            ));
        }
        let index = usize::from(packet.fragment);
        if assembly.fragments[index].is_none() {
            assembly.fragments[index] = Some(packet.payload);
            assembly.received += 1;
        }
        if assembly.received != count {
            while self.assemblies.len() > 3 {
                if let Some(oldest) = self.assemblies.keys().next().copied() {
                    self.assemblies.remove(&oldest);
                }
            }
            return Ok(None);
        }
        let mut assembly = self
            .assemblies
            .remove(&packet.sequence)
            .expect("completed assembly remains present");
        let length = assembly
            .fragments
            .iter()
            .flatten()
            .map(|fragment| fragment.len())
            .sum();
        let mut joined = Zeroizing::new(Vec::with_capacity(length));
        for fragment in &mut assembly.fragments {
            joined.extend_from_slice(fragment.take().expect("complete assembly").as_slice());
        }
        self.latest_complete = packet.sequence;
        self.assemblies
            .retain(|sequence, _| *sequence > packet.sequence);
        Ok(Some(joined))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputAction {
    Print(u8),
    Backspace,
    MoveLeft,
    MoveRight,
    Submit,
    Barrier,
    Ignore,
}

#[derive(Default)]
struct InputPredictionParser {
    carry: Vec<u8>,
    bracketed_paste: bool,
}

impl InputPredictionParser {
    fn push(&mut self, bytes: &[u8]) -> Vec<InputAction> {
        self.carry.extend_from_slice(bytes);
        let mut actions = Vec::new();
        let mut consumed = 0;
        while consumed < self.carry.len() {
            let byte = self.carry[consumed];
            if self.bracketed_paste && byte != 0x1b {
                actions.push(InputAction::Barrier);
                consumed += 1;
                continue;
            }
            if byte == 0x1b {
                if consumed + 1 >= self.carry.len() {
                    break;
                }
                if self.carry[consumed + 1] != b'[' {
                    actions.push(InputAction::Barrier);
                    consumed += 2;
                    continue;
                }
                let Some(final_offset) = self.carry[consumed + 2..]
                    .iter()
                    .position(|candidate| (0x40..=0x7e).contains(candidate))
                else {
                    break;
                };
                let end = consumed + 2 + final_offset;
                let action = parse_csi_input(&self.carry[consumed + 2..=end]);
                if action == ParsedInput::PasteStart {
                    self.bracketed_paste = true;
                } else if action == ParsedInput::PasteEnd {
                    self.bracketed_paste = false;
                }
                actions.push(action.action());
                consumed = end + 1;
                continue;
            }
            actions.push(match byte {
                0x20..=0x7e => InputAction::Print(byte),
                0x08 | 0x7f => InputAction::Backspace,
                b'\r' | b'\n' => InputAction::Submit,
                _ => InputAction::Barrier,
            });
            consumed += 1;
        }
        if consumed != 0 {
            self.carry.drain(..consumed);
        }
        if self.carry.len() > 64 {
            self.carry.clear();
            actions.push(InputAction::Barrier);
        }
        actions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedInput {
    Action(InputAction),
    PasteStart,
    PasteEnd,
}

impl ParsedInput {
    fn action(self) -> InputAction {
        match self {
            Self::Action(action) => action,
            Self::PasteStart | Self::PasteEnd => InputAction::Barrier,
        }
    }
}

fn parse_csi_input(sequence: &[u8]) -> ParsedInput {
    let Some((&final_byte, parameters)) = sequence.split_last() else {
        return ParsedInput::Action(InputAction::Barrier);
    };
    let parameters = std::str::from_utf8(parameters).unwrap_or("");
    if final_byte == b'C' {
        return ParsedInput::Action(InputAction::MoveRight);
    }
    if final_byte == b'D' {
        return ParsedInput::Action(InputAction::MoveLeft);
    }
    if final_byte == b'u' {
        let mut fields = parameters.split(';');
        let codepoint = fields
            .next()
            .and_then(|value| value.split(':').next())
            .and_then(|value| value.parse::<u32>().ok());
        let mut modifier_event = fields.next().unwrap_or("1").split(':');
        let modifier = modifier_event
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        let event = modifier_event
            .next()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(1);
        if event == 3 {
            return ParsedInput::Action(InputAction::Ignore);
        }
        if modifier > 2 {
            return ParsedInput::Action(InputAction::Barrier);
        }
        let action = codepoint.and_then(|value| u8::try_from(value).ok()).map_or(
            InputAction::Barrier,
            |byte| match byte {
                b' '..=b'~' => InputAction::Print(byte),
                0x08 | 0x7f => InputAction::Backspace,
                b'\r' | b'\n' => InputAction::Submit,
                _ => InputAction::Barrier,
            },
        );
        return ParsedInput::Action(action);
    }
    if final_byte == b'~' {
        let values = parameters
            .split(';')
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if values.first() == Some(&27) {
            let action = values
                .get(2)
                .and_then(|value| u8::try_from(*value).ok())
                .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
                .map_or(InputAction::Barrier, InputAction::Print);
            return ParsedInput::Action(action);
        }
        if values.first() == Some(&200) {
            return ParsedInput::PasteStart;
        }
        if values.first() == Some(&201) {
            return ParsedInput::PasteEnd;
        }
    }
    ParsedInput::Action(InputAction::Barrier)
}

#[derive(Clone, Copy)]
struct ConditionalCell {
    line: usize,
    column: usize,
    byte: u8,
    sequence: u64,
    predicted_at: Instant,
}

#[derive(Clone, Copy)]
struct RowBoundaryHandoff {
    sequence: u64,
    anchor: (usize, usize),
    region: PredictionRegion,
}

#[derive(Default)]
struct OverwritePredictor {
    cells: Vec<ConditionalCell>,
    cursor: Option<(usize, usize)>,
    suspended_cursor: Option<(usize, usize)>,
    suspended_at: Option<Instant>,
    cursor_sequence: Option<u64>,
    cursor_predicted_at: Option<Instant>,
    handoff_sequence: Option<u64>,
    mismatch_since: Option<Instant>,
    row_boundary_handoff: Option<RowBoundaryHandoff>,
    context: Option<ScreenContext>,
    origin: Option<(usize, usize)>,
    region: Option<PredictionRegion>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ScreenContext {
    columns: u16,
    lines: u16,
    alternate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PredictionRegion {
    top: usize,
    bottom: usize,
    left: usize,
    right: usize,
}

struct PredictionOverlay {
    cells: Vec<OverlayCell>,
    cursor: Option<(usize, usize)>,
}

impl OverwritePredictor {
    fn apply(&mut self, action: InputAction, sequence: u64, frame: &WireFrame) {
        if !frame.prediction_allowed {
            self.clear();
            return;
        }
        if !frame.prediction_stable {
            return;
        }
        if self.row_boundary_handoff.is_some() {
            return;
        }
        if self.suspended_at.is_some() {
            self.clear();
        }
        self.begin_context(frame);
        self.mismatch_since = None;
        let Some(region) = self.region else {
            return;
        };
        match action {
            InputAction::Print(byte) => self.apply_print(byte, sequence, frame, region),
            InputAction::Backspace => {
                let now = Instant::now();
                let cursor = self.cursor.unwrap_or((
                    usize::from(frame.cursor_line),
                    usize::from(frame.cursor_column),
                ));
                let Some(target) = retreat_cell(cursor, region) else {
                    return;
                };
                let Some(cell) = self
                    .cells
                    .iter_mut()
                    .find(|cell| (cell.line, cell.column) == target)
                else {
                    // Without a pending local cell, the target belongs to the
                    // authoritative screen and may be part of the prompt. Let
                    // the remote line editor decide whether it is erasable.
                    return;
                };
                cell.byte = b' ';
                cell.sequence = sequence;
                cell.predicted_at = now;
                self.set_conditional_cursor(target, sequence, now);
            }
            InputAction::MoveLeft => {
                let now = Instant::now();
                let cursor = self.cursor.unwrap_or((
                    usize::from(frame.cursor_line),
                    usize::from(frame.cursor_column),
                ));
                if let Some(target) = retreat_cell(cursor, region) {
                    self.set_conditional_cursor(target, sequence, now);
                }
            }
            InputAction::MoveRight => {
                let now = Instant::now();
                let cursor = self.cursor.unwrap_or((
                    usize::from(frame.cursor_line),
                    usize::from(frame.cursor_column),
                ));
                if let Some(target) = advance_cell(cursor, region) {
                    self.set_conditional_cursor(target, sequence, now);
                }
            }
            InputAction::Submit => {
                let cursor = self.cursor.unwrap_or((
                    usize::from(frame.cursor_line),
                    usize::from(frame.cursor_column),
                ));
                if cursor.0 + 1 < region.bottom {
                    self.set_conditional_cursor(
                        (cursor.0 + 1, region.left),
                        sequence,
                        Instant::now(),
                    );
                }
                self.handoff_sequence = Some(sequence);
            }
            InputAction::Ignore => {}
            InputAction::Barrier => self.clear(),
        }
    }

    fn reconcile(&mut self, frame: &WireFrame) {
        self.reconcile_at(frame, Instant::now());
    }

    fn reconcile_at(&mut self, frame: &WireFrame, now: Instant) {
        if !frame.prediction_allowed {
            self.clear();
            return;
        }
        if self
            .handoff_sequence
            .is_some_and(|sequence| sequence <= frame.echo_ack)
        {
            self.clear();
            return;
        }
        if !frame.prediction_stable {
            if self.row_boundary_handoff.is_none() {
                self.suspend(now);
            }
            return;
        }
        let remote_cursor = (
            usize::from(frame.cursor_line),
            usize::from(frame.cursor_column),
        );
        if self.row_boundary_pending(frame, remote_cursor) {
            return;
        }
        if self.suspended_at.is_some() {
            self.clear();
            return;
        }
        if self
            .context
            .is_some_and(|context| context != ScreenContext::from(frame))
        {
            self.clear();
            return;
        }

        if !self.predictions_fit(frame) {
            self.clear();
            return;
        }

        if self
            .region
            .is_some_and(|region| PredictionRegion::around(frame, remote_cursor) != region)
        {
            self.clear();
            return;
        }
        if self
            .oldest_sequence()
            .is_some_and(|sequence| sequence <= frame.input_ack)
            && !self.remote_cursor_line_is_compatible(remote_cursor.0)
        {
            self.clear();
            return;
        }
        let cursor_matches = self.cursor == Some(remote_cursor);
        let mut eligible_mismatch = false;
        let mut expired = false;
        self.cells.retain(|predicted| {
            if predicted.sequence > frame.echo_ack {
                return true;
            }
            let actual = frame
                .character(predicted.line, predicted.column)
                .unwrap_or(' ');
            if actual == char::from(predicted.byte) {
                return false;
            }
            eligible_mismatch = true;
            expired |=
                now.saturating_duration_since(predicted.predicted_at) >= CONDITIONAL_MAX_HOLD;
            true
        });
        let cursor_expired = self.cursor_predicted_at.is_some_and(|predicted_at| {
            now.saturating_duration_since(predicted_at) >= CONDITIONAL_MAX_HOLD
        });
        if expired || cursor_expired {
            self.clear();
            return;
        }

        let cursor_eligible = self
            .cursor_sequence
            .is_some_and(|sequence| sequence <= frame.echo_ack);
        if eligible_mismatch && cursor_eligible && cursor_matches {
            let mismatch_since = *self.mismatch_since.get_or_insert(now);
            if now.saturating_duration_since(mismatch_since) >= CONDITIONAL_MISMATCH_SETTLE {
                self.clear();
                return;
            }
        } else {
            self.mismatch_since = None;
        }

        // A timer alone must never move the displayed cursor backward.
        if cursor_eligible && cursor_matches && self.cells.is_empty() {
            self.cursor = None;
            self.cursor_sequence = None;
            self.cursor_predicted_at = None;
        }
        if self.cells.is_empty() && self.cursor.is_none() {
            self.context = None;
        }
    }

    fn row_boundary_pending(&mut self, frame: &WireFrame, remote_cursor: (usize, usize)) -> bool {
        let Some(handoff) = self.row_boundary_handoff else {
            return false;
        };
        let remote_reanchored = handoff.sequence <= frame.input_ack
            && remote_cursor != handoff.anchor
            && handoff.region.contains(remote_cursor);
        if !remote_reanchored {
            return true;
        }
        self.clear();
        false
    }

    fn predictions_fit(&self, frame: &WireFrame) -> bool {
        let columns = usize::from(frame.columns);
        let lines = usize::from(frame.lines);
        self.cells
            .iter()
            .all(|cell| cell.line < lines && cell.column < columns)
    }

    fn overlay(&self, frame: &WireFrame) -> PredictionOverlay {
        if !frame.prediction_allowed {
            return PredictionOverlay {
                cells: Vec::new(),
                cursor: None,
            };
        }
        if !frame.prediction_stable {
            return PredictionOverlay {
                cells: Vec::new(),
                cursor: self.suspended_cursor,
            };
        }
        PredictionOverlay {
            cells: self
                .cells
                .iter()
                .map(|predicted| OverlayCell {
                    line: predicted.line,
                    column: predicted.column,
                    byte: predicted.byte,
                })
                .collect(),
            cursor: self.cursor,
        }
    }

    fn clear(&mut self) {
        self.cells.clear();
        self.cursor = None;
        self.suspended_cursor = None;
        self.suspended_at = None;
        self.cursor_sequence = None;
        self.cursor_predicted_at = None;
        self.handoff_sequence = None;
        self.mismatch_since = None;
        self.row_boundary_handoff = None;
        self.context = None;
        self.origin = None;
        self.region = None;
    }

    fn suspend(&mut self, now: Instant) {
        let cursor = self.cursor.or(self.suspended_cursor);
        let suspended_at = self.suspended_at.unwrap_or(now);
        let handoff_sequence = self.handoff_sequence;
        self.clear();
        if now.saturating_duration_since(suspended_at) >= CURSOR_MOTION_MAX_HOLD {
            return;
        }
        self.suspended_cursor = cursor;
        self.suspended_at = Some(suspended_at);
        self.handoff_sequence = handoff_sequence;
    }

    fn set_conditional_cursor(
        &mut self,
        cursor: (usize, usize),
        sequence: u64,
        predicted_at: Instant,
    ) {
        self.cursor = Some(cursor);
        self.cursor_sequence = Some(sequence);
        self.cursor_predicted_at = Some(predicted_at);
    }

    fn begin_context(&mut self, frame: &WireFrame) {
        let context = ScreenContext::from(frame);
        if self.context.is_some_and(|existing| existing != context) {
            self.clear();
        }
        self.context = Some(context);
        if self.region.is_none() {
            let cursor = (
                usize::from(frame.cursor_line),
                usize::from(frame.cursor_column),
            );
            self.origin = Some(cursor);
            self.region = Some(PredictionRegion::around(frame, cursor));
        }
    }

    fn oldest_sequence(&self) -> Option<u64> {
        self.cells
            .iter()
            .map(|cell| cell.sequence)
            .chain(self.cursor_sequence)
            .min()
    }

    fn remote_cursor_line_is_compatible(&self, line: usize) -> bool {
        let mut minimum = self.origin.map_or(line, |cursor| cursor.0);
        let mut maximum = minimum;
        for predicted in &self.cells {
            minimum = minimum.min(predicted.line);
            maximum = maximum.max(predicted.line);
        }
        if let Some((cursor_line, _)) = self.cursor {
            minimum = minimum.min(cursor_line);
            maximum = maximum.max(cursor_line);
        }
        (minimum..=maximum).contains(&line)
    }

    fn apply_print(
        &mut self,
        byte: u8,
        sequence: u64,
        frame: &WireFrame,
        region: PredictionRegion,
    ) {
        let now = Instant::now();
        let cursor = self.cursor.unwrap_or((
            usize::from(frame.cursor_line),
            usize::from(frame.cursor_column),
        ));
        let Some(next) = advance_cell(cursor, region) else {
            self.clear();
            return;
        };
        if next.0 != cursor.0 {
            // A TUI can grow its input widget upward instead of accepting the
            // terminal's linear continuation row. Wait for remote layout.
            self.clear();
            self.row_boundary_handoff = Some(RowBoundaryHandoff {
                sequence,
                anchor: (
                    usize::from(frame.cursor_line),
                    usize::from(frame.cursor_column),
                ),
                region,
            });
            return;
        }
        if let Some(cell) = self
            .cells
            .iter_mut()
            .find(|cell| (cell.line, cell.column) == cursor)
        {
            cell.byte = byte;
            cell.sequence = sequence;
            cell.predicted_at = now;
        } else if self.cells.len() < frame.cells.len() {
            self.cells.push(ConditionalCell {
                line: cursor.0,
                column: cursor.1,
                byte,
                sequence,
                predicted_at: now,
            });
        }
        self.set_conditional_cursor(next, sequence, now);
    }
}

impl From<&WireFrame> for ScreenContext {
    fn from(frame: &WireFrame) -> Self {
        Self {
            columns: frame.columns,
            lines: frame.lines,
            alternate: frame.modes & TermMode::ALT_SCREEN.bits() != 0,
        }
    }
}

impl PredictionRegion {
    fn around(frame: &WireFrame, cursor: (usize, usize)) -> Self {
        let columns = usize::from(frame.columns);
        let lines = usize::from(frame.lines);
        let mut region = Self {
            top: 0,
            bottom: lines,
            left: 0,
            right: columns,
        };

        let mut left_segment = None;
        for column in (0..cursor.1).rev() {
            if let Some(segment) = vertical_border_segment(frame, column, cursor.0) {
                region.left = column + 1;
                left_segment = Some(segment);
                break;
            }
        }
        let mut right_segment = None;
        for column in cursor.1.saturating_add(1)..columns {
            if let Some(segment) = vertical_border_segment(frame, column, cursor.0) {
                region.right = column;
                right_segment = Some(segment);
                break;
            }
        }

        for (start, end) in left_segment.into_iter().chain(right_segment) {
            region.top = region.top.max(start);
            region.bottom = region.bottom.min(end);
        }
        region
    }
}

fn vertical_border_segment(
    frame: &WireFrame,
    column: usize,
    cursor_line: usize,
) -> Option<(usize, usize)> {
    if !frame
        .character(cursor_line, column)
        .is_some_and(has_vertical_stroke)
    {
        return None;
    }
    let mut start = cursor_line;
    while start != 0
        && frame
            .character(start - 1, column)
            .is_some_and(has_vertical_stroke)
    {
        start -= 1;
    }
    let mut end = cursor_line + 1;
    while end < usize::from(frame.lines)
        && frame
            .character(end, column)
            .is_some_and(has_vertical_stroke)
    {
        end += 1;
    }
    (end.saturating_sub(start) >= 3).then_some((start, end))
}

fn has_vertical_stroke(character: char) -> bool {
    matches!(
        character,
        '|' | '│'
            | '┃'
            | '┆'
            | '┇'
            | '┊'
            | '┋'
            | '╎'
            | '╏'
            | '║'
            | '┌'
            | '┐'
            | '└'
            | '┘'
            | '├'
            | '┤'
            | '┬'
            | '┴'
            | '┼'
            | '╔'
            | '╗'
            | '╚'
            | '╝'
            | '╠'
            | '╣'
            | '╦'
            | '╩'
            | '╬'
    )
}

fn retreat_cell(cursor: (usize, usize), region: PredictionRegion) -> Option<(usize, usize)> {
    if !region.contains(cursor) {
        return None;
    }
    if cursor.1 > region.left {
        Some((cursor.0, cursor.1 - 1))
    } else if cursor.0 > region.top {
        Some((cursor.0 - 1, region.right.saturating_sub(1)))
    } else {
        None
    }
}

fn advance_cell(cursor: (usize, usize), region: PredictionRegion) -> Option<(usize, usize)> {
    if !region.contains(cursor) {
        return None;
    }
    if cursor.1 + 1 < region.right {
        Some((cursor.0, cursor.1 + 1))
    } else if cursor.0 + 1 < region.bottom {
        Some((cursor.0 + 1, region.left))
    } else {
        None
    }
}

impl PredictionRegion {
    fn contains(self, cursor: (usize, usize)) -> bool {
        (self.top..self.bottom).contains(&cursor.0) && (self.left..self.right).contains(&cursor.1)
    }
}

#[derive(Default)]
struct ClientReady {
    input: bool,
    network: bool,
}

fn poll_client(input: RawFd, network: RawFd, timeout: Duration) -> io::Result<ClientReady> {
    let mut fds = [
        libc::pollfd {
            fd: input,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: network,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    poll(&mut fds, timeout)?;
    Ok(ClientReady {
        input: fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0,
        network: fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0,
    })
}

fn poll_one(fd: RawFd, events: libc::c_short, timeout: Duration) -> io::Result<()> {
    let mut pollfd = [libc::pollfd {
        fd,
        events,
        revents: 0,
    }];
    poll(&mut pollfd, timeout)?;
    if pollfd[0].revents & (events | libc::POLLHUP) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for SSH bootstrap",
        ));
    }
    Ok(())
}

fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let milliseconds = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `fds` contains valid pollfd entries for the duration of the call.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(text: &str, cursor: usize, ack: u64) -> WireFrame {
        let columns = 20;
        let blank = crate::screen::WireCell {
            codepoint: u32::from(' '),
            foreground: 256,
            background: 257,
            flags: 0,
        };
        let mut cells = vec![blank; columns];
        for (index, character) in text.chars().enumerate() {
            cells[index].codepoint = u32::from(character);
        }
        WireFrame {
            columns: u16::try_from(columns).unwrap(),
            lines: 1,
            cursor_line: 0,
            cursor_column: u16::try_from(cursor).unwrap(),
            modes: (TermMode::SHOW_CURSOR | TermMode::LINE_WRAP).bits(),
            input_ack: ack,
            echo_ack: ack,
            title: String::new(),
            bell: false,
            prediction_allowed: true,
            prediction_stable: true,
            clipboard: None,
            cells,
        }
    }

    fn split_pane_frame(cursor: (usize, usize), ack: u64) -> WireFrame {
        let columns = 30;
        let lines = 5;
        let blank = crate::screen::WireCell {
            codepoint: u32::from(' '),
            foreground: 256,
            background: 257,
            flags: 0,
        };
        let mut cells = vec![blank; columns * lines];
        for line in 0..lines - 1 {
            cells[line * columns + 14].codepoint = u32::from('│');
        }
        WireFrame {
            columns: u16::try_from(columns).unwrap(),
            lines: u16::try_from(lines).unwrap(),
            cursor_line: u16::try_from(cursor.0).unwrap(),
            cursor_column: u16::try_from(cursor.1).unwrap(),
            modes: (TermMode::SHOW_CURSOR | TermMode::LINE_WRAP).bits(),
            input_ack: ack,
            echo_ack: ack,
            title: String::new(),
            bell: false,
            prediction_allowed: true,
            prediction_stable: true,
            clipboard: None,
            cells,
        }
    }

    #[test]
    fn kitty_printable_keys_receive_local_overwrite_prediction() {
        let mut parser = InputPredictionParser::default();
        assert_eq!(parser.push(b"\x1b[120;1u"), vec![InputAction::Print(b'x')]);
        assert_eq!(
            parser.push(b"\x1b[27;2;65~"),
            vec![InputAction::Print(b'A')]
        );
    }

    #[test]
    fn proxied_ssh_bootstrap_can_use_an_independent_udp_route() {
        let config = "hostname 127.0.0.1\nproxycommand aws ssm start-session\n";
        assert_eq!(
            resolve_server_address(config, 60_000).unwrap(),
            "127.0.0.1:60000".parse().unwrap()
        );
    }

    #[test]
    fn prediction_never_moves_existing_same_row_text() {
        let authoritative = frame("prompt      RIGHT", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &authoritative);
        let overlay = predictor.overlay(&authoritative);
        assert_eq!(overlay.cells.len(), 1);
        assert_eq!((overlay.cells[0].line, overlay.cells[0].column), (0, 6));
        assert_eq!(overlay.cursor, Some((0, 7)));
        assert_eq!(authoritative.character(0, 12), Some('R'));
    }

    #[test]
    fn prediction_pauses_at_a_tmux_pane_row_boundary_until_remote_reanchors() {
        let authoritative = split_pane_frame((1, 12), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &authoritative);
        predictor.apply(InputAction::Print(b'y'), 2, &authoritative);
        predictor.apply(InputAction::Print(b'z'), 3, &authoritative);

        let overlay = predictor.overlay(&authoritative);
        assert!(overlay.cells.is_empty());
        assert_eq!(overlay.cursor, None);

        let unchanged = split_pane_frame((1, 12), 3);
        predictor.reconcile(&unchanged);
        assert!(predictor.row_boundary_handoff.is_some());

        let divider_cursor = split_pane_frame((1, 14), 3);
        predictor.reconcile(&divider_cursor);
        assert!(predictor.row_boundary_handoff.is_some());

        let reanchored = split_pane_frame((2, 1), 3);
        predictor.reconcile(&reanchored);
        predictor.apply(InputAction::Print(b'q'), 4, &reanchored);
        let overlay = predictor.overlay(&reanchored);
        assert_eq!(overlay.cursor, Some((2, 2)));
        assert_eq!(
            overlay
                .cells
                .iter()
                .map(|cell| (cell.line, cell.column, cell.byte))
                .collect::<Vec<_>>(),
            vec![(2, 1, b'q')]
        );
    }

    #[test]
    fn prediction_submit_stays_inside_the_right_tmux_pane() {
        let authoritative = split_pane_frame((1, 28), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &authoritative);
        assert_eq!(predictor.overlay(&authoritative).cursor, Some((1, 29)));

        predictor.apply(InputAction::Submit, 2, &authoritative);
        assert_eq!(predictor.overlay(&authoritative).cursor, Some((2, 15)));
        assert!(
            predictor
                .overlay(&authoritative)
                .cells
                .iter()
                .all(|cell| cell.column != 14)
        );
    }

    #[test]
    fn a_new_tmux_split_invalidates_the_old_full_width_anchor() {
        let mut base = split_pane_frame((1, 5), 0);
        for line in 0..4 {
            base.cells[line * 30 + 14].codepoint = u32::from(' ');
        }
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);

        let split = split_pane_frame((1, 5), 1);
        predictor.reconcile(&split);
        assert!(predictor.overlay(&split).cells.is_empty());
        assert_eq!(predictor.overlay(&split).cursor, None);
    }

    #[test]
    fn submit_hands_the_cursor_to_a_new_full_screen_layout() {
        let base = split_pane_frame((1, 5), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        predictor.apply(InputAction::Submit, 2, &base);

        let mut codex = split_pane_frame((3, 20), 2);
        codex.echo_ack = 2;
        predictor.reconcile(&codex);
        assert!(predictor.overlay(&codex).cells.is_empty());
        assert_eq!(predictor.overlay(&codex).cursor, None);
    }

    #[test]
    fn authoritative_cells_confirm_predictions_without_cursor_cleanup() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'a'), 1, &base);
        predictor.apply(InputAction::Print(b'b'), 2, &base);
        let confirmed = frame("promptab", 8, 2);
        predictor.reconcile(&confirmed);
        assert!(predictor.overlay(&confirmed).cells.is_empty());
        assert_eq!(predictor.overlay(&confirmed).cursor, None);
    }

    #[test]
    fn transport_ack_does_not_expire_predictions_before_echo_ack() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'a'), 1, &base);
        let mut received_without_echo = frame("prompt", 6, 1);
        received_without_echo.echo_ack = 0;
        predictor.reconcile(&received_without_echo);
        assert_eq!(predictor.overlay(&received_without_echo).cells.len(), 1);
    }

    #[test]
    fn late_ack_cannot_pull_cursor_behind_a_busy_coding_agent() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'a'), 1, &base);
        let predicted_at = predictor.cells[0].predicted_at;

        let delayed_agent = frame("prompt", 6, 1);
        predictor.reconcile_at(&delayed_agent, predicted_at + CONDITIONAL_MISMATCH_SETTLE);
        let overlay = predictor.overlay(&delayed_agent);
        assert_eq!(overlay.cells.len(), 1);
        assert_eq!(overlay.cursor, Some((0, 7)));

        let caught_up = frame("prompta", 7, 1);
        predictor.reconcile_at(&caught_up, predicted_at + CONDITIONAL_MISMATCH_SETTLE);
        assert!(predictor.overlay(&caught_up).cells.is_empty());
        assert_eq!(predictor.overlay(&caught_up).cursor, None);
    }

    #[test]
    fn partial_agent_echo_keeps_only_the_unresolved_suffix() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'a'), 1, &base);
        predictor.apply(InputAction::Print(b'b'), 2, &base);
        let predicted_at = predictor.cells[0].predicted_at;

        let partial = frame("prompta", 7, 2);
        predictor.reconcile_at(&partial, predicted_at + Duration::from_millis(100));
        let overlay = predictor.overlay(&partial);
        assert_eq!(overlay.cells.len(), 1);
        assert_eq!(overlay.cells[0].byte, b'b');
        assert_eq!(overlay.cursor, Some((0, 8)));

        let complete = frame("promptab", 8, 2);
        predictor.reconcile_at(&complete, predicted_at + Duration::from_millis(150));
        assert!(predictor.overlay(&complete).cells.is_empty());
        assert_eq!(predictor.overlay(&complete).cursor, None);
    }

    #[test]
    fn stable_contradiction_still_rolls_back_conditionally() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'a'), 1, &base);
        let predicted_at = predictor.cells[0].predicted_at;
        let contradicted = frame("promptZ", 7, 1);

        let first_mismatch = predicted_at + Duration::from_millis(100);
        predictor.reconcile_at(&contradicted, first_mismatch);
        assert_eq!(predictor.overlay(&contradicted).cells.len(), 1);

        predictor.reconcile_at(&contradicted, first_mismatch + CONDITIONAL_MISMATCH_SETTLE);
        assert!(predictor.overlay(&contradicted).cells.is_empty());
        assert_eq!(predictor.overlay(&contradicted).cursor, None);
    }

    #[test]
    fn alternate_screen_transition_starts_a_new_prediction_epoch() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        let mut alternate = base.clone();
        alternate.modes |= TermMode::ALT_SCREEN.bits();
        predictor.reconcile(&alternate);
        assert!(predictor.overlay(&alternate).cells.is_empty());
        assert_eq!(predictor.overlay(&alternate).cursor, None);
    }

    #[test]
    fn moving_coding_agent_input_row_suspends_prediction_until_stable() {
        let base = split_pane_frame((1, 5), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        let initial_overlay = predictor.overlay(&base);
        assert_eq!(initial_overlay.cursor, Some((1, 6)));
        let mut renderer = ScreenRenderer::default();
        let _ = renderer
            .render(&base, &initial_overlay.cells, initial_overlay.cursor)
            .unwrap();

        let mut moving = split_pane_frame((1, 5), 1);
        moving.prediction_stable = false;
        predictor.reconcile(&moving);
        predictor.apply(InputAction::Print(b'y'), 2, &moving);
        let suspended = predictor.overlay(&moving);
        assert!(suspended.cells.is_empty());
        assert_eq!(suspended.cursor, Some((1, 6)));
        let paint = renderer
            .render(&moving, &suspended.cells, suspended.cursor)
            .unwrap();
        assert!(paint.ends_with(b"\x1b[0m\x1b[2;7H\x1b[?25h\x1b[?2026l"));

        let stable = split_pane_frame((2, 8), 2);
        predictor.reconcile(&stable);
        predictor.apply(InputAction::Print(b'z'), 3, &stable);
        let overlay = predictor.overlay(&stable);
        assert_eq!(
            overlay
                .cells
                .iter()
                .map(|cell| (cell.line, cell.column, cell.byte))
                .collect::<Vec<_>>(),
            vec![(2, 8, b'z')]
        );
        assert_eq!(overlay.cursor, Some((2, 9)));
    }

    #[test]
    fn prolonged_input_row_motion_releases_the_held_cursor() {
        let base = split_pane_frame((1, 5), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        let predicted_at = predictor.cursor_predicted_at.unwrap();

        let mut moving = split_pane_frame((1, 5), 1);
        moving.prediction_stable = false;
        predictor.reconcile_at(&moving, predicted_at + Duration::from_millis(10));
        assert_eq!(predictor.overlay(&moving).cursor, Some((1, 6)));

        let suspended_at = predictor.suspended_at.unwrap();
        predictor.reconcile_at(&moving, suspended_at + CURSOR_MOTION_MAX_HOLD);
        assert!(predictor.overlay(&moving).cells.is_empty());
        assert_eq!(predictor.overlay(&moving).cursor, None);
    }

    #[test]
    fn newline_handoff_cannot_stick_during_an_unstable_redraw() {
        let base = split_pane_frame((1, 5), 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Submit, 1, &base);
        let predicted_at = predictor.cursor_predicted_at.unwrap();

        let mut moving = split_pane_frame((1, 5), 1);
        moving.echo_ack = 0;
        moving.prediction_stable = false;
        predictor.reconcile_at(&moving, predicted_at + Duration::from_millis(10));
        assert_eq!(predictor.overlay(&moving).cursor, Some((2, 0)));

        moving.echo_ack = 1;
        predictor.reconcile_at(&moving, predicted_at + Duration::from_millis(60));
        assert!(predictor.overlay(&moving).cells.is_empty());
        assert_eq!(predictor.overlay(&moving).cursor, None);
    }

    #[test]
    fn fragmented_escape_input_waits_for_completion() {
        let mut parser = InputPredictionParser::default();
        assert!(parser.push(b"\x1b[12").is_empty());
        assert_eq!(parser.push(b"0u"), vec![InputAction::Print(b'x')]);
    }

    #[test]
    fn kitty_space_backspace_and_release_events_are_classified() {
        let mut parser = InputPredictionParser::default();
        assert_eq!(parser.push(b"\x1b[32u"), vec![InputAction::Print(b' ')]);
        assert_eq!(parser.push(b"\x1b[127u"), vec![InputAction::Backspace]);
        assert_eq!(parser.push(b"\x1b[120;1:3u"), vec![InputAction::Ignore]);
    }

    #[test]
    fn cursor_actions_are_predicted_conditionally() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        predictor.apply(InputAction::MoveLeft, 2, &base);
        assert_eq!(predictor.overlay(&base).cursor, Some((0, 6)));
        predictor.apply(InputAction::MoveRight, 3, &base);
        assert_eq!(predictor.overlay(&base).cursor, Some((0, 7)));
    }

    #[test]
    fn backspace_overlays_a_blank_until_remote_state_catches_up() {
        let base = frame("prompt", 6, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Print(b'x'), 1, &base);
        predictor.apply(InputAction::Backspace, 2, &base);
        let overlay = predictor.overlay(&base);
        assert_eq!(overlay.cells.len(), 1);
        assert_eq!(overlay.cells[0].byte, b' ');
        assert_eq!(overlay.cursor, Some((0, 6)));
    }

    #[test]
    fn backspace_without_a_local_suffix_never_erases_the_remote_prompt() {
        let base = frame("user@host$ ", 11, 0);
        let mut predictor = OverwritePredictor::default();
        predictor.apply(InputAction::Backspace, 1, &base);

        let overlay = predictor.overlay(&base);
        assert!(overlay.cells.is_empty());
        assert_eq!(overlay.cursor, None);
    }

    #[test]
    fn bracketed_paste_payload_is_never_locally_predicted() {
        let mut parser = InputPredictionParser::default();
        let actions = parser.push(b"\x1b[200~pasted text\x1b[201~");
        assert!(actions.iter().all(|action| *action == InputAction::Barrier));
    }
}
