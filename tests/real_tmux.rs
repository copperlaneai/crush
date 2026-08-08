use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::Winsize;

const PROMPT: &[u8] = b"CRUSH_TMUX_PROMPT>";
const START_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn real_tmux_custom_prefix_detaches_through_openssh() {
    if env::var_os("CRUSH_RUN_TMUX_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!("skipping real tmux test; set CRUSH_RUN_TMUX_TESTS=1 to enable it");
        return;
    }

    let ssh_key = required_file("CRUSH_TMUX_SSH_KEY");
    let known_hosts = required_file("CRUSH_TMUX_KNOWN_HOSTS");
    require_file(Path::new("/usr/bin/ssh"));
    require_file(Path::new("/usr/bin/tmux"));

    let temp = TestDir::new();
    let trace = temp.path.join("trace.jsonl");
    let socket_name = format!(
        "crush-real-tmux-{}-{}",
        std::process::id(),
        unique_timestamp()
    );
    let config = temp.write(
        "tmux.conf",
        "set-option -g prefix C-g\n\
         unbind-key C-b\n\
         bind-key q detach-client\n\
         set-option -g status off\n",
    );
    let pane = temp.executable(
        "pane.sh",
        "#!/bin/sh\n\
         PS1='CRUSH_TMUX_PROMPT>'\n\
         export PS1\n\
         exec /bin/sh -i\n",
    );
    let launcher = temp.executable(
        "launch-tmux.sh",
        "#!/bin/sh\n\
         set -eu\n\
         /usr/bin/tmux -L \"$1\" -f \"$2\" new-session -d -s \"$3\" \"$4\"\n\
         exec /usr/bin/tmux -L \"$1\" -f \"$2\" attach-session -t \"$3\"\n",
    );
    let remote_command = [
        shell_quote(&launcher),
        shell_quote(&socket_name),
        shell_quote(&config),
        shell_quote("crush-real"),
        shell_quote(&pane),
    ]
    .join(" ");

    let mut command = Command::new(env!("CARGO_BIN_EXE_crush"));
    command
        .env("CRUSH_SSH", "/usr/bin/ssh")
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "fast")
        .env_remove("CRUSH_ACTION")
        .env("CRUSH_TRACE", &trace)
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color")
        .arg("-tt")
        .args(["-F", "/dev/null"])
        .arg("-i")
        .arg(&ssh_key)
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "ConnectionAttempts=1"])
        .args(["-o", "ConnectTimeout=5"])
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-o", "LogLevel=ERROR"])
        .args(["-o", "StrictHostKeyChecking=yes"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("localhost")
        .arg(remote_command);

    let mut run = PtyProcess::spawn(command);
    let _server = TmuxServerGuard::new(Path::new("/usr/bin/tmux"), &socket_name);
    run.wait_for(b"\x1b[?996n", START_TIMEOUT)
        .unwrap_or_else(|error| panic!("local tmux terminal queries did not appear: {error}"));
    run.write_input(
        b"\x1b[?1;2c\x1b[>0;136;0c\x1bP>|crush-test\x1b\\\
          \x1b]10;rgb:ffff/ffff/ffff\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\
          \x1b[?997;2n",
    )
    .expect("answer local tmux terminal capability queries");
    run.wait_for(PROMPT, START_TIMEOUT)
        .unwrap_or_else(|error| panic!("real tmux prompt did not appear: {error}"));

    run.write_input(b"echo CRUSH_TMUX_FAST\r")
        .expect("type through fast tmux prediction");
    run.wait_for(b"CRUSH_TMUX_FAST", START_TIMEOUT)
        .unwrap_or_else(|error| panic!("fast tmux input did not render: {error}"));
    wait_for_file_contents(&trace, b"\"event\":\"prediction_rendered\"");

    // The tmux configuration replaces the default prefix with Ctrl-G and
    // binds `q` in the prefix table to detach-client.
    run.write_input(b"\x07q")
        .expect("send custom tmux prefix and detach key");
    let (status, output) = run
        .finish(EXIT_TIMEOUT)
        .unwrap_or_else(|error| panic!("real tmux session did not exit cleanly: {error}"));

    assert_real_tmux_result(status, &output, &trace);
}

#[test]
fn local_tmux_fast_prediction_is_visibly_faint() {
    if env::var_os("CRUSH_RUN_LOCAL_TMUX_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!("skipping local tmux test; set CRUSH_RUN_LOCAL_TMUX_TESTS=1 and CRUSH_TMUX_BIN");
        return;
    }

    let tmux = required_file("CRUSH_TMUX_BIN");
    let client_term = env::var_os("CRUSH_TMUX_TERM").unwrap_or_else(|| "xterm-256color".into());
    let settled_echo = if client_term.as_encoded_bytes() == b"xterm-kitty" {
        b"\x1bP=1s\x1b\\\x1b[?25l \x08\x08x\x1b[?25h\x1bP=2s\x1b\\".as_slice()
    } else {
        b"\x1b[?2026h\x1b[?25l \x08\x08x\x1b[?25h\x1b[?2026l".as_slice()
    };
    let temp = TestDir::new();
    let trace = temp.path.join("trace.jsonl");
    let socket_name = format!(
        "crush-local-tmux-{}-{}",
        std::process::id(),
        unique_timestamp()
    );
    let config = temp.write(
        "tmux.conf",
        "set-option -g prefix C-g\n\
         unbind-key C-b\n\
         bind-key q detach-client\n\
         set-option -g status on\n\
         set-option -g status-interval 1\n\
         set-option -g status-right '#(date +%s)'\n",
    );
    let pane = temp.executable(
        "pane.sh",
        "#!/bin/sh\n\
         PS1='CRUSH_TMUX_PROMPT>'\n\
         export PS1\n\
         exec /bin/sh -i\n",
    );
    let launcher = temp.executable(
        "local-tmux-ssh.sh",
        "#!/bin/sh\n\
         exec \"$TEST_TMUX_BIN\" -L \"$TEST_SOCKET\" -f \"$TEST_CONFIG\" new-session -s crush-local \"$TEST_PANE\"\n",
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_crush"));
    command
        .env("CRUSH_SSH", launcher)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "fast")
        .env("CRUSH_TRANSPORT", "ssh")
        .env_remove("CRUSH_ACTION")
        .env("CRUSH_TRACE", &trace)
        .env("TEST_TMUX_BIN", &tmux)
        .env("TEST_SOCKET", &socket_name)
        .env("TEST_CONFIG", &config)
        .env("TEST_PANE", &pane)
        .env("LC_ALL", "C")
        .env("TERM", &client_term)
        .arg("local-fixture");

    let mut run = PtyProcess::spawn(command);
    let server = TmuxServerGuard::new(&tmux, &socket_name);
    if let Err(error) = run.wait_for(b"\x1b[?996n", START_TIMEOUT) {
        drop(server);
        panic!("local tmux terminal queries did not appear: {error}");
    }
    run.write_input(
        b"\x1b[?1;2c\x1b[>0;136;0c\x1bP>|crush-test\x1b\\\
          \x1b]10;rgb:ffff/ffff/ffff\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\
          \x1b[?997;2n",
    )
    .expect("answer local tmux terminal capability queries");
    if let Err(error) = run.wait_for(PROMPT, START_TIMEOUT) {
        drop(server);
        panic!("local tmux prompt did not appear: {error}");
    }
    thread::sleep(Duration::from_millis(2_200));
    run.write_input(b"x").expect("type in local tmux fixture");
    if let Err(error) = run.wait_for(b"\x1b[2mx\x1b[22m", Duration::from_secs(2)) {
        drop(server);
        panic!(
            "fast prediction was not faint inside local tmux: {error}; trace={}",
            String::from_utf8_lossy(&fs::read(&trace).unwrap_or_default())
        );
    }
    if let Err(error) = run.wait_for(settled_echo, Duration::from_secs(2)) {
        drop(server);
        panic!(
            "authoritative tmux echo did not settle behind a hidden cursor: {error}; trace={}",
            String::from_utf8_lossy(&fs::read(&trace).unwrap_or_default())
        );
    }
    drop(server);
    drop(run);
}

#[test]
fn local_tmux_coding_agent_keeps_every_key_composed() {
    const INPUT: &[u8] = b"crushsync";
    const PLACEHOLDER: &[u8] = b"Explain this codebase";
    const WRAPPED_INPUT: &[u8] = b"wrap";
    if env::var_os("CRUSH_RUN_LOCAL_TMUX_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!("skipping local tmux coding-agent test; set CRUSH_RUN_LOCAL_TMUX_TESTS=1");
        return;
    }

    let tmux = required_file("CRUSH_TMUX_BIN");
    let client_term = env::var_os("CRUSH_TMUX_TERM").unwrap_or_else(|| "xterm-256color".into());
    let temp = TestDir::new();
    let trace = temp.path.join("trace.jsonl");
    let captured_input = temp.path.join("agent-input.bin");
    let captured_wrapped_input = temp.path.join("agent-wrapped-input.bin");
    let socket_name = format!(
        "crush-agent-tmux-{}-{}",
        std::process::id(),
        unique_timestamp()
    );
    let config = temp.write("tmux.conf", "set-option -g status off\n");
    let pane = temp.executable("agent-pane.sh", coding_agent_pane_script());
    let launcher = temp.executable(
        "local-agent-tmux-ssh.sh",
        "#!/bin/sh\nexec \"$TEST_TMUX_BIN\" -L \"$TEST_SOCKET\" -f \"$TEST_CONFIG\" new-session -s crush-agent \"$TEST_PANE\"\n",
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_crush"));
    command
        .env("CRUSH_SSH", launcher)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "fast")
        .env("CRUSH_TRANSPORT", "ssh")
        .env("CRUSH_TRACE", &trace)
        .env("TEST_TMUX_BIN", &tmux)
        .env("TEST_SOCKET", &socket_name)
        .env("TEST_CONFIG", &config)
        .env("TEST_PANE", &pane)
        .env("TEST_AGENT_INPUT", &captured_input)
        .env("TEST_INPUT_LEN", INPUT.len().to_string())
        .env("TEST_AGENT_WRAPPED_INPUT", &captured_wrapped_input)
        .env("TEST_WRAPPED_INPUT_LEN", WRAPPED_INPUT.len().to_string())
        .env("LC_ALL", "C")
        .env("TERM", &client_term)
        .arg("local-agent-fixture");

    let mut run = PtyProcess::spawn(command);
    let server = TmuxServerGuard::new(&tmux, &socket_name);
    answer_tmux_queries(&mut run);
    run.wait_for(b"CRUSH_AGENT_READY", START_TIMEOUT)
        .unwrap_or_else(|error| panic!("coding-agent prompt did not appear through tmux: {error}"));
    exercise_agent_keys(&mut run, &trace, INPUT, PLACEHOLDER);
    run.wait_for(b"CRUSH_AGENT_WRAP_READY", START_TIMEOUT)
        .unwrap_or_else(|error| panic!("wrapped coding-agent prompt did not appear: {error}"));
    exercise_wrapped_agent_keys(&mut run, &trace, WRAPPED_INPUT);

    let (status, output) = run
        .finish(EXIT_TIMEOUT)
        .unwrap_or_else(|error| panic!("tmux coding-agent fixture did not exit: {error}"));
    drop(server);
    assert!(
        status.success(),
        "status={status}, output={}",
        visible(&output)
    );
    assert_eq!(fs::read(captured_input).expect("read agent input"), INPUT);
    assert_eq!(
        fs::read(captured_wrapped_input).expect("read wrapped agent input"),
        WRAPPED_INPUT
    );
    assert!(contains(&output, b"\x1b[?25l\x1b[10;3H\x1b[2mc\x1b[22m"));
    let trace = fs::read_to_string(trace).expect("read coding-agent tmux trace");
    assert_eq!(
        trace.matches("\"event\":\"prediction_rendered\"").count(),
        INPUT.len() + 1,
        "wrapped input must pause after its same-row prefix: {trace}"
    );
    assert!(
        trace.matches("\"event\":\"tui_frame_composed\"").count() >= INPUT.len(),
        "same-row tmux repaints must retain the software cursor: {trace}"
    );
    assert!(
        !trace.contains("\"event\":\"prediction_blocked\""),
        "{trace}"
    );
    assert!(!trace.contains("\"event\":\"prediction_stale\""), "{trace}");
    assert!(!trace.contains("\"event\":\"shadow_lag\""), "{trace}");
}

fn coding_agent_pane_script() -> &'static str {
    r#"#!/bin/sh
stty raw -echo
printf '\033[?2026h\033[2J\033[HCRUSH_AGENT_READY\033[10;1H\033[1m\342\200\272\033[22m\033[10;3H\033[2mExplain this codebase\033[22m\033[10;3H\033[?2026l'
: > "$TEST_AGENT_INPUT"
i=1
while [ "$i" -le "$TEST_INPUT_LEN" ]; do
    dd bs=1 count=1 2>/dev/null >> "$TEST_AGENT_INPUT"
    printf '\033[?2026h\033[5;1H\033[2mThinking %s\033[22m\033[10;3H\033[?2026l' "$i"
    i=$((i + 1))
done
sleep 0.1
printf '\033[?2026h\033[10;3H'
cat "$TEST_AGENT_INPUT"
printf '\033[?2026l'
sleep 0.1
printf '\033[?2026h\033[2J\033[HCRUSH_AGENT_WRAP_READY\033[10;77H\033[1m\342\200\272\033[22m\033[10;79H\033[2mEx\033[22m\033[11;1H\033[2mplain this codebase\033[22m\033[10;79H\033[?2026l'
: > "$TEST_AGENT_WRAPPED_INPUT"
i=1
while [ "$i" -le "$TEST_WRAPPED_INPUT_LEN" ]; do
    dd bs=1 count=1 2>/dev/null >> "$TEST_AGENT_WRAPPED_INPUT"
    printf '\033[?2026h\033[5;1H\033[2mWrapping %s\033[22m\033[10;79H\033[?2026l' "$i"
    i=$((i + 1))
done
sleep 0.1
printf '\033[?2026h\033[10;79Hwr\033[11;1Hap\033[11;3H\033[?2026l'
sleep 0.1
"#
}

fn exercise_agent_keys(run: &mut PtyProcess, trace: &Path, input: &[u8], placeholder: &[u8]) {
    let rendered_before = trace_event_count(trace, b"\"event\":\"prediction_rendered\"");
    let composed_before = trace_event_count(trace, b"\"event\":\"tui_frame_composed\"");
    for (index, &byte) in input.iter().enumerate() {
        run.write_input(&[byte])
            .expect("type coding-agent key through tmux");
        wait_for_file_event_count(
            trace,
            b"\"event\":\"prediction_rendered\"",
            rendered_before + index + 1,
        );
        let local_frame = expected_local_cursor_append(byte, placeholder[index + 1], index);
        run.wait_for(&local_frame, Duration::from_secs(2))
            .unwrap_or_else(|error| {
                panic!("key {index} lacked its software cursor frame: {error}")
            });
        wait_for_file_event_count(
            trace,
            b"\"event\":\"tui_frame_composed\"",
            composed_before + index + 1,
        );
    }
}

fn exercise_wrapped_agent_keys(run: &mut PtyProcess, trace: &Path, input: &[u8]) {
    let rendered_before = trace_event_count(trace, b"\"event\":\"prediction_rendered\"");
    run.write_input(&input[..1])
        .expect("type same-row coding-agent key through tmux");
    wait_for_file_event_count(
        trace,
        b"\"event\":\"prediction_rendered\"",
        rendered_before + 1,
    );
    run.wait_for(
        b"\x1b[10;80H\x1b[2;7mx\x1b[22;27m\x1b[10;80H",
        Duration::from_secs(2),
    )
    .unwrap_or_else(|error| panic!("same-row key lacked its software cursor: {error}"));

    run.write_input(&input[1..])
        .expect("type row-crossing coding-agent keys through tmux");
    wait_for_file_contents(trace, b"\"event\":\"prediction_row_boundary\"");
}

fn expected_local_cursor_append(byte: u8, cursor_underlay: u8, index: usize) -> Vec<u8> {
    let cell_column = 3 + index;
    let cursor_column = cell_column + 1;
    let mut frame = Vec::new();
    frame.extend_from_slice(format!("\x1b[10;{cell_column}H").as_bytes());
    frame.extend_from_slice(&[b'\x1b', b'[', b'2', b'm', byte]);
    frame.extend_from_slice(b"\x1b[22m");
    frame.extend_from_slice(format!("\x1b[10;{cursor_column}H").as_bytes());
    if cursor_underlay == b' ' {
        frame.extend_from_slice(&[b'\x1b', b'[', b'7', b'm', cursor_underlay]);
        frame.extend_from_slice(b"\x1b[27m");
    } else {
        frame.extend_from_slice(b"\x1b[2;7m");
        frame.push(cursor_underlay);
        frame.extend_from_slice(b"\x1b[22;27m");
    }
    frame.extend_from_slice(format!("\x1b[10;{cursor_column}H").as_bytes());
    frame
}

fn answer_tmux_queries(run: &mut PtyProcess) {
    run.wait_for(b"\x1b[?996n", START_TIMEOUT)
        .unwrap_or_else(|error| panic!("local tmux terminal queries did not appear: {error}"));
    run.write_input(
        b"\x1b[?1;2c\x1b[>0;136;0c\x1bP>|crush-test\x1b\\\
          \x1b]10;rgb:ffff/ffff/ffff\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\
          \x1b[?997;2n",
    )
    .expect("answer local tmux terminal capability queries");
}

fn assert_real_tmux_result(status: ExitStatus, output: &[u8], trace: &Path) {
    assert!(
        status.success(),
        "status={status}, output={}",
        visible(output)
    );
    assert!(
        contains(output, PROMPT),
        "tmux pane prompt was absent: {}",
        visible(output)
    );
    assert!(
        contains(output, b"detached"),
        "tmux did not report a detach: {}",
        visible(output)
    );
    assert!(
        contains(
            &fs::read(trace).expect("read real tmux prediction trace"),
            b"\"event\":\"prediction_rendered\""
        ),
        "fast prediction never rendered inside tmux"
    );
}

fn wait_for_file_contents(path: &Path, marker: &[u8]) {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let contents = fs::read(path).unwrap_or_default();
        if contains(&contents, marker) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {marker:?} in {}; contents={contents:?}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file_event_count(path: &Path, marker: &[u8], expected: usize) {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let contents = fs::read(path).unwrap_or_default();
        let count = contents
            .windows(marker.len())
            .filter(|window| *window == marker)
            .count();
        if count >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} {marker:?} events; contents={contents:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn trace_event_count(path: &Path, marker: &[u8]) -> usize {
    fs::read(path)
        .unwrap_or_default()
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count()
}

fn required_file(variable: &str) -> PathBuf {
    let value = env::var_os(variable)
        .unwrap_or_else(|| panic!("{variable} must name the nightly SSH fixture file"));
    let path = PathBuf::from(value);
    require_file(&path);
    path
}

fn require_file(path: &Path) {
    assert!(
        path.is_file(),
        "required file is missing: {}",
        path.display()
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn visible(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

fn shell_quote(value: impl AsRef<Path>) -> String {
    let value = value.as_ref().as_os_str().to_string_lossy();
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn unique_timestamp() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp}-{counter}")
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let path = env::temp_dir().join(format!(
            "crush-real-tmux-{}-{}",
            std::process::id(),
            unique_timestamp()
        ));
        fs::create_dir(&path).expect("create real tmux test directory");
        Self { path }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, contents).expect("write real tmux fixture");
        path
    }

    fn executable(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.write(name, contents);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make real tmux fixture executable");
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TmuxServerGuard {
    program: PathBuf,
    socket_name: String,
}

impl TmuxServerGuard {
    fn new(program: &Path, socket_name: &str) -> Self {
        Self {
            program: program.to_owned(),
            socket_name: socket_name.to_owned(),
        }
    }
}

impl Drop for TmuxServerGuard {
    fn drop(&mut self) {
        let _ = Command::new(&self.program)
            .args(["-L", &self.socket_name, "kill-server"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Default)]
struct Transcript {
    bytes: Vec<u8>,
    closed: bool,
    error: Option<String>,
}

struct PtyProcess {
    child: Option<Child>,
    writer: Option<File>,
    reader: Option<JoinHandle<()>>,
    transcript: Arc<(Mutex<Transcript>, Condvar)>,
}

impl PtyProcess {
    fn spawn(mut command: Command) -> Self {
        let winsize = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 800,
            ws_ypixel: 480,
        };
        let pair = rustix_openpty::openpty(None, Some(&winsize)).expect("open real tmux test PTY");
        let stdin = File::from(dup(&pair.user).expect("duplicate real tmux PTY stdin"));
        let stdout = File::from(dup(&pair.user).expect("duplicate real tmux PTY stdout"));
        let stderr = File::from(pair.user);
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command
            .spawn()
            .expect("spawn Crush under real tmux test PTY");
        let writer = File::from(dup(&pair.controller).expect("duplicate real tmux PTY controller"));
        let mut controller = File::from(pair.controller);
        let transcript = Arc::new((Mutex::new(Transcript::default()), Condvar::new()));
        let reader_transcript = Arc::clone(&transcript);
        let reader = thread::spawn(move || {
            let mut buffer = [0_u8; 4_096];
            loop {
                match controller.read(&mut buffer) {
                    Ok(0) => {
                        close_transcript(&reader_transcript, None);
                        break;
                    }
                    Ok(count) => {
                        let (lock, changed) = &*reader_transcript;
                        let mut state = lock.lock().expect("lock real tmux transcript");
                        state.bytes.extend_from_slice(&buffer[..count]);
                        changed.notify_all();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    // Linux reports EIO after the last PTY slave closes.
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                        close_transcript(&reader_transcript, None);
                        break;
                    }
                    Err(error) => {
                        close_transcript(&reader_transcript, Some(error.to_string()));
                        break;
                    }
                }
            }
        });

        Self {
            child: Some(child),
            writer: Some(writer),
            reader: Some(reader),
            transcript,
        }
    }

    fn wait_for(&self, marker: &[u8], timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let (lock, changed) = &*self.transcript;
        let mut state = lock.lock().expect("lock real tmux transcript");
        loop {
            if contains(&state.bytes, marker) {
                return Ok(());
            }
            if state.closed {
                return Err(format!(
                    "PTY closed before marker; output={}",
                    visible(&state.bytes)
                ));
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "timed out after {timeout:?}; output={}",
                    visible(&state.bytes)
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_state, _) = changed
                .wait_timeout(state, remaining)
                .expect("wait for real tmux transcript");
            state = next_state;
        }
    }

    fn write_input(&mut self, input: &[u8]) -> std::io::Result<()> {
        self.writer
            .as_mut()
            .expect("real tmux PTY writer is available")
            .write_all(input)
    }

    fn finish(mut self, timeout: Duration) -> Result<(ExitStatus, Vec<u8>), String> {
        let deadline = Instant::now() + timeout;
        let status = loop {
            let child = self.child.as_mut().expect("real tmux child is available");
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if Instant::now() >= deadline {
                self.stop_child();
                return Err(format!(
                    "timed out after {timeout:?}; output={}",
                    visible(&self.snapshot())
                ));
            }
            thread::sleep(Duration::from_millis(10));
        };

        self.child.take();
        self.writer.take();
        self.join_reader();
        let (lock, _) = &*self.transcript;
        let state = lock.lock().expect("lock completed real tmux transcript");
        if let Some(error) = &state.error {
            return Err(format!("failed to read PTY: {error}"));
        }
        Ok((status, state.bytes.clone()))
    }

    fn snapshot(&self) -> Vec<u8> {
        let (lock, _) = &*self.transcript;
        lock.lock()
            .expect("lock real tmux transcript snapshot")
            .bytes
            .clone()
    }

    fn stop_child(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            if let Ok(pid) = i32::try_from(child.id()) {
                // SAFETY: `pid` is the live child returned by `Command`; a
                // positive PID targets only Crush, whose handler forwards the
                // termination signal to its OpenSSH process group.
                let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        self.child.take();
    }

    fn join_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        self.stop_child();
        self.writer.take();
        self.join_reader();
    }
}

fn close_transcript(transcript: &Arc<(Mutex<Transcript>, Condvar)>, error: Option<String>) {
    let (lock, changed) = &**transcript;
    let mut state = lock.lock().expect("lock closing real tmux transcript");
    state.closed = true;
    state.error = error;
    changed.notify_all();
}
