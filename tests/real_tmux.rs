use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::Winsize;

const PROMPT: &[u8] = b"CRUSH_TMUX_PROMPT>";
const START_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

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
    let socket_name = format!(
        "crush-real-tmux-{}-{}",
        std::process::id(),
        unique_timestamp()
    );
    let _server = TmuxServerGuard::new(&socket_name);
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
        .env("CRUSH_PREDICT", "auto")
        .env_remove("CRUSH_ACTION")
        .env_remove("CRUSH_TRACE")
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
    run.wait_for(PROMPT, START_TIMEOUT)
        .unwrap_or_else(|error| panic!("real tmux prompt did not appear: {error}"));

    // The tmux configuration replaces the default prefix with Ctrl-G and
    // binds `q` in the prefix table to detach-client.
    run.write_input(b"\x07q")
        .expect("send custom tmux prefix and detach key");
    let (status, output) = run
        .finish(EXIT_TIMEOUT)
        .unwrap_or_else(|error| panic!("real tmux session did not exit cleanly: {error}"));

    assert!(
        status.success(),
        "status={status}, output={}",
        visible(&output)
    );
    assert!(
        contains(&output, PROMPT),
        "tmux pane prompt was absent: {}",
        visible(&output)
    );
    assert!(
        contains(&output, b"detached"),
        "tmux did not report a detach: {}",
        visible(&output)
    );
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

fn unique_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
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
    socket_name: String,
}

impl TmuxServerGuard {
    fn new(socket_name: &str) -> Self {
        Self {
            socket_name: socket_name.to_owned(),
        }
    }
}

impl Drop for TmuxServerGuard {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/tmux")
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
