mod support;

use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::Winsize;

use support::{TempDir, crush_binary, crush_command};

const PROMPT: &[u8] = b"CRUSH_MOBILE>";

#[test]
fn mobile_helper_round_trip_is_local_and_never_inserts_same_row_text() {
    let temp = TempDir::new("mobile-round-trip");
    let trace = temp.file("mobile.trace");
    let fixture_shell = temp.executable(
        "fixture-shell",
        "#!/bin/sh\n\
         /bin/stty echo\n\
         printf '\\033]52;;Y3J1c2ggY2xpcGJvYXJk\\007\\033[2J\\033[HCRUSH_MOBILE>      RIGHT\\033[1;14H'\n\
         while IFS= read -r line; do\n\
             if [ \"$line\" = quit ]; then exit 7; fi\n\
             printf '\\r\\nGOT:%s\\r\\nCRUSH_MOBILE>      RIGHT\\033[1;14H' \"$line\"\n\
         done\n",
    );
    let fake_ssh = temp.executable(
        "fake-ssh",
        "#!/bin/sh\n\
         if [ \"${1-}\" = -G ]; then\n\
             printf 'hostname 127.0.0.1\\n'\n\
             exit 0\n\
         fi\n\
         exec \"$TEST_CRUSH\" --server\n",
    );

    let mut command = crush_command();
    command
        .env("CRUSH_SSH", &fake_ssh)
        .env("CRUSH_TRANSPORT", "mobile")
        .env("CRUSH_SERVER", "crush")
        .env("CRUSH_TRACE", &trace)
        .env("TEST_CRUSH", crush_binary())
        .env("SHELL", &fixture_shell)
        .arg("fixture-host");

    let mut run = PtyRun::spawn(command);
    run.wait_for(PROMPT, Duration::from_secs(5));
    if std::env::var_os("CRUSH_RUN_MOBILE_IDLE_TESTS").as_deref() == Some("1".as_ref()) {
        thread::sleep(Duration::from_secs(31));
        run.write_input(b"idle\r");
        run.wait_for(b"GOT:idle", Duration::from_secs(5));
        run.write_input(b"quit\r");
        let (status, _) = run.finish(Duration::from_secs(5));
        assert_eq!(status.code(), Some(7));
        assert_local_paint_trace(&trace);
        return;
    }
    let typed_at = Instant::now();
    run.write_input(b"x");
    run.wait_for(b"\x1b[0;2", Duration::from_secs(2));
    assert!(
        typed_at.elapsed() < Duration::from_millis(250),
        "local speculative paint exceeded the integration latency budget"
    );
    run.write_input(b"\r");
    run.wait_for(b"GOT:x", Duration::from_secs(5));

    let observed = run.snapshot();
    assert!(observed.windows(5).any(|bytes| bytes == b"RIGHT"));
    assert!(
        observed
            .windows(28)
            .any(|bytes| bytes == b"\x1b]52;c;Y3J1c2ggY2xpcGJvYXJk\x07"),
        "remote OSC 52 write was not forwarded to the local terminal"
    );
    assert!(
        !observed.windows(3).any(|bytes| bytes == b"\x1b[@")
            && !observed.windows(4).any(|bytes| bytes == b"\x1b[1@"),
        "overwrite prediction must never issue an insert-character operation"
    );

    run.write_input(b"quit\r");
    let (status, _) = run.finish(Duration::from_secs(5));
    assert_eq!(status.code(), Some(7));
    assert_local_paint_trace(&trace);
}

#[test]
fn mobile_helper_preserves_overwrite_prediction_inside_real_tmux() {
    if std::env::var_os("CRUSH_RUN_MOBILE_TMUX_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!(
            "skipping mobile tmux test; set CRUSH_RUN_MOBILE_TMUX_TESTS=1 and CRUSH_TMUX_BIN"
        );
        return;
    }
    let tmux = std::env::var_os("CRUSH_TMUX_BIN").expect("CRUSH_TMUX_BIN is required");
    let temp = TempDir::new("mobile-tmux");
    let socket = format!("crush-mobile-test-{}", std::process::id());
    let config = temp.file("tmux.conf");
    fs::write(
        &config,
        "set-option -g status off\nset-option -g default-terminal xterm-256color\n",
    )
    .expect("write mobile tmux config");
    let pane = temp.executable(
        "tmux-pane",
        "#!/bin/sh\n\
         /bin/stty echo\n\
         printf '\\033[2J\\033[HCRUSH_TMUX>\\033[1;39H'\n\
         while IFS= read -r line; do\n\
             printf '\\r\\nTMUX_GOT:%s\\r\\nCRUSH_TMUX>\\033[1;39H' \"$line\"\n\
         done\n",
    );
    let side = temp.executable(
        "tmux-side",
        "#!/bin/sh\n\
         printf '\\033[2J\\033[HSIDE_PANE'\n\
         while :; do sleep 60; done\n",
    );
    let launcher = temp.executable(
        "tmux-launcher",
        "#!/bin/sh\n\
         export SHELL=/bin/sh\n\
         \"$TEST_TMUX\" -L \"$TEST_SOCKET\" -f \"$TEST_CONFIG\" \\
             new-session -d -s crush-mobile \"$TEST_PANE\" || exit 1\n\
         \"$TEST_TMUX\" -L \"$TEST_SOCKET\" split-window -h -l 40 \\
             -t crush-mobile:0 \"$TEST_SIDE\" || exit 1\n\
         \"$TEST_TMUX\" -L \"$TEST_SOCKET\" select-pane \\
             -t crush-mobile:0.0 || exit 1\n\
         exec \"$TEST_TMUX\" -L \"$TEST_SOCKET\" attach-session \\
             -t crush-mobile\n",
    );
    let fake_ssh = temp.executable(
        "fake-ssh",
        "#!/bin/sh\n\
         if [ \"${1-}\" = -G ]; then\n\
             printf 'hostname 127.0.0.1\\n'\n\
             exit 0\n\
         fi\n\
         exec \"$TEST_CRUSH\" --server\n",
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", &fake_ssh)
        .env("CRUSH_TRANSPORT", "mobile")
        .env("TEST_CRUSH", crush_binary())
        .env("SHELL", &launcher)
        .env("TEST_TMUX", &tmux)
        .env("TEST_SOCKET", &socket)
        .env("TEST_CONFIG", &config)
        .env("TEST_PANE", &pane)
        .env("TEST_SIDE", &side)
        .arg("fixture-host");

    let mut run = PtyRun::spawn(command);
    run.wait_for(b"CRUSH_TMUX>", Duration::from_secs(10));
    run.wait_for(b"SIDE_PANE", Duration::from_secs(5));
    assert_tmux_clipboard_sync(tmux.as_os_str(), &socket, &run);
    let before_prediction = run.snapshot().len();
    run.write_input(b"z");
    run.wait_for(b"\x1b[0;2", Duration::from_secs(2));
    let predicted = run.snapshot();
    let predicted = &predicted[before_prediction..];
    assert!(
        predicted.windows(6).any(|bytes| bytes == b"\x1b[2;1H"),
        "last-column input did not wrap to the left edge of its tmux pane: {predicted:?}"
    );
    assert!(
        !predicted.windows(7).any(|bytes| bytes == b"\x1b[1;40H"),
        "prediction addressed the tmux divider column: {predicted:?}"
    );
    run.write_input(b"\r");
    run.wait_for(b"TMUX_GOT:z", Duration::from_secs(5));
    assert!(
        !run.snapshot().windows(3).any(|bytes| bytes == b"\x1b[@"),
        "mobile prediction issued insert-character inside tmux"
    );
    run.write_input(b"\x02d");
    thread::sleep(Duration::from_millis(100));
    let _ = Command::new(&tmux)
        .args(["-L", &socket, "kill-server"])
        .status();
    let (status, _) = run.finish(Duration::from_secs(5));
    assert!(
        status.success(),
        "tmux-backed mobile session failed: {status}"
    );
}

fn assert_tmux_clipboard_sync(tmux: &std::ffi::OsStr, socket: &str, run: &PtyRun) {
    let clipboard = Command::new(tmux)
        .args(["-L", socket, "set-buffer", "-w", "crush-mobile-clipboard"])
        .status()
        .expect("set remote tmux clipboard buffer");
    assert!(clipboard.success(), "tmux clipboard command failed");
    run.wait_for(
        b"\x1b]52;c;Y3J1c2gtbW9iaWxlLWNsaXBib2FyZA==\x07",
        Duration::from_secs(5),
    );
}

struct PtyRun {
    child: Child,
    writer: Option<File>,
    reader: Option<JoinHandle<Vec<u8>>>,
    observed: Arc<Mutex<Vec<u8>>>,
}

impl PtyRun {
    fn spawn(mut command: Command) -> Self {
        let pair = rustix_openpty::openpty(
            None,
            Some(&Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 800,
                ws_ypixel: 480,
            }),
        )
        .expect("open mobile integration PTY");
        command
            .stdin(Stdio::from(File::from(
                dup(&pair.user).expect("duplicate mobile PTY stdin"),
            )))
            .stdout(Stdio::from(File::from(
                dup(&pair.user).expect("duplicate mobile PTY stdout"),
            )))
            .stderr(Stdio::from(File::from(pair.user)));
        let child = command.spawn().expect("spawn Crush mobile client");
        let writer = File::from(dup(&pair.controller).expect("duplicate mobile PTY controller"));
        let mut controller = File::from(pair.controller);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let reader_observed = Arc::clone(&observed);
        let reader = thread::spawn(move || {
            let mut complete = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                if !poll_readable(controller.as_raw_fd(), -1) {
                    continue;
                }
                match controller.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        complete.extend_from_slice(&buffer[..count]);
                        reader_observed
                            .lock()
                            .expect("lock mobile output")
                            .extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("read mobile integration PTY: {error}"),
                }
            }
            complete
        });
        Self {
            child,
            writer: Some(writer),
            reader: Some(reader),
            observed,
        }
    }

    fn write_input(&mut self, bytes: &[u8]) {
        self.writer
            .as_mut()
            .expect("mobile PTY writer remains open")
            .write_all(bytes)
            .expect("write mobile PTY input");
    }

    fn wait_for(&self, marker: &[u8], timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .observed
                .lock()
                .expect("lock mobile output")
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {:?}; output={:?}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&self.snapshot())
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        self.observed.lock().expect("lock mobile output").clone()
    }

    fn finish(mut self, timeout: Duration) -> (ExitStatus, Vec<u8>) {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll mobile client") {
                break status;
            }
            assert!(Instant::now() < deadline, "mobile client did not exit");
            thread::sleep(Duration::from_millis(5));
        };
        drop(self.writer.take());
        let output = self
            .reader
            .take()
            .expect("mobile reader exists")
            .join()
            .expect("join mobile reader");
        (status, output)
    }
}

impl Drop for PtyRun {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        drop(self.writer.take());
        let _ = self.reader.take();
    }
}

fn poll_readable(fd: libc::c_int, timeout: libc::c_int) -> bool {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    loop {
        // SAFETY: `descriptor` is valid for this one-element poll call.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result >= 0 {
            return result != 0;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

fn assert_local_paint_trace(path: &Path) {
    let trace = fs::read_to_string(path).expect("read mobile trace");
    let latency = trace
        .lines()
        .find(|line| line.contains("\"event\":\"mobile_local_paint\""))
        .and_then(|line| line.split("\"latency_us\":").nth(1))
        .and_then(|value| value.trim_end_matches('}').parse::<u64>().ok())
        .expect("mobile trace contains local-paint latency");
    assert!(
        latency < 50_000,
        "mobile input-to-paint latency was {latency} us"
    );
    eprintln!("mobile input-to-paint latency: {latency} us");
}
