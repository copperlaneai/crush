mod support;

use std::env;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::Winsize;

use support::{TempDir, crush_binary, crush_command};

#[test]
fn version_action_is_local_and_exact() {
    let output = crush_command()
        .env("CRUSH_ACTION", "version")
        .env("CRUSH_SSH", "/definitely/not/needed/for/version")
        .args(["ignored-host", "ignored-command"])
        .output()
        .expect("run crush version action");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("crush {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_uses_ssh_version_and_strips_private_environment() {
    let temp = TempDir::new("doctor");
    let fake_ssh = temp.executable(
        "fake-ssh",
        r#"#!/bin/sh
if [ "$#" -ne 1 ] || [ "$1" != "-V" ]; then
    exit 91
fi
if [ "${CRUSH_SSH+x}" = x ] || [ "${CRUSH_MODE+x}" = x ] || \
   [ "${CRUSH_PREDICT+x}" = x ] || [ "${CRUSH_TRACE+x}" = x ] || \
   [ "${CRUSH_ACTION+x}" = x ] || [ "${CRUSH_FUTURE+x}" = x ]; then
    exit 92
fi
if [ "${KEEP_ME-}" != "preserved" ]; then
    exit 93
fi
printf 'OpenSSH_fake_1.2' >&2
"#,
    );

    let output = crush_command()
        .env("CRUSH_ACTION", "doctor")
        .env("CRUSH_SSH", &fake_ssh)
        .env("CRUSH_MODE", "auto")
        .env("CRUSH_PREDICT", "off")
        .env("CRUSH_TRACE", temp.file("unused.trace"))
        .env("CRUSH_FUTURE", "private")
        .env("KEEP_ME", "preserved")
        .output()
        .expect("run crush doctor action");

    assert!(output.status.success(), "stderr={:?}", output.stderr);
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    assert!(stdout.contains(&format!("crush {}\n", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.contains("ssh:"));
    assert!(stdout.contains("tty: stdin=false stdout=false stderr=false"));
    assert!(stdout.contains("TERM: Some(\"xterm-256color\")"));
    assert!(stdout.ends_with("OpenSSH: OpenSSH_fake_1.2\n"));
    assert!(!temp.file("unused.trace").exists());
}

#[test]
fn doctor_reports_an_unavailable_ssh_without_panicking() {
    let output = crush_command()
        .env("CRUSH_ACTION", "doctor")
        .env("CRUSH_SSH", "/definitely/not/a/crush-test-ssh")
        .output()
        .expect("run crush doctor action");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OpenSSH: unavailable ("));
}

#[test]
fn passthrough_preserves_argv_exit_status_and_non_crush_environment() {
    let temp = TempDir::new("passthrough");
    let args_file = temp.file("args.bin");
    let env_file = temp.file("env.txt");
    let unused_trace = temp.file("unused.trace");
    let fake_ssh = temp.executable(
        "fake-ssh",
        r#"#!/bin/sh
: > "$TEST_ARGS_FILE"
for arg do
    printf '%s\000' "$arg" >> "$TEST_ARGS_FILE"
done
if [ "${CRUSH_SSH+x}" = x ] || [ "${CRUSH_MODE+x}" = x ] || \
   [ "${CRUSH_PREDICT+x}" = x ] || [ "${CRUSH_TRACE+x}" = x ] || \
   [ "${CRUSH_ACTION+x}" = x ] || [ "${CRUSH_FUTURE+x}" = x ]; then
    exit 91
fi
printf '%s|%s|%s' "$NOT_CRUSH_MODE" "$Crush_MODE" "$TERM" > "$TEST_ENV_FILE"
printf 'fake stdout'
printf 'fake stderr' >&2
exit "$TEST_EXIT_CODE"
"#,
    );

    let invalid_utf8 = OsString::from_vec(vec![b'f', 0x80, 0xff]);
    let args = vec![
        OsString::from("user@example.test"),
        OsString::from(""),
        OsString::from("two words"),
        OsString::from("[*?]"),
        OsString::from("unicodé"),
        invalid_utf8,
    ];
    let output = crush_command()
        .env("CRUSH_SSH", &fake_ssh)
        .env("CRUSH_MODE", "passthrough")
        .env("CRUSH_PREDICT", "off")
        .env("CRUSH_TRACE", &unused_trace)
        .env("CRUSH_FUTURE", "must-not-leak")
        .env("NOT_CRUSH_MODE", "keep-upper")
        .env("Crush_MODE", "keep-mixed")
        .env("TEST_ARGS_FILE", &args_file)
        .env("TEST_ENV_FILE", &env_file)
        .env("TEST_EXIT_CODE", "37")
        .args(&args)
        .output()
        .expect("execute fake SSH through passthrough mode");

    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"fake stdout");
    assert_eq!(output.stderr, b"fake stderr");
    assert_eq!(
        decode_nul_arguments(&fs::read(args_file).expect("read recorded argv")),
        args.iter()
            .map(|arg| arg.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fs::read_to_string(env_file).expect("read recorded environment"),
        "keep-upper|keep-mixed|xterm-256color"
    );
    assert!(!unused_trace.exists());
}

#[test]
fn automatic_non_tty_mode_directly_executes_ssh() {
    let temp = TempDir::new("auto-nontty");
    let args_file = temp.file("args.bin");
    let fake_ssh = temp.executable(
        "fake-ssh",
        r#"#!/bin/sh
: > "$TEST_ARGS_FILE"
for arg do
    printf '%s\000' "$arg" >> "$TEST_ARGS_FILE"
done
if [ "${CRUSH_SSH+x}" = x ] || [ "${CRUSH_MODE+x}" = x ]; then
    exit 91
fi
exit 23
"#,
    );
    let args = [
        "-J",
        "jump.example",
        "user@example",
        "printf",
        "hello world",
    ];

    let output = crush_command()
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "auto")
        .env("TEST_ARGS_FILE", &args_file)
        .args(args)
        .output()
        .expect("execute non-TTY invocation");

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(
        decode_nul_arguments(&fs::read(args_file).expect("read recorded argv")),
        args.iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
}

#[test]
fn invalid_configuration_exits_two_and_names_the_variable() {
    let cases = [
        ("CRUSH_SSH", "", "a non-empty executable name or path"),
        ("CRUSH_MODE", "fast", "one of: auto, passthrough, force"),
        ("CRUSH_PREDICT", "on", "one of: auto, off"),
        ("CRUSH_TRACE", "", "a non-empty file path"),
        ("CRUSH_ACTION", "help", "one of: version, doctor"),
    ];

    for (variable, value, expected) in cases {
        let output = crush_command()
            .env(variable, value)
            .output()
            .unwrap_or_else(|error| panic!("run invalid {variable}: {error}"));
        assert_eq!(output.status.code(), Some(2), "variable={variable}");
        assert!(output.stdout.is_empty(), "variable={variable}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("crush: invalid "), "stderr={stderr:?}");
        assert!(stderr.contains(variable), "stderr={stderr:?}");
        assert!(stderr.contains(expected), "stderr={stderr:?}");
    }
}

#[test]
fn force_mode_rejects_non_tty_stdio_before_starting_ssh() {
    let temp = TempDir::new("force-nontty");
    let marker = temp.file("started");
    let fake_ssh = temp.executable("fake-ssh", "#!/bin/sh\nprintf started > \"$TEST_MARKER\"\n");

    let output = crush_command()
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("TEST_MARKER", &marker)
        .arg("user@example.test")
        .output()
        .expect("run forced non-TTY invocation");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("CRUSH_MODE=force requires stdin, stdout, and stderr to be terminals")
    );
    assert!(!marker.exists());
}

#[test]
fn recursive_ssh_program_is_rejected() {
    let output = crush_command()
        .env("CRUSH_SSH", crush_binary())
        .env("CRUSH_MODE", "passthrough")
        .arg("user@example.test")
        .output()
        .expect("run recursive configuration check");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CRUSH_SSH resolves to crush itself"));
}

#[test]
fn hard_link_to_crush_is_rejected_as_recursive() {
    let binary = Path::new(crush_binary());
    let binary_directory = binary
        .parent()
        .expect("Crush binary has a parent directory");
    let temp = TempDir::new_in(binary_directory, "hard-link-recursion");
    let hard_link = temp.file("ssh-hard-link");
    fs::hard_link(binary, &hard_link).expect("create same-filesystem hard link to Crush");

    let output = crush_command()
        .env("CRUSH_SSH", hard_link)
        .env("CRUSH_MODE", "passthrough")
        .arg("user@example.test")
        .output()
        .expect("run hard-link recursion check");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CRUSH_SSH resolves to crush itself"));
}

#[test]
fn path_lookup_skips_an_earlier_non_executable_file() {
    // Root may execute any regular file with at least one execute bit, so a
    // mode-0010 owner fixture is not non-executable under that account.
    // SAFETY: `geteuid` has no arguments or memory-safety preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping owner-permission PATH test as root");
        return;
    }

    let temp = TempDir::new("path-non-executable");
    let first = temp.file("first");
    let second = temp.file("second");
    fs::create_dir(&first).expect("create first PATH directory");
    fs::create_dir(&second).expect("create second PATH directory");

    let program_name = "crush-test-ssh";
    let non_executable = first.join(program_name);
    fs::write(&non_executable, b"this must never execute\n")
        .expect("write non-executable PATH fixture");
    // The current user owns this file, so the empty owner execute class wins;
    // its group execute bit must not make it executable for this process.
    fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o010))
        .expect("make first PATH fixture non-executable");
    assert_eq!(
        fs::metadata(&non_executable)
            .expect("read non-executable fixture metadata")
            .permissions()
            .mode()
            & 0o777,
        0o010
    );
    let fixture_path =
        CString::new(non_executable.as_os_str().as_bytes()).expect("fixture path contains no NUL");
    // SAFETY: `fixture_path` is a live, NUL-terminated pathname.
    assert_eq!(
        unsafe { libc::access(fixture_path.as_ptr(), libc::X_OK) },
        -1
    );

    let marker = temp.file("selected");
    let executable = second.join(program_name);
    fs::write(
        &executable,
        b"#!/bin/sh\nprintf second > \"$TEST_MARKER\"\nexit 29\n",
    )
    .expect("write executable PATH fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make second PATH fixture executable");
    let search_path = env::join_paths([first.as_path(), second.as_path()])
        .expect("construct isolated PATH fixture");

    let output = crush_command()
        .env("PATH", search_path)
        .env("CRUSH_SSH", program_name)
        .env("CRUSH_MODE", "passthrough")
        .env("TEST_MARKER", &marker)
        .arg("user@example.test")
        .output()
        .expect("run PATH executable-selection check");

    assert_eq!(output.status.code(), Some(29));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read_to_string(marker).expect("read selection marker"),
        "second"
    );
}

#[test]
fn missing_ssh_program_is_an_internal_launch_error() {
    let output = crush_command()
        .env("CRUSH_SSH", "/definitely/not/a/crush-test-ssh")
        .env("CRUSH_MODE", "passthrough")
        .arg("user@example.test")
        .output()
        .expect("run missing SSH program check");

    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("crush: "));
}

#[test]
fn interactive_relay_preserves_fragmented_tmux_output_byte_for_byte() {
    let temp = TempDir::new("tmux-output");
    let transcript = tmux_transcript();
    let transcript_file = temp.file("tmux-transcript.bin");
    fs::write(&transcript_file, &transcript).expect("write tmux transcript fixture");
    let fake_ssh = temp.executable(
        "fragmented-ssh",
        r#"#!/bin/sh
block=0
while [ "$block" -lt "$TEST_BLOCK_COUNT" ]; do
    dd if="$TEST_TRANSCRIPT" bs="$TEST_CHUNK" skip="$block" count=1 2>/dev/null
    block=$((block + 1))
done
"#,
    );

    // These boundaries exercise single-byte controls, partial parameters,
    // terminators split from their strings, and a larger relay read.
    for chunk_size in [1_usize, 2, 3, 7, 31, 4_096] {
        let block_count = transcript.len().div_ceil(chunk_size);
        let mut command = crush_command();
        command
            .env("CRUSH_SSH", &fake_ssh)
            .env("CRUSH_MODE", "force")
            .env("CRUSH_PREDICT", "off")
            .env("TEST_TRANSCRIPT", &transcript_file)
            .env("TEST_CHUNK", chunk_size.to_string())
            .env("TEST_BLOCK_COUNT", block_count.to_string())
            .arg("user@example.test");

        let run = PtyRun::spawn(command, None);
        let (status, output) = run.finish();
        assert!(status.success(), "chunk_size={chunk_size}, status={status}");
        assert_eq!(output, transcript, "chunk_size={chunk_size}");
    }
}

#[test]
fn interactive_relay_forwards_terminal_input_without_reserving_tmux_keys() {
    const READY: &[u8] = b"\x1b[2J\x1b[HCRUSH_READY>";
    const DONE: &[u8] = b"\rCRUSH_DONE";

    let temp = TempDir::new("tmux-input");
    let input_file = temp.file("input.bin");
    let fake_ssh = temp.executable(
        "recording-ssh",
        r#"#!/bin/sh
stty raw -echo
printf '\033[2J\033[HCRUSH_READY>'
dd of="$TEST_INPUT_FILE" bs=1 count="$TEST_INPUT_LEN" 2>/dev/null
printf '\rCRUSH_DONE'
"#,
    );
    let input = terminal_input_fixture();
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "auto")
        .env("TEST_INPUT_FILE", &input_file)
        .env("TEST_INPUT_LEN", input.len().to_string())
        .arg("user@example.test");

    let mut run = PtyRun::spawn(command, Some(READY));
    run.wait_until_ready();
    run.write_input(&input);
    let (status, output) = run.finish();

    assert!(status.success(), "status={status}, output={output:?}");
    assert!(output.starts_with(READY), "output={output:?}");
    assert!(output.ends_with(DONE), "output={output:?}");
    assert_eq!(
        fs::read(input_file).expect("read fake SSH input recording"),
        input
    );
}

#[test]
fn interactive_relay_draws_then_cleans_up_a_confirmed_prediction() {
    const SAFE_EPOCH: &[u8] = b"\x1b(B\x1b[0m\x1b[2J\x1b[H\x1b[1;24rREADY";
    const OVERLAY: &[u8] = b"x";
    const CLEANUP_AND_ECHO: &[u8] = b"\x08 \x08x";

    let temp = TempDir::new("visible-prediction");
    let probe_file = temp.file("probe.bin");
    let probe_echoed = temp.file("probe-echoed");
    let predicted_file = temp.file("predicted.bin");
    let predicted_received = temp.file("predicted-received");
    let fake_ssh = temp.executable(
        "predicting-ssh",
        r#"#!/bin/sh
stty raw -echo
printf '\033(B\033[0m\033[2J\033[H\033[1;24rREADY'
dd of="$TEST_PROBE_FILE" bs=1 count=1 2>/dev/null
cat "$TEST_PROBE_FILE"
: > "$TEST_PROBE_ECHOED"
dd of="$TEST_PREDICTED_FILE" bs=1 count=1 2>/dev/null
: > "$TEST_PREDICTED_RECEIVED"
sleep 1
cat "$TEST_PREDICTED_FILE"
"#,
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "auto")
        .env("TEST_PROBE_FILE", &probe_file)
        .env("TEST_PROBE_ECHOED", &probe_echoed)
        .env("TEST_PREDICTED_FILE", &predicted_file)
        .env("TEST_PREDICTED_RECEIVED", &predicted_received)
        .arg("user@example.test");

    let mut run = PtyRun::spawn(command, Some(SAFE_EPOCH));
    run.wait_until_ready();
    run.write_input(b"p");
    wait_for_file(&probe_echoed);
    // The marker is created immediately after the probe write. Allow the
    // authoritative sidecar to parse it and enter the trusted echo epoch.
    thread::sleep(Duration::from_millis(100));
    run.write_input(b"x");
    wait_for_file(&predicted_received);
    thread::sleep(Duration::from_millis(100));
    let output_during_remote_delay = run.output_snapshot();
    let (status, output) = run.finish();

    assert!(status.success(), "status={status}, output={output:?}");
    assert_eq!(fs::read(probe_file).expect("read probe recording"), b"p");
    assert_eq!(
        fs::read(predicted_file).expect("read predicted-byte recording"),
        b"x"
    );
    assert!(
        output_during_remote_delay
            .windows(OVERLAY.len())
            .any(|window| window == OVERLAY),
        "speculative overlay was not visible before remote echo: {output_during_remote_delay:?}"
    );

    let overlay_position = find_subslice(&output, OVERLAY).expect("final output contains overlay");
    let cleanup_position = find_subslice(&output, CLEANUP_AND_ECHO)
        .expect("authoritative echo clears the speculative overlay");
    assert!(overlay_position < cleanup_position, "output={output:?}");
    assert_eq!(
        output,
        [SAFE_EPOCH, b"p", OVERLAY, CLEANUP_AND_ECHO].concat(),
        "the probe and authoritative echo must remain byte-exact"
    );
}

#[test]
fn interactive_relay_drains_buffered_output_after_ssh_exits() {
    let temp = TempDir::new("drain-after-exit");
    let transcript = (0..(1024 * 1024))
        .map(|index| b'a' + u8::try_from(index % 26).unwrap())
        .collect::<Vec<_>>();
    let transcript_file = temp.file("large-transcript.bin");
    fs::write(&transcript_file, &transcript).expect("write large transcript fixture");
    let fake_ssh = temp.executable(
        "large-output-ssh",
        "#!/bin/sh\nexec /bin/cat \"$TEST_TRANSCRIPT\"\n",
    );

    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .env("TEST_TRANSCRIPT", transcript_file)
        .arg("user@example.test");

    let (status, output) = PtyRun::spawn(command, None).finish();
    assert!(status.success(), "status={status}");
    assert_eq!(output, transcript);
}

#[test]
fn child_job_control_stop_suspends_and_resumes_crush() {
    const READY: &[u8] = b"\x1b[2J\x1b[HCRUSH_STOP_READY";
    const RESUMED: &[u8] = b"\rCRUSH_STOP_RESUMED";

    let temp = TempDir::new("job-control");
    let fake_ssh = temp.executable(
        "stopping-ssh",
        "#!/bin/sh\nprintf '\\033[2J\\033[HCRUSH_STOP_READY'\nkill -STOP $$\nprintf '\\rCRUSH_STOP_RESUMED'\n",
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .arg("user@example.test");

    let mut run = PtyRun::spawn(command, None);
    run.wait_until_stopped_and_resume();
    let (status, output) = run.finish();

    assert!(status.success(), "status={status}, output={output:?}");
    assert!(output.starts_with(READY), "output={output:?}");
    assert!(output.ends_with(RESUMED), "output={output:?}");
}

#[test]
fn visible_prediction_is_cleared_before_explicit_suspend() {
    const SAFE_EPOCH: &[u8] = b"\x1b(B\x1b[0m\x1b[2J\x1b[H\x1b[1;24rREADY";
    const OVERLAY: &[u8] = b"x";
    const CLEANUP: &[u8] = b"\x08 \x08";

    let temp = TempDir::new("prediction-suspend");
    let probe_file = temp.file("probe.bin");
    let probe_echoed = temp.file("probe-echoed");
    let predicted_file = temp.file("predicted.bin");
    let predicted_received = temp.file("predicted-received");
    let fake_ssh = temp.executable(
        "suspend-predicting-ssh",
        r#"#!/bin/sh
stty raw -echo
printf '\033(B\033[0m\033[2J\033[H\033[1;24rREADY'
dd of="$TEST_PROBE_FILE" bs=1 count=1 2>/dev/null
cat "$TEST_PROBE_FILE"
: > "$TEST_PROBE_ECHOED"
dd of="$TEST_PREDICTED_FILE" bs=1 count=1 2>/dev/null
: > "$TEST_PREDICTED_RECEIVED"
sleep 30
"#,
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "auto")
        .env("TEST_PROBE_FILE", &probe_file)
        .env("TEST_PROBE_ECHOED", &probe_echoed)
        .env("TEST_PREDICTED_FILE", &predicted_file)
        .env("TEST_PREDICTED_RECEIVED", &predicted_received)
        .arg("user@example.test");

    let mut run = PtyRun::spawn(command, Some(SAFE_EPOCH));
    run.wait_until_ready();
    run.write_input(b"p");
    wait_for_file(&probe_echoed);
    thread::sleep(Duration::from_millis(100));
    run.write_input(b"x");
    wait_for_file(&predicted_received);
    wait_for_output(&run, OVERLAY);

    run.signal(libc::SIGTSTP);
    run.wait_until_stopped();
    wait_for_output(&run, CLEANUP);
    let stopped_output = run.output_snapshot();
    let overlay_position = find_subslice(&stopped_output, OVERLAY)
        .expect("speculative overlay was visible before suspension");
    let cleanup_position =
        find_subslice(&stopped_output, CLEANUP).expect("suspension erased the visible overlay");
    assert!(
        overlay_position < cleanup_position,
        "output={stopped_output:?}"
    );

    run.resume_after_stop();
    run.signal(libc::SIGTERM);
    let (status, _) = run.finish();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "status={status}");
}

#[test]
fn input_backpressure_does_not_block_pause_or_signal_shutdown() {
    const READY: &[u8] = b"CRUSH_INPUT_BACKPRESSURE_READY";

    let temp = TempDir::new("input-backpressure-lifecycle");
    let fake_ssh = temp.executable(
        "nonreading-ssh",
        "#!/bin/sh\nstty raw -echo\nprintf CRUSH_INPUT_BACKPRESSURE_READY\nsleep 30\n",
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .arg("user@example.test");

    let mut run = PtyRun::spawn(command, Some(READY));
    run.wait_until_ready();
    let mut flooding_writer = run
        .writer
        .try_clone()
        .expect("duplicate controller for input flood");
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let flood = thread::spawn(move || {
        let block = [b'x'; 16 * 1024];
        let _ = started_tx.send(());
        while flooding_writer.write_all(&block).is_ok() {}
    });
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("input flood started");
    thread::sleep(Duration::from_millis(150));

    run.signal(libc::SIGTSTP);
    run.wait_until_stopped_and_resume();
    run.signal(libc::SIGTERM);
    let (status, _) = run.finish();
    flood.join().expect("join input flood writer");

    assert_eq!(status.signal(), Some(libc::SIGTERM), "status={status}");
}

#[test]
fn stalled_physical_output_does_not_block_sigterm_cleanup() {
    let temp = TempDir::new("stalled-output-signal");
    let marker = temp.file("started");
    let fake_ssh = temp.executable(
        "flooding-ssh",
        "#!/bin/sh\ntrap '' HUP INT QUIT TERM\n: > \"$TEST_MARKER\"\nexec /usr/bin/yes CRUSH_STALLED_OUTPUT\n",
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .env("TEST_MARKER", &marker)
        .arg("user@example.test");

    let (mut run, release_output) = PtyRun::spawn_with_stalled_output(command);
    wait_for_file(&marker);
    thread::sleep(Duration::from_millis(200));
    run.signal(libc::SIGTERM);
    let status = run.wait_for_exit(Duration::from_secs(3));
    let _ = release_output.send(());
    let (collected_status, _) = run.finish();

    assert_eq!(status.signal(), Some(libc::SIGTERM), "status={status}");
    assert_eq!(collected_status.signal(), Some(libc::SIGTERM));
}

#[test]
fn ignored_signal_with_closed_child_stdio_is_escalated_boundedly() {
    let temp = TempDir::new("closed-stdio-signal");
    let marker = temp.file("started");
    let fake_ssh = temp.executable(
        "closed-stdio-ssh",
        r#"#!/bin/sh
trap '' HUP INT QUIT TERM
: > "$TEST_MARKER"
exec </dev/null >&- 2>&-
while :; do
    sleep 1
done
"#,
    );
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .env("TEST_MARKER", &marker)
        .arg("user@example.test");

    let run = PtyRun::spawn(command, None);
    wait_for_file(&marker);
    run.signal(libc::SIGTERM);
    let started = Instant::now();
    let (status, _) = run.finish();

    assert_eq!(status.signal(), Some(libc::SIGTERM), "status={status}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "ignored child signal exceeded bounded cleanup"
    );
}

#[test]
fn child_signal_is_preserved_as_wait_signal_status() {
    let temp = TempDir::new("signaled-child-status");
    let fake_ssh = temp.executable("signaled-ssh", "#!/bin/sh\nkill -TERM $$\n");
    let mut command = crush_command();
    command
        .env("CRUSH_SSH", fake_ssh)
        .env("CRUSH_MODE", "force")
        .env("CRUSH_PREDICT", "off")
        .arg("user@example.test");

    let (status, _) = PtyRun::spawn(command, None).finish();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "status={status}");
}

fn tmux_transcript() -> Vec<u8> {
    [
        // Reset, clear, home, and status-line positioning.
        b"\x1bc\x1b[2J\x1b[H\x1b[24;1H\x1b[7m[tmux status]\x1b[0m\x1b[1;1H".as_slice(),
        // Alternate screen, cursor modes, focus, mouse, and bracketed paste.
        b"\x1b[?1049h\x1b[?25l\x1b[5 q\x1b[?1004h\x1b[?1006h\x1b[?2004h",
        // Tmux and arbitrary DCS passthrough, including an escaped ESC.
        b"\x1bPtmux;\x1b\x1b]52;c;Y3J1c2g=\x07\x1b\\\x1bPq#0;2;0;0;0#1!3~\x1b\\",
        // OSC title/hyperlink plus APC, PM, and SOS strings.
        b"\x1b]2;remote tmux\x07\x1b]8;;https://example.test\x1b\\link\x1b]8;;\x1b\\",
        b"\x1b_Ga=d;OK\x1b\\\x1b^private-message\x1b\\\x1bXsos-data\x1b\\",
        // A synchronized update followed by common capability queries.
        b"\x1b[?2026h\x1b[10;20Hagent output\x1b[24;1Hstatus\x1b[?2026l",
        b"\x1b[c\x1b[>c\x1b[6n\x1b[?2004$p\x1b]10;?\x07\x1b]11;?\x07",
        // Restore ordinary modes and leave a deterministic final marker.
        b"\x1b[?2004l\x1b[?1006l\x1b[?1004l\x1b[?25h\x1b[?1049lEND",
    ]
    .concat()
}

fn terminal_input_fixture() -> Vec<u8> {
    let mut fixture = [
        // Ctrl-G is a valid custom tmux prefix and must not be stolen.
        b"\x07c\x07[".as_slice(),
        // Bracketed paste payload, including line endings and an escape.
        b"\x1b[200~first line\nsecond \x1b line\x1b[201~",
        // Focus, SGR mouse, CSI-u, Kitty-key release, and terminal replies.
        b"\x1b[I\x1b[O\x1b[<0;12;4M\x1b[<0;12;4m\x1b[97;5u\x1b[97;1:3u",
        b"\x1b[?1;2c\x1b[12;40R\x1b]10;rgb:ffff/ffff/ffff\x1b\\",
        // Raw control and binary bytes must survive the relay as well.
        b"\x00\x03\x04\x1c\x7f",
    ]
    .concat();
    // Exceed both the relay's 4 KiB chunk and StdinLock's typical 8 KiB
    // internal buffer. A buffered reader can otherwise prefetch bytes that
    // disappear from fd readiness and leave the relay asleep in `poll`.
    fixture.extend((0..(16 * 1024)).map(|index| b'a' + u8::try_from(index % 26).unwrap()));
    fixture
}

struct PtyRun {
    child: Child,
    writer: File,
    ready: Receiver<()>,
    reader: JoinHandle<Vec<u8>>,
    observed: Arc<Mutex<Vec<u8>>>,
}

impl PtyRun {
    fn spawn(command: Command, ready_marker: Option<&'static [u8]>) -> Self {
        Self::spawn_inner(command, ready_marker, None)
    }

    fn spawn_with_stalled_output(command: Command) -> (Self, mpsc::SyncSender<()>) {
        let (release, released) = mpsc::sync_channel(1);
        (Self::spawn_inner(command, None, Some(released)), release)
    }

    fn spawn_inner(
        mut command: Command,
        ready_marker: Option<&'static [u8]>,
        output_gate: Option<Receiver<()>>,
    ) -> Self {
        let winsize = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 800,
            ws_ypixel: 480,
        };
        let pair = rustix_openpty::openpty(None, Some(&winsize)).expect("open test PTY");
        let stdin = File::from(dup(&pair.user).expect("duplicate test PTY stdin"));
        let stdout = File::from(dup(&pair.user).expect("duplicate test PTY stdout"));
        let stderr = File::from(pair.user);
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command.spawn().expect("spawn Crush under test PTY");
        let writer = File::from(dup(&pair.controller).expect("duplicate test PTY controller"));
        let mut controller = File::from(pair.controller);
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let reader_observed = Arc::clone(&observed);
        let reader = thread::spawn(move || {
            if let Some(output_gate) = output_gate {
                let _ = output_gate.recv();
            }
            let mut output = Vec::new();
            let mut buffer = [0_u8; 4_096];
            let mut announced = false;
            loop {
                match controller.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        output.extend_from_slice(&buffer[..count]);
                        reader_observed
                            .lock()
                            .expect("lock observed PTY output")
                            .extend_from_slice(&buffer[..count]);
                        if !announced
                            && ready_marker.is_some_and(|marker| {
                                output.windows(marker.len()).any(|window| window == marker)
                            })
                        {
                            let _ = ready_tx.send(());
                            announced = true;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    // Linux PTY controllers conventionally report EIO after
                    // the final slave descriptor closes; macOS returns EOF.
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("read Crush test PTY: {error}"),
                }
            }
            output
        });

        Self {
            child,
            writer,
            ready,
            reader,
            observed,
        }
    }

    fn wait_until_ready(&self) {
        self.ready
            .recv_timeout(Duration::from_secs(5))
            .expect("fake SSH did not become ready");
    }

    fn write_input(&mut self, input: &[u8]) {
        self.writer.write_all(input).expect("write test PTY input");
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = i32::try_from(self.child.id()).expect("Crush PID fits pid_t");
        // SAFETY: `pid` identifies the live owned test child.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    }

    fn output_snapshot(&self) -> Vec<u8> {
        self.observed
            .lock()
            .expect("lock observed PTY output")
            .clone()
    }

    fn wait_until_stopped_and_resume(&mut self) {
        self.wait_until_stopped();
        self.resume_after_stop();
    }

    fn wait_until_stopped(&mut self) {
        let pid = i32::try_from(self.child.id()).expect("Crush PID fits pid_t");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: `status` is a valid output pointer and `pid` identifies
            // the owned Crush test child.
            let result =
                unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::WUNTRACED) };
            if result == pid && libc::WIFSTOPPED(status) {
                return;
            }
            assert!(
                result >= 0,
                "waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            assert!(
                Instant::now() < deadline,
                "Crush did not suspend for child job control"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn resume_after_stop(&self) {
        let pid = i32::try_from(self.child.id()).expect("Crush PID fits pid_t");
        // SAFETY: `pid` still identifies the stopped owned child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll Crush test child") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("Crush test child timed out");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>) {
        let status = self.wait_for_exit(Duration::from_secs(10));
        drop(self.writer);
        let output = self.reader.join().expect("join test PTY reader");
        (status, output)
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_output(run: &PtyRun, marker: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = run.output_snapshot();
        if output.windows(marker.len()).any(|window| window == marker) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for PTY output {marker:?}; output={output:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_nul_arguments(bytes: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(bytes.last(), Some(&0), "recorded argv must end in NUL");
    let mut arguments = bytes
        .split(|byte| *byte == 0)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(arguments.pop(), Some(Vec::new()));
    arguments
}
