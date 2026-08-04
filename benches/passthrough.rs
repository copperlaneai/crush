//! Dependency-free diagnostic baselines for Crush's public executable.
//!
//! Run with `cargo bench --bench passthrough`. Results are intentionally not
//! release gates: startup measurements are noisy on shared CI hosts, while the
//! interactive PTY latency gates require the dedicated harness described in
//! `docs/testing.md`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_STARTUP_ITERATIONS: u32 = 100;
const DEFAULT_THROUGHPUT_MIB: u32 = 64;

fn main() {
    // `cargo test --all-targets` also starts harness-free benchmark binaries.
    // Keep ordinary debug test runs quick; `cargo bench` uses the optimized
    // bench profile and reaches the measurements below.
    if cfg!(debug_assertions) {
        println!("passthrough benchmark skipped; run `cargo bench --bench passthrough`");
        return;
    }

    let iterations = environment_u32("CRUSH_BENCH_ITERATIONS", DEFAULT_STARTUP_ITERATIONS);
    let throughput_mib = environment_u32("CRUSH_BENCH_MIB", DEFAULT_THROUGHPUT_MIB);
    let fixture = Fixture::new();

    // Warm the executable and dynamic-loader caches before reporting timings.
    assert_success(&version_command().output().expect("run version warmup"));
    assert_success(
        &passthrough_command(&fixture.exit_ssh)
            .output()
            .expect("run passthrough warmup"),
    );

    let version_elapsed = measure(iterations, || {
        assert_success(&version_command().output().expect("run version action"));
    });
    let passthrough_elapsed = measure(iterations, || {
        assert_success(
            &passthrough_command(&fixture.exit_ssh)
                .output()
                .expect("run passthrough action"),
        );
    });
    let throughput_elapsed = measure_throughput(&fixture.cat_ssh, throughput_mib);

    println!("Crush public-executable diagnostic benchmark");
    println!("samples: {iterations}");
    println!(
        "version startup:       {:>10.3} ms/launch",
        millis_per_iteration(version_elapsed, iterations)
    );
    println!(
        "passthrough exec:      {:>10.3} ms/launch",
        millis_per_iteration(passthrough_elapsed, iterations)
    );
    println!(
        "passthrough stream:    {:>10.1} MiB/s ({} MiB)",
        f64::from(throughput_mib) / throughput_elapsed.as_secs_f64(),
        throughput_mib
    );
}

fn version_command() -> Command {
    let mut command = base_command();
    command.env("CRUSH_ACTION", "version");
    command
}

fn passthrough_command(fake_ssh: &Path) -> Command {
    let mut command = base_command();
    command
        .env("CRUSH_MODE", "passthrough")
        .env("CRUSH_SSH", fake_ssh);
    command
}

fn base_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crush"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn measure(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed()
}

fn measure_throughput(fake_ssh: &Path, mebibytes: u32) -> Duration {
    let mut command = passthrough_command(fake_ssh);
    command.stdin(Stdio::piped());
    let mut child = command.spawn().expect("start passthrough stream");
    let mut input = child.stdin.take().expect("capture passthrough stdin");
    let block = vec![0x5a_u8; 64 * 1024].into_boxed_slice();
    let block_count = u64::from(mebibytes).saturating_mul(1024 * 1024)
        / u64::try_from(block.len()).expect("benchmark block length fits u64");
    let started = Instant::now();
    for _ in 0..block_count {
        input.write_all(&block).expect("write passthrough stream");
    }
    drop(input);
    let status = child.wait().expect("wait for passthrough stream");
    assert!(status.success(), "passthrough stream failed: {status}");
    started.elapsed()
}

fn millis_per_iteration(elapsed: Duration, iterations: u32) -> f64 {
    elapsed.as_secs_f64() * 1_000.0 / f64::from(iterations)
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "benchmark child failed: {output:?}"
    );
}

fn environment_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

struct Fixture {
    directory: PathBuf,
    exit_ssh: PathBuf,
    cat_ssh: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "crush-benchmark-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).expect("create benchmark temporary directory");
        let exit_ssh = write_executable(&directory, "exit-ssh", "#!/bin/sh\nexit 0\n");
        let cat_ssh = write_executable(&directory, "cat-ssh", "#!/bin/sh\nexec /bin/cat\n");
        Self {
            directory,
            exit_ssh,
            cat_ssh,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn write_executable(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write benchmark fake SSH");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("make benchmark fake SSH executable");
    path
}
