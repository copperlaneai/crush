use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

pub fn crush_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crush"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color");
    command
}

pub fn crush_binary() -> &'static OsStr {
    OsStr::new(env!("CARGO_BIN_EXE_crush"))
}

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(test_name: &str) -> Self {
        let parent = std::env::temp_dir();
        Self::new_in(&parent, test_name)
    }

    pub fn new_in(parent: &Path, test_name: &str) -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = parent.join(format!(
            "crush-integration-{test_name}-{}-{timestamp}-{sequence}",
            std::process::id(),
        ));
        fs::create_dir(&path).expect("create integration-test temporary directory");
        Self { path }
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn executable(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.file(name);
        fs::write(&path, contents).expect("write fake SSH executable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make fake SSH executable runnable");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Every path is a freshly created directory with a process-specific
        // prefix; the cleanup target is never supplied by the environment.
        let _ = fs::remove_dir_all(&self.path);
    }
}
