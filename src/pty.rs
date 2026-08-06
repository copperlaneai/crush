//! Small, auditable POSIX PTY primitives used by the interactive relay.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use rustix_openpty::rustix::io::dup;
use rustix_openpty::rustix::termios::{
    OptionalActions, Termios, Winsize, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize,
};

use crate::config::strip_crush_env;

/// Captured state for the user's physical terminal.
pub(crate) struct PhysicalTerminal {
    fd: OwnedFd,
    original: Termios,
}

impl PhysicalTerminal {
    pub(crate) fn capture() -> io::Result<Self> {
        let stdin = stdin_fd();
        let original = tcgetattr(stdin).map_err(errno_to_io)?;
        let fd = dup(stdin).map_err(errno_to_io)?;
        Ok(Self { fd, original })
    }

    pub(crate) fn winsize(&self) -> io::Result<Winsize> {
        tcgetwinsize(&self.fd).map_err(errno_to_io)
    }

    /// Duplicate the physical input descriptor for unbuffered relay reads.
    /// The duplicate shares file-status flags with stdin, including temporary
    /// `O_NONBLOCK` changes when all three stdio descriptors alias one PTY.
    pub(crate) fn duplicate_input(&self) -> io::Result<File> {
        Ok(File::from(self.fd.try_clone()?))
    }

    pub(crate) fn enter_raw(&self) -> io::Result<TerminalModeGuard> {
        // Acquire the restoration descriptor before changing terminal state.
        // If `dup` fails (for example at the process FD limit), returning here
        // must leave the user's terminal untouched.
        let guard_fd = self.fd.try_clone()?;
        let mut raw = self.original.clone();
        raw.make_raw();
        tcsetattr(&self.fd, OptionalActions::Now, &raw).map_err(errno_to_io)?;
        Ok(TerminalModeGuard {
            fd: guard_fd,
            original: self.original.clone(),
            active: true,
        })
    }

    pub(crate) fn original(&self) -> &Termios {
        &self.original
    }
}

/// Restores the physical terminal on every controlled return path.
pub(crate) struct TerminalModeGuard {
    fd: OwnedFd,
    original: Termios,
    active: bool,
}

/// A duplicate of the physical output descriptor whose status flags are
/// restored before Crush yields the terminal or returns to its caller.
///
/// `O_NONBLOCK` belongs to the open file description, not an individual
/// descriptor. Some launchers install stdin/stdout/stderr as aliases of the
/// same description, so changing stdout may temporarily affect input too.
pub(crate) struct PhysicalOutput {
    file: File,
    original_flags: libc::c_int,
    nonblocking: bool,
}

impl PhysicalOutput {
    pub(crate) fn capture_nonblocking() -> io::Result<Self> {
        let stdout = stdout_fd();
        let original_flags = get_status_flags(stdout.as_raw_fd())?;
        let file = File::from(dup(stdout).map_err(errno_to_io)?);
        let mut output = Self {
            file,
            original_flags,
            nonblocking: false,
        };
        output.make_nonblocking()?;
        Ok(output)
    }

    pub(crate) fn make_nonblocking(&mut self) -> io::Result<()> {
        if !self.nonblocking {
            set_status_flags(
                self.file.as_raw_fd(),
                self.original_flags | libc::O_NONBLOCK,
            )?;
            self.nonblocking = true;
        }
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if self.nonblocking {
            set_status_flags(self.file.as_raw_fd(), self.original_flags)?;
            self.nonblocking = false;
        }
        Ok(())
    }
}

impl AsRawFd for PhysicalOutput {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl io::Write for PhysicalOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.file, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.file)
    }

    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        io::Write::write_vectored(&mut self.file, buffers)
    }
}

impl Drop for PhysicalOutput {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

impl TerminalModeGuard {
    /// Re-enter raw mode after a job-control suspension.
    pub(crate) fn make_raw(&mut self) -> io::Result<()> {
        if !self.active {
            let mut raw = self.original.clone();
            raw.make_raw();
            tcsetattr(&self.fd, OptionalActions::Now, &raw).map_err(errno_to_io)?;
            self.active = true;
        }
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if self.active {
            tcsetattr(&self.fd, OptionalActions::Now, &self.original).map_err(errno_to_io)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) struct PtyChild {
    pub(crate) controller: File,
    pub(crate) writer: File,
    pub(crate) child: Child,
}

impl PtyChild {
    pub(crate) fn spawn(
        ssh_program: &OsStr,
        args: &[OsString],
        terminal: &PhysicalTerminal,
    ) -> io::Result<Self> {
        let winsize = terminal.winsize()?;
        let pair = rustix_openpty::openpty(Some(terminal.original()), Some(&winsize))
            .map_err(errno_to_io)?;

        let child_stdin = dup(&pair.user).map_err(errno_to_io)?;
        let child_stdout = dup(&pair.user).map_err(errno_to_io)?;
        let child_stderr = pair.user;

        let mut command = Command::new(ssh_program);
        command.args(args);
        command.stdin(Stdio::from(File::from(child_stdin)));
        command.stdout(Stdio::from(File::from(child_stdout)));
        command.stderr(Stdio::from(File::from(child_stderr)));
        strip_crush_env(&mut command);

        // The stdio descriptors have already been installed when `pre_exec`
        // runs. The closure intentionally contains only async-signal-safe
        // syscalls and no allocation.
        unsafe {
            command.pre_exec(|| {
                // SAFETY: This runs in the single-threaded child immediately
                // before exec. No Rust-owned state is touched after failure.
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: stdin is the PTY user descriptor installed above;
                // TIOCSCTTY makes it the controlling terminal for this new
                // session.
                // The request type is target-specific (`c_ulong` on glibc and
                // Darwin, `c_int` on musl), so inference is intentional here.
                #[allow(clippy::cast_lossless)]
                let request = libc::TIOCSCTTY as _;
                if libc::ioctl(libc::STDIN_FILENO, request, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        // Establish every fallible parent-side PTY resource before spawning.
        // Otherwise a post-spawn `dup` failure would drop `Child` without a
        // chance to terminate or reap the newly started OpenSSH process.
        let writer = File::from(dup(&pair.controller).map_err(errno_to_io)?);
        let child = command.spawn()?;
        let controller = File::from(pair.controller);
        Ok(Self {
            controller,
            writer,
            child,
        })
    }

    pub(crate) fn resize_from(&self, terminal: &PhysicalTerminal) -> io::Result<Winsize> {
        let winsize = terminal.winsize()?;
        tcsetwinsize(self.controller.as_fd(), winsize).map_err(errno_to_io)?;
        Ok(winsize)
    }

    pub(crate) fn signal_group(&self, signal: libc::c_int) -> io::Result<()> {
        let pid = i32::try_from(self.child.id())
            .map_err(|_| io::Error::other("SSH child PID does not fit pid_t"))?;
        // SAFETY: the child creates a new session and process group whose ID
        // is its PID; a negative PID targets that group only.
        let result = unsafe { libc::kill(-pid, signal) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn group_exists(&self) -> io::Result<bool> {
        let pid = i32::try_from(self.child.id())
            .map_err(|_| io::Error::other("SSH child PID does not fit pid_t"))?;
        // SAFETY: signal zero performs existence/permission checking only; the
        // negative PID remains scoped to the SSH process group.
        let result = unsafe { libc::kill(-pid, 0) };
        if result == 0 {
            Ok(true)
        } else {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => Ok(false),
                // A group which exists but cannot be signalled still has to be
                // treated as live for bounded cleanup accounting.
                Some(libc::EPERM) => Ok(true),
                _ => Err(error),
            }
        }
    }

    /// Put both aliases of the PTY controller into nonblocking mode. File
    /// status flags are shared by `dup`, so changing either descriptor covers
    /// the input writer and authoritative-output reader together.
    pub(crate) fn make_controller_nonblocking(&self) -> io::Result<()> {
        let fd = self.controller.as_raw_fd();
        let flags = get_status_flags(fd)?;
        set_status_flags(fd, flags | libc::O_NONBLOCK)
    }
}

impl Drop for PtyChild {
    fn drop(&mut self) {
        // `Child` does not terminate or reap on drop. On an unwind or an early
        // return not already handled by the session, make sure OpenSSH and its
        // local process group cannot survive wrapper teardown. Do not block in
        // `Drop`: the session's ordinary cleanup path already performs a
        // bounded reap, while panic/error teardown must remain hang-proof.
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Ok(None) | Err(_) => {
                let _ = self.signal_group(libc::SIGKILL);
                let _ = self.child.try_wait();
            }
        }
    }
}

pub(crate) fn exec_ssh(ssh_program: &OsStr, args: &[OsString]) -> io::Error {
    let mut command = Command::new(ssh_program);
    command.args(args);
    strip_crush_env(&mut command);
    command.exec()
}

fn stdin_fd() -> BorrowedFd<'static> {
    // SAFETY: POSIX reserves descriptor 0 for the process lifetime. Callers
    // duplicate it before storing a descriptor beyond a syscall.
    unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) }
}

fn stdout_fd() -> BorrowedFd<'static> {
    // SAFETY: POSIX reserves descriptor 1 for the process lifetime. The
    // descriptor is duplicated before it is stored.
    unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) }
}

fn get_status_flags(fd: libc::c_int) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFL` only reads status flags from the supplied descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

fn set_status_flags(fd: libc::c_int, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `F_SETFL` updates status flags on the supplied descriptor; the
    // value originated from `F_GETFL` with only `O_NONBLOCK` changed.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn errno_to_io(error: rustix_openpty::rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}
