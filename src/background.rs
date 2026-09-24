//! Fork only before constructing Tokio or starting any worker threads.
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub enum Fork {
    Parent,
    Child(Startup),
}
#[derive(Default)]
pub struct Startup {
    notify: Option<UnixStream>,
    pid_path: Option<PathBuf>,
}
pub struct PidGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for PidGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.is_file() && m.ino() == self.inode) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
impl Startup {
    /// Call only after listeners, locks, and signal handlers have been installed.
    /// A join is ready even if Bob is offline: reconnection happens in the daemon.
    pub fn ready(&mut self) -> Result<Option<PidGuard>> {
        let mut guard = None;
        if let Some(path) = &self.pid_path {
            let mut file = private_file(path, false)?;
            let inode = file.metadata()?.ino();
            guard = Some(PidGuard {
                path: path.clone(),
                inode,
            });
            file.set_len(0)?;
            writeln!(file, "{}", std::process::id())?;
        }
        if let Some(mut notify) = self.notify.take() {
            writeln!(notify, "OK {}", std::process::id())?;
        }
        Ok(guard)
    }
    pub fn failed(&mut self, error: &anyhow::Error) {
        if let Some(mut notify) = self.notify.take() {
            let message: String = format!("{error:#}").chars().take(2000).collect();
            let _ = writeln!(notify, "ERR {message}");
        }
    }
}
fn private_file(path: &Path, append: bool) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .append(append)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "{} must be a private regular file owned by this user (mode 0600)",
        path.display()
    );
    Ok(file)
}
fn child_failure(notify: &mut UnixStream, error: impl std::fmt::Display) -> ! {
    let _ = writeln!(notify, "ERR {error}");
    unsafe { libc::_exit(1) }
}
fn close_inherited(keep: RawFd) {
    // Enumerate only this process's descriptors, including descriptors above a
    // subsequently lowered RLIMIT_NOFILE. Embedded Linux without procfs falls back.
    let directory = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let descriptors: Vec<i32> = match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect(),
        Err(_) => {
            let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
            (3..if limit > 0 {
                limit.min(i32::MAX as _) as i32
            } else {
                65536
            })
                .collect()
        }
    };
    for fd in descriptors {
        if fd > 2 && fd != keep {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

pub fn detach(socket: &Path, role: &str) -> Result<Fork> {
    ensure!(
        socket.is_absolute(),
        "background socket path must be absolute"
    );
    crate::control::private_directory(socket)?;
    let log_path = socket.with_extension("log");
    let pid_path = socket.with_extension("pid");
    // Make sure newly opened descriptors cannot accidentally occupy stdin/out/err.
    for fd in 0..3 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            let n = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            ensure!(n >= 0, "cannot open /dev/null");
            if n != fd {
                unsafe {
                    libc::dup2(n, fd);
                    libc::close(n);
                }
            }
        }
    }
    let log = private_file(&log_path, true).context("opening background log")?;
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let (mut parent, mut child) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(120)))?;
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid > 0 {
        drop(child);
        drop(log);
        drop(null);
        let mut status = 0;
        while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        let mut message = String::new();
        (&mut parent)
            .take(8192)
            .read_to_string(&mut message)
            .with_context(|| {
                format!("waiting for background startup; see {}", log_path.display())
            })?;
        if let Some(pid) = message
            .strip_prefix("OK ")
            .and_then(|p| p.trim().parse::<u32>().ok())
        {
            eprintln!(
                "marriedsh: {role} started (PID {pid})\n  control: {}\n  log: {}\n  pid: {}",
                socket.display(),
                log_path.display(),
                pid_path.display()
            );
            return Ok(Fork::Parent);
        }
        if let Some(error) = message.strip_prefix("ERR ") {
            bail!("{}", error.trim());
        }
        bail!(
            "background process exited before becoming ready; see {}",
            log_path.display()
        );
    }
    drop(parent);
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    if unsafe { libc::setsid() } < 0 {
        child_failure(&mut child, std::io::Error::last_os_error());
    }
    let second = unsafe { libc::fork() };
    if second < 0 {
        child_failure(&mut child, std::io::Error::last_os_error());
    }
    if second > 0 {
        unsafe { libc::_exit(0) }
    }
    unsafe {
        libc::umask(0o077);
    }
    if let Err(e) = std::env::set_current_dir("/") {
        child_failure(&mut child, e);
    }
    for (from, to) in [
        (null.as_raw_fd(), 0),
        (log.as_raw_fd(), 1),
        (log.as_raw_fd(), 2),
    ] {
        if unsafe { libc::dup2(from, to) } < 0 {
            child_failure(&mut child, std::io::Error::last_os_error());
        }
    }
    drop(null);
    drop(log);
    close_inherited(child.as_raw_fd());
    // The retained notification FD remains CLOEXEC; commands cannot inherit it.
    Ok(Fork::Child(Startup {
        notify: Some(child),
        pid_path: Some(pid_path),
    }))
}
