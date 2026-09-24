//! Optional early single-instance gate for shell startup files.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

pub fn acquire(path: &Path) -> Result<Option<File>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening instance lock {}", path.display()))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "instance lock {} must be a private regular file owned by this user (mode 0600)",
        path.display()
    );
    // Keep the lock above stdio even when launched with a closed standard FD.
    if file.as_raw_fd() < 3 {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        file = unsafe { File::from_raw_fd(fd) };
    }
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            // Close only: explicitly unlocking in the launcher would also unlock
            // the shared open file description inherited by its daemon child.
            return Ok(Some(file));
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::WouldBlock => return Ok(None),
            io::ErrorKind::Interrupted => continue,
            _ => return Err(error).with_context(|| format!("locking {}", path.display())),
        }
    }
}

pub fn check_service_paths(lock: &File, socket: &Path) -> Result<()> {
    let held = lock.metadata()?;
    for path in [
        socket.to_owned(),
        socket.with_extension("lock"),
        socket.with_extension("log"),
        socket.with_extension("pid"),
    ] {
        if let Ok(other) = std::fs::metadata(&path) {
            ensure!(
                (held.dev(), held.ino()) != (other.dev(), other.ino()),
                "--lock must use a separate file, not a service socket, socket lock, log or PID file: {}",
                path.display()
            );
        }
    }
    Ok(())
}
