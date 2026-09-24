use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::unix::AsyncFd,
    io::{AsyncRead, AsyncWrite, ReadBuf},
};

struct Inner {
    fd: OwnedFd,
    flags: i32,
}
impl AsRawFd for Inner {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.as_raw_fd(), libc::F_SETFL, self.flags);
        }
    }
}
enum Handle {
    Poll(AsyncFd<Inner>),
    File(Inner),
}
#[derive(Clone)]
pub struct UnixIo(Arc<Handle>);
impl UnixIo {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(raw, &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let inner = Inner { fd, flags };
        if st.st_mode & libc::S_IFMT == libc::S_IFREG {
            return Ok(Self(Arc::new(Handle::File(inner))));
        }
        if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // /dev/null and some device files cannot be registered with epoll.
        match AsyncFd::try_new(inner) {
            Ok(a) => Ok(Self(Arc::new(Handle::Poll(a)))),
            Err(e) => {
                let (inner, error) = e.into_parts();
                if st.st_mode & libc::S_IFMT == libc::S_IFCHR
                    && unsafe { libc::isatty(raw) } == 0
                    && matches!(error.raw_os_error(), Some(libc::EPERM | libc::EINVAL))
                {
                    Ok(Self(Arc::new(Handle::File(inner))))
                } else {
                    Err(error)
                }
            }
        }
    }
    pub fn duplicate(fd: RawFd) -> io::Result<Self> {
        let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if new < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::new(unsafe { OwnedFd::from_raw_fd(new) })
    }
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(self.as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl AsRawFd for UnixIo {
    fn as_raw_fd(&self) -> RawFd {
        match &*self.0 {
            Handle::Poll(a) => a.as_raw_fd(),
            Handle::File(f) => f.as_raw_fd(),
        }
    }
}
fn read(fd: RawFd, buf: &mut ReadBuf<'_>) -> io::Result<()> {
    loop {
        let target = buf.initialize_unfilled();
        let n = unsafe { libc::read(fd, target.as_mut_ptr().cast(), target.len()) };
        if n >= 0 {
            buf.advance(n as usize);
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}
fn write(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}
impl AsyncRead for UnixIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &*self.0 {
            Handle::File(f) => Poll::Ready(read(f.as_raw_fd(), buf)),
            Handle::Poll(a) => loop {
                let mut ready = std::task::ready!(a.poll_read_ready(cx))?;
                match ready.try_io(|fd| read(fd.as_raw_fd(), buf)) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_) => continue,
                }
            },
        }
    }
}
impl AsyncWrite for UnixIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &*self.0 {
            Handle::File(f) => Poll::Ready(write(f.as_raw_fd(), bytes)),
            Handle::Poll(a) => loop {
                let mut ready = std::task::ready!(a.poll_write_ready(cx))?;
                match ready.try_io(|fd| write(fd.as_raw_fd(), bytes)) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_) => continue,
                }
            },
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct Terminal {
    fd: RawFd,
    original: libc::termios,
}
impl Terminal {
    pub fn raw(fd: RawFd) -> io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}
pub fn size() -> (u16, u16) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_row > 0
        && size.ws_col > 0
    {
        (size.ws_row, size.ws_col)
    } else {
        (24, 80)
    }
}
