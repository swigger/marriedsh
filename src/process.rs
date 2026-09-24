use crate::{
    link::{Event, Sender, Session},
    protocol::{CHUNK, CommandSpec, Frame, PtyMode},
    unix_io::UnixIo,
};
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, OsString},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStringExt,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::Path,
    process::Stdio,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    sync::mpsc,
    task::JoinHandle,
};

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;
struct Group(u32);
impl Drop for Group {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                libc::kill(-(self.0 as i32), libc::SIGKILL);
            }
        }
    }
}
struct Pumps(Vec<JoinHandle<Result<()>>>);
impl Drop for Pumps {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}
fn shell() -> OsString {
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    if unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    } == 0
        && !result.is_null()
        && !entry.pw_shell.is_null()
    {
        let bytes = unsafe { CStr::from_ptr(entry.pw_shell) }.to_bytes();
        if !bytes.is_empty() {
            return OsString::from_vec(bytes.to_vec());
        }
    }
    "/bin/sh".into()
}
fn pty(rows: u16, cols: u16) -> Result<(UnixIo, OwnedFd)> {
    let mut master = -1;
    let mut slave = -1;
    let mut size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    for fd in [&master, &slave] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok((UnixIo::new(master)?, slave))
}
async fn output(mut reader: Reader, sender: Sender, stream: u8, pty: bool) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => n,
            Err(e) if pty && e.raw_os_error() == Some(libc::EIO) => 0,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(());
        }
        sender.data(stream, buf[..n].to_vec()).await?;
    }
}
pub async fn execute(mut session: Session, spec: CommandSpec) {
    if let Err(e) = run(&mut session, spec).await {
        let message: String = format!("command failed: {e:#}").chars().take(512).collect();
        let _ = session
            .sender
            .frame(Frame::Error {
                id: session.sender.id,
                message,
            })
            .await;
    }
}
async fn run(session: &mut Session, spec: CommandSpec) -> Result<()> {
    spec.validate()?;
    let want_pty = matches!(spec.pty, PtyMode::Always)
        || (matches!(spec.pty, PtyMode::Auto) && spec.interactive);
    let terminal = if want_pty {
        match pty(spec.rows, spec.cols) {
            Ok(p) => Some(p),
            Err(e) if matches!(spec.pty, PtyMode::Always) => {
                return Err(e.context("PTY required but unavailable"));
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let using_pty = terminal.is_some();
    let mut command = if spec.argv.is_empty() {
        let shell = shell();
        let mut c = Command::new(&shell);
        let mut arg0 = OsString::from("-");
        arg0.push(Path::new(&shell).file_name().unwrap_or(shell.as_os_str()));
        c.as_std_mut().arg0(arg0);
        if let Some(home) = std::env::var_os("HOME") {
            if Path::new(&home).is_dir() {
                c.current_dir(home);
            }
        }
        c
    } else {
        let mut c = Command::new(OsString::from_vec(spec.argv[0].clone()));
        c.args(spec.argv[1..].iter().cloned().map(OsString::from_vec));
        c
    };
    if using_pty {
        command.env("TERM", &spec.term);
    }
    command.kill_on_drop(true);
    let master = if let Some((master, slave)) = terminal {
        command
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        Some(master)
    } else {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        None
    };
    // Only async-signal-safe libc operations are allowed between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if using_pty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for sig in [
                libc::SIGPIPE,
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGHUP,
                libc::SIGQUIT,
            ] {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("exec")?;
    drop(command); // close the parent's slave descriptors
    let pid = child.id().context("missing child PID")?;
    let mut group = Group(pid);
    let (mut stdin, stdout, stderr): (Writer, Reader, Option<Reader>) = if let Some(m) = &master {
        (Box::new(m.clone()), Box::new(m.clone()), None)
    } else {
        (
            Box::new(child.stdin.take().unwrap()),
            Box::new(child.stdout.take().unwrap()),
            Some(Box::new(child.stderr.take().unwrap())),
        )
    };
    session
        .sender
        .frame(Frame::Opened {
            id: session.sender.id,
            pty: using_pty,
        })
        .await?;
    let (input, mut data) = mpsc::channel::<Option<Vec<u8>>>(80);
    let sender = session.sender.clone();
    let eof_terminal = master.clone();
    let mut pumps = Pumps(Vec::new());
    let input_task = tokio::spawn(async move {
        while let Some(bytes) = data.recv().await {
            match bytes {
                Some(bytes) => {
                    // Continue consuming credits after a child closes stdin early.
                    match stdin.write_all(&bytes).await {
                        Ok(()) => (),
                        Err(e)
                            if matches!(e.kind(), std::io::ErrorKind::BrokenPipe)
                                || e.raw_os_error() == Some(libc::EIO) => {}
                        Err(e) => return Err(e.into()),
                    }
                    sender.consumed(bytes.len())?;
                }
                None => {
                    if let Some(m) = &eof_terminal {
                        let mut term = unsafe { std::mem::zeroed::<libc::termios>() };
                        if unsafe { libc::tcgetattr(m.as_raw_fd(), &mut term) } == 0
                            && term.c_lflag & libc::ICANON != 0
                        {
                            stdin.write_all(&[term.c_cc[libc::VEOF]; 2]).await?;
                        }
                    } else {
                        stdin.shutdown().await?;
                    }
                    break;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    pumps.0.push(tokio::spawn(output(
        stdout,
        session.sender.clone(),
        1,
        using_pty,
    )));
    if let Some(stderr) = stderr {
        pumps.0.push(tokio::spawn(output(
            stderr,
            session.sender.clone(),
            2,
            false,
        )));
    }
    let mut input_task = crate::runtime::AbortTask::new(input_task);
    let mut eof = false;
    let mut input_done = false;
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            event = session.events.recv() => match event {
                Some(Event::Data(0, bytes)) if !eof => input.try_send(Some(bytes)).map_err(|_| anyhow::anyhow!("stdin queue overflow"))?,
                Some(Event::Eof) if !eof => { eof = true; input.try_send(None)?; }
                Some(Event::Resize(rows, cols)) => if let Some(m) = &master { m.resize(rows, cols)?; },
                Some(Event::Signal(signal)) => { unsafe { libc::kill(-(pid as i32), signal); } }
                None => bail!("controller disconnected"),
                _ => bail!("invalid command input"),
            },
            result = &mut input_task.handle, if !input_done => { input_done = true; result??; }
        }
    };
    // Do not leave background children holding output pipes or executing after the session.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    group.0 = 0;
    input_task.handle.abort();
    for pump in &mut pumps.0 {
        pump.await??;
    }
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    session
        .sender
        .frame(Frame::Exit {
            id: session.sender.id,
            code,
        })
        .await?;
    Ok(())
}
