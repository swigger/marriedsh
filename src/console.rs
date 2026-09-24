use crate::{
    control,
    protocol::{self, CommandSpec, LocalInput, LocalReply, LocalRequest, PtyMode},
    runtime::AbortTask,
    unix_io::{self, Terminal, UnixIo},
};
use anyhow::{Result, bail, ensure};
use std::{ffi::OsString, os::unix::ffi::OsStrExt, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, mpsc},
};

pub async fn list(path: &Path) -> Result<()> {
    let mut socket = control::connect(path).await?;
    protocol::write_local(&mut socket, &LocalRequest::List).await?;
    let LocalReply::Peers(peers) = protocol::read_local(&mut socket).await? else {
        bail!("invalid device list");
    };
    println!("{:<32}  {:<16}  {:<16}  EXEC", "ID", "NAME", "CREDENTIAL");
    for p in peers {
        println!(
            "{:<32}  {:<16}  {:<16}  {}",
            p.id,
            p.name.as_deref().unwrap_or("-"),
            p.credential,
            if p.allow_exec { "yes" } else { "no" }
        );
    }
    Ok(())
}
pub async fn console(
    path: &Path,
    name: Option<String>,
    id: Option<String>,
    pty: PtyMode,
    argv: &[OsString],
) -> Result<i32> {
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    let (rows, cols) = unix_io::size();
    let spec = CommandSpec {
        argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        pty,
        interactive: tty,
        term: std::env::var("TERM").unwrap_or_else(|_| "dumb".into()),
        rows,
        cols,
    };
    spec.validate()?;
    let mut socket = control::connect(path).await?;
    protocol::write_local(&mut socket, &LocalRequest::Open { name, id, spec }).await?;
    let using_pty = match tokio::time::timeout(
        Duration::from_secs(30),
        protocol::read_local::<_, LocalReply>(&mut socket),
    )
    .await??
    {
        LocalReply::Opened { pty } => pty,
        LocalReply::Error(e) => bail!("{e}"),
        _ => bail!("invalid command response"),
    };
    if tty && !using_pty && !matches!(pty, PtyMode::Never) {
        eprintln!("marriedsh: PTY unavailable; using pipes");
    }
    // Install termination handlers before changing terminal state.
    use tokio::signal::unix::{SignalKind, signal};
    let mut resize = signal(SignalKind::window_change())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut quit = signal(SignalKind::quit())?;
    let _terminal = if using_pty && tty {
        Some(Terminal::raw(0)?)
    } else {
        None
    };
    let (mut reader, mut writer) = socket.into_split();
    let (tx, mut rx) = mpsc::channel::<LocalInput>(8);
    let mut network_writer = AbortTask::new(tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            protocol::write_local(&mut writer, &event).await?;
        }
        Ok::<_, anyhow::Error>(())
    }));
    let (disconnect, mut disconnected) = mpsc::channel(1);
    let credit = Arc::new(Semaphore::new(protocol::WINDOW));
    let input_credit = credit.clone();
    let input_tx = tx.clone();
    let _input = AbortTask::new(tokio::spawn(async move {
        let work = async {
            let mut stdin = UnixIo::duplicate(0)?;
            let mut buf = vec![0u8; protocol::CHUNK];
            let mut at_line_start = true;
            let mut escape = false;
            loop {
                let n = stdin.read(&mut buf).await?;
                if n == 0 {
                    if escape {
                        input_credit.acquire_many(1024).await?.forget();
                        input_tx.send(LocalInput::Data(vec![b'~'])).await?;
                    }
                    input_tx.send(LocalInput::Eof).await?;
                    return Ok::<_, anyhow::Error>(());
                }
                let mut data = Vec::with_capacity(n + 1);
                for &b in &buf[..n] {
                    if using_pty && tty {
                        if escape {
                            escape = false;
                            if b == b'.' {
                                bail!("console disconnected by ~.");
                            }
                            data.push(b'~');
                            if b == b'~' {
                                at_line_start = false;
                                continue;
                            }
                        } else if at_line_start && b == b'~' {
                            escape = true;
                            continue;
                        }
                        at_line_start = b == b'\r' || b == b'\n';
                    }
                    data.push(b);
                }
                for chunk in data.chunks(protocol::CHUNK) {
                    input_credit
                        .acquire_many(protocol::charge(chunk.len()) as u32)
                        .await?
                        .forget();
                    input_tx.send(LocalInput::Data(chunk.to_vec())).await?;
                }
            }
        }
        .await;
        if let Err(e) = work {
            // The peer may finish while stdin is still being produced. Its
            // output and exit status must win over a closed writer channel.
            if e.downcast_ref::<mpsc::error::SendError<LocalInput>>()
                .is_none()
            {
                let _ = disconnect.send(e).await;
            }
        }
    }));
    let signals = async {
        loop {
            let signal = tokio::select! {
                _ = resize.recv() => { let (r,c) = unix_io::size(); tx.send(LocalInput::Resize(r,c)).await?; continue; }
                _ = interrupt.recv() => libc::SIGINT,
                _ = term.recv() => libc::SIGTERM,
                _ = hup.recv() => libc::SIGHUP,
                _ = quit.recv() => libc::SIGQUIT,
            };
            tx.send(LocalInput::Signal(signal)).await?;
            if signal != libc::SIGINT {
                return Ok::<i32, anyhow::Error>(128 + signal);
            }
        }
    };
    let output = async {
        let mut stdout = UnixIo::duplicate(1)?;
        let mut stderr = UnixIo::duplicate(2)?;
        loop {
            match protocol::read_local::<_, LocalReply>(&mut reader).await? {
                LocalReply::Credit(n) => {
                    ensure!(
                        n > 0
                            && n as usize <= protocol::WINDOW
                            && credit.available_permits() + n as usize <= protocol::WINDOW,
                        "invalid local credit"
                    );
                    credit.add_permits(n as usize);
                }
                LocalReply::Data { stream, bytes } => {
                    ensure!(bytes.len() <= protocol::CHUNK, "oversized console output");
                    match stream {
                        1 => stdout.write_all(&bytes).await?,
                        2 => stderr.write_all(&bytes).await?,
                        _ => bail!("invalid output stream"),
                    }
                }
                LocalReply::Exit(code) => return Ok(code.clamp(0, 255)),
                LocalReply::Error(e) => bail!("{e}"),
                _ => bail!("invalid console output"),
            }
        }
    };
    tokio::pin!(output, signals);
    let mut writer_done = false;
    loop {
        tokio::select! {
            result = &mut output => return result,
            result = &mut signals => return result,
            Some(e) = disconnected.recv() => return Err(e),
            result = &mut network_writer.handle, if !writer_done => {
                writer_done = true;
                let _ = result?; // Drain the read half even after EPIPE on stdin.
            }
        }
    }
}
