use crate::{
    config,
    link::{Event, Link},
    protocol::{self, Frame, LocalInput, LocalReply, LocalRequest},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

pub type Registry = Arc<Mutex<HashMap<String, Link>>>;
pub struct SocketGuard {
    path: PathBuf,
    inode: u64,
    _lock: File,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.ino() == self.inode && m.file_type().is_socket())
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub fn private_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("socket needs a directory path")?;
    let mut builder = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.recursive(true).mode(0o700).create(parent)?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "socket directory {} must be owned by this user with mode 0700",
        parent.display()
    );
    Ok(())
}
pub fn bind(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    private_directory(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.with_extension("lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "unsafe socket lock file"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another marriedsh instance owns {}",
        path.display()
    );
    match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() },
                "refusing to replace non-socket or foreign socket"
            );
            ensure!(
                std::os::unix::net::UnixStream::connect(path).is_err(),
                "socket is already active"
            );
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let inode = fs::symlink_metadata(path)?.ino();
    Ok((
        listener,
        SocketGuard {
            path: path.to_owned(),
            inode,
            _lock: lock,
        },
    ))
}
pub async fn connect(path: &Path) -> Result<UnixStream> {
    let m = fs::symlink_metadata(path).with_context(|| {
        format!(
            "no local daemon/join at {}; use --socket to select it",
            path.display()
        )
    })?;
    ensure!(
        m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "unsafe control socket"
    );
    let stream = UnixStream::connect(path).await?;
    ensure!(
        stream.peer_cred()?.uid() == unsafe { libc::geteuid() },
        "control socket user mismatch"
    );
    Ok(stream)
}
pub async fn serve(listener: UnixListener, registry: Registry) -> Result<()> {
    let limit = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (stream, _) = incoming?;
                if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } { continue; }
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                let registry = registry.clone();
                tasks.spawn(async move { let _permit = permit; let _ = handle(stream, registry).await; });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => (),
        }
    }
}
fn choose(registry: &Registry, name: Option<String>, id: Option<String>) -> Result<Link> {
    ensure!(
        name.is_none() || id.is_none(),
        "choose a name or ID, not both"
    );
    if let Some(n) = &name {
        ensure!(config::valid_label(n), "invalid name");
    }
    let peers = registry.lock().unwrap();
    let mut matched = peers.values().filter(|l| {
        name.as_ref()
            .is_none_or(|n| l.info.name.as_ref() == Some(n))
            && id.as_ref().is_none_or(|id| l.info.id == *id)
    });
    let first = matched
        .next()
        .context("no matching connected device")?
        .clone();
    ensure!(
        matched.next().is_none(),
        "ambiguous device; use -n or --id (see marriedsh list)"
    );
    Ok(first)
}
async fn handle(mut stream: UnixStream, registry: Registry) -> Result<()> {
    let request: LocalRequest =
        tokio::time::timeout(Duration::from_secs(10), protocol::read_local(&mut stream)).await??;
    match request {
        LocalRequest::List => {
            let mut peers: Vec<_> = registry
                .lock()
                .unwrap()
                .values()
                .map(|l| l.info.clone())
                .collect();
            peers.sort_by(|a, b| a.id.cmp(&b.id));
            protocol::write_local(&mut stream, &LocalReply::Peers(peers)).await
        }
        LocalRequest::Open { name, id, spec } => {
            let opened = async {
                spec.validate()?;
                choose(&registry, name, id)?.open(spec).await
            }
            .await;
            let mut session = match opened {
                Ok(s) => s,
                Err(e) => {
                    protocol::write_local(&mut stream, &LocalReply::Error(e.to_string())).await?;
                    return Ok(());
                }
            };
            let (mut r, mut w) = stream.into_split();
            let sender = session.sender.clone();
            let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<
                Option<(Vec<u8>, tokio::sync::OwnedSemaphorePermit)>,
            >(80);
            let budget = Arc::new(Semaphore::new(protocol::WINDOW));
            let (credit_tx, mut credits) = tokio::sync::mpsc::channel(80);
            let data_sender = sender.clone();
            let pump = tokio::spawn(async move {
                while let Some(data) = data_rx.recv().await {
                    match data {
                        Some((bytes, permit)) => {
                            let n = protocol::charge(bytes.len());
                            data_sender.data(0, bytes).await?;
                            drop(permit);
                            credit_tx.send(n as u32).await?;
                        }
                        None => {
                            data_sender.eof().await?;
                            break;
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
            let mut pump = crate::runtime::AbortTask::new(pump);
            let mut pump_done = false;
            // A dedicated reader avoids cancelling a partially read length-prefixed frame.
            // Local credit prevents stdin from blocking signal/EOF/disconnect detection.
            let input = tokio::spawn(async move {
                let mut eof = false;
                loop {
                    match protocol::read_local::<_, LocalInput>(&mut r).await? {
                        LocalInput::Data(bytes) => {
                            ensure!(!eof, "data after EOF");
                            ensure!(
                                !bytes.is_empty() && bytes.len() <= protocol::CHUNK,
                                "invalid console input"
                            );
                            let permit = budget
                                .clone()
                                .try_acquire_many_owned(protocol::charge(bytes.len()) as u32)?;
                            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                                data_tx.try_send(Some((bytes, permit)))
                            {
                                bail!("console input queue overflow");
                            }
                        }
                        LocalInput::Eof => {
                            ensure!(!eof, "duplicate EOF");
                            eof = true;
                            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                                data_tx.try_send(None)
                            {
                                bail!("console input queue overflow");
                            }
                        }
                        LocalInput::Resize(rows, cols) => {
                            sender
                                .frame(Frame::Resize {
                                    id: sender.id,
                                    rows,
                                    cols,
                                })
                                .await?
                        }
                        LocalInput::Signal(signal) => {
                            sender
                                .frame(Frame::Signal {
                                    id: sender.id,
                                    signal,
                                })
                                .await?
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            });
            let mut input = crate::runtime::AbortTask::new(input);
            let mut started = false;
            loop {
                tokio::select! {
                    _ = &mut input.handle => bail!("console disconnected"),
                    result = &mut pump.handle, if !pump_done => {
                        pump_done = true;
                        // A command may exit before consuming all input. Drain its
                        // queued output/exit status even if its input credit closes.
                        let _ = result?;
                    }
                    Some(n) = credits.recv() => protocol::write_local(&mut w, &LocalReply::Credit(n)).await?,
                    event = session.events.recv() => {
                        let reply = match event {
                            Some(Event::Opened(pty)) if !started => { started = true; LocalReply::Opened { pty } }
                            Some(Event::Data(stream, bytes)) if started => {
                                let n = bytes.len(); protocol::write_local(&mut w, &LocalReply::Data { stream, bytes }).await?;
                                session.sender.consumed(n)?; continue;
                            }
                            Some(Event::Exit(code)) if started => { protocol::write_local(&mut w, &LocalReply::Exit(code)).await?; break; }
                            Some(Event::Error(e)) => { protocol::write_local(&mut w, &LocalReply::Error(e)).await?; break; }
                            None => { protocol::write_local(&mut w, &LocalReply::Error("connection lost; command outcome is unknown and it will not be replayed".into())).await?; break; }
                            _ => bail!("unexpected session response"),
                        };
                        protocol::write_local(&mut w, &reply).await?;
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn socket_lock_permissions_and_cleanup() {
        let dir = std::path::Path::new("/tmp").join(format!("mrsh-{}", config::random_id()));
        let path = dir.join("control.sock");
        let (listener, guard) = bind(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(bind(&path).is_err());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
