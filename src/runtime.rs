use crate::{
    config::{Settings, random_id, valid_label},
    control::{self, Registry},
    crypto, link,
    logging::log,
    protocol::{Frame, PeerInfo},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};

pub struct AbortTask<T> {
    pub handle: JoinHandle<T>,
}
impl<T> AbortTask<T> {
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self { handle }
    }
}
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
struct Registration {
    registry: Registry,
    link: link::Link,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut peers = self.registry.lock().unwrap();
        // A superseded connection must never remove its replacement, including
        // when a reconnect uses the same process-lifetime device ID.
        if peers
            .get(&self.link.info.id)
            .is_some_and(|current| current.same_connection(&self.link))
        {
            peers.remove(&self.link.info.id);
        }
    }
}
fn peer_description(info: &PeerInfo, remote: Option<std::net::SocketAddr>) -> String {
    format!(
        "id={} name={} credential={} remote={}",
        info.id,
        info.name.as_deref().unwrap_or("-"),
        info.credential,
        remote.map(|r| r.to_string()).unwrap_or_else(|| "-".into())
    )
}
fn register(registry: Registry, link: link::Link, max: usize) -> Result<Registration> {
    let id = link.info.id.clone();
    let incoming = peer_description(&link.info, link.remote);
    let replaced = {
        let mut peers = registry.lock().unwrap();
        // Only the authenticated credential identifies the device. Names and
        // random process IDs must not authorize replacing a different device.
        for existing in peers
            .values()
            .filter(|p| p.info.credential != link.info.credential)
        {
            let current = peer_description(&existing.info, existing.remote);
            ensure!(
                existing.info.id != id,
                "duplicate device ID: incoming [{incoming}]; existing [{current}]"
            );
            ensure!(
                existing.info.name.is_none() || existing.info.name != link.info.name,
                "duplicate device name: incoming [{incoming}]; existing [{current}]"
            );
        }
        let previous = peers
            .values()
            .find(|p| p.info.credential == link.info.credential)
            .cloned();
        ensure!(
            previous.is_some() || peers.len() < max,
            "peer limit reached: incoming [{incoming}]; limit={max}"
        );
        if let Some(previous) = &previous {
            peers.remove(&previous.info.id);
            previous.disconnect();
        }
        peers.insert(id, link.clone());
        previous
    };
    if let Some(previous) = replaced {
        log(format_args!(
            "connection replaced (authenticated credential reconnect): incoming [{incoming}]; previous [{}]",
            peer_description(&previous.info, previous.remote)
        ));
    }
    Ok(Registration { registry, link })
}
fn validate(info: &PeerInfo) -> Result<()> {
    ensure!(
        info.id.len() == 32 && info.id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid device ID"
    );
    ensure!(
        info.name.as_ref().is_none_or(|n| valid_label(n)) && valid_label(&info.credential),
        "invalid peer metadata"
    );
    Ok(())
}
fn shutdown() -> Result<impl std::future::Future<Output = Result<()>>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    Ok(async move {
        tokio::select! { _ = term.recv() => (), _ = interrupt.recv() => (), _ = hup.recv() => () }
        Ok(())
    })
}
pub async fn daemon(
    mut settings: Settings,
    address: String,
    startup: &mut crate::background::Startup,
) -> Result<()> {
    let credentials = std::mem::take(&mut settings.credentials);
    let db =
        Arc::new(tokio::task::spawn_blocking(move || crypto::AuthDb::new(credentials)).await??);
    let settings = Arc::new(settings);
    let listener = TcpListener::bind(&address)
        .await
        .with_context(|| format!("listening on {address}"))?;
    let (local, _guard) = control::bind(&settings.socket)?;
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let mut control = AbortTask::new(tokio::spawn(control::serve(local, registry.clone())));
    let id = random_id();
    log(format_args!(
        "listening on {}; control {}; device ID {id}; name={}",
        listener.local_addr()?,
        settings.socket.display(),
        settings.name.as_deref().unwrap_or("-")
    ));
    let handshakes = Arc::new(Semaphore::new(8));
    let mut tasks: JoinSet<(std::net::SocketAddr, Option<PeerInfo>, Result<()>)> = JoinSet::new();
    let mut rates = HashMap::<std::net::IpAddr, (Instant, u32)>::new();
    let mut log_time = Instant::now() - Duration::from_secs(60);
    let stopping = shutdown()?;
    tokio::pin!(stopping);
    let _pid_guard = startup.ready()?;
    loop {
        tokio::select! {
            r = &mut stopping => { r?; break; }
            r = &mut control.handle => { r??; anyhow::bail!("control listener stopped"); }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    match result {
                        Ok((remote, info, result)) => {
                            if let Err(e) = result {
                                // Limit unauthenticated noise, but retain every
                                // authenticated failure and its device identity.
                                if info.is_some() || log_time.elapsed() >= Duration::from_secs(5) {
                                    let peer = info.as_ref().map(|i| peer_description(i, Some(remote)))
                                        .unwrap_or_else(|| format!("remote={remote} unauthenticated"));
                                    log(format_args!("connection ended: [{peer}]: {e:#}"));
                                    if info.is_none() { log_time = Instant::now(); }
                                }
                            }
                        }
                        Err(e) => log(format_args!("connection task failed: {e}")),
                    }
                }
            }
            accepted = listener.accept() => {
                let (stream, remote) = accepted?;
                rates.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
                if rates.len() >= 128 && !rates.contains_key(&remote.ip()) { continue; }
                let rate = rates.entry(remote.ip()).or_insert((Instant::now(), 0));
                if rate.0.elapsed() >= Duration::from_secs(10) { *rate = (Instant::now(), 0); }
                if rate.1 >= 8 { continue; } rate.1 += 1;
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue; };
                tasks.spawn(serve_device(stream, remote, permit, settings.clone(), db.clone(), registry.clone(), id.clone()));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn serve_device(
    stream: TcpStream,
    remote: std::net::SocketAddr,
    permit: tokio::sync::OwnedSemaphorePermit,
    settings: Arc<Settings>,
    db: Arc<crypto::AuthDb>,
    registry: Registry,
    id: String,
) -> (std::net::SocketAddr, Option<PeerInfo>, Result<()>) {
    let mut authenticated = None;
    let result = async {
        stream.set_nodelay(true)?;
        let (pair, info) = timeout(Duration::from_secs(settings.connect_timeout_secs), async {
            let ((mut r, mut w), credential) = crypto::server(stream, db.clone()).await?;
            let Frame::Hello(mut info) = r.recv().await? else {
                anyhow::bail!("missing device metadata");
            };
            validate(&info)?;
            ensure!(info.credential == credential, "credential binding mismatch");
            info.name = info
                .name
                .or_else(|| db.names[&credential].clone())
                .or_else(|| (db.names.len() > 1).then(|| credential.clone()));
            authenticated = Some(info.clone());
            ensure!(
                info.allow_exec || settings.allow_exec,
                "both peers deny remote execution"
            );
            w.send(&Frame::Hello(PeerInfo {
                id,
                name: settings.name.clone(),
                credential,
                allow_exec: settings.allow_exec,
            }))
            .await?;
            Ok::<_, anyhow::Error>(((r, w), info))
        })
        .await
        .context("handshake timed out")??;
        drop(permit);
        let peer = peer_description(&info, Some(remote));
        let (link, task) = link::start(
            pair,
            info,
            Some(remote),
            false,
            settings.allow_exec,
            settings.heartbeat_secs,
            settings.heartbeat_timeout_secs,
        );
        let mut task = AbortTask::new(task);
        let _registration = register(registry, link, settings.max_peers)?;
        log(format_args!("device connected: [{peer}]"));
        match (&mut task.handle).await {
            Err(e) if e.is_cancelled() => Ok(()),
            result => result?,
        }
    }
    .await;
    (remote, authenticated, result)
}

pub async fn join(
    mut settings: Settings,
    address: String,
    startup: &mut crate::background::Startup,
) -> Result<()> {
    let credential = settings.credentials.pop().context("missing credential")?;
    let (local, _guard) = control::bind(&settings.socket)?;
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let mut control = AbortTask::new(tokio::spawn(control::serve(local, registry.clone())));
    let id = random_id();
    let stopping = shutdown()?;
    tokio::pin!(stopping);
    let _pid_guard = startup.ready()?;
    let mut attempts = 0u64;
    let mut last_log = Instant::now() - Duration::from_secs(60);
    let local_peer = format!(
        "id={id} name={} credential={}",
        settings.name.as_deref().unwrap_or("-"),
        settings.credential
    );
    log(format_args!(
        "joining {address}; local [{local_peer}]; control {}",
        settings.socket.display()
    ));
    loop {
        let attempt = async {
            let (pair, info, remote) =
                timeout(Duration::from_secs(settings.connect_timeout_secs), async {
                    let stream = TcpStream::connect(&address).await?;
                    let remote = stream.peer_addr()?;
                    stream.set_nodelay(true)?;
                    let (mut r, mut w) = crypto::client(
                        stream,
                        settings.credential.clone(),
                        credential.password.clone(),
                    )
                    .await?;
                    w.send(&Frame::Hello(PeerInfo {
                        id: id.clone(),
                        name: settings.name.clone(),
                        credential: settings.credential.clone(),
                        allow_exec: settings.allow_exec,
                    }))
                    .await?;
                    let Frame::Hello(info) = r.recv().await? else {
                        anyhow::bail!("missing server metadata");
                    };
                    validate(&info)?;
                    ensure!(
                        info.credential == settings.credential,
                        "credential binding mismatch"
                    );
                    ensure!(
                        info.allow_exec || settings.allow_exec,
                        "both peers deny remote execution"
                    );
                    Ok::<_, anyhow::Error>(((r, w), info, remote))
                })
                .await
                .context("connection/handshake timed out")??;
            let peer = peer_description(&info, Some(remote));
            let (link, task) = link::start(
                pair,
                info,
                Some(remote),
                true,
                settings.allow_exec,
                settings.heartbeat_secs,
                settings.heartbeat_timeout_secs,
            );
            let mut task = AbortTask::new(task);
            let _registration = register(registry.clone(), link, 1)?;
            log(format_args!(
                "connected to {address}; local [{local_peer}]; server [{peer}]"
            ));
            (&mut task.handle)
                .await?
                .with_context(|| format!("server [{peer}]"))
        };
        tokio::select! {
            result = &mut stopping => { result?; break; }
            result = &mut control.handle => { result??; anyhow::bail!("control listener stopped"); }
            result = attempt => {
                attempts += 1;
                if last_log.elapsed() >= Duration::from_secs(30) {
                    log(format_args!("disconnected from {address} (attempt {attempts}); local [{local_peer}]: {}; retrying", result.err().map(|e| format!("{e:#}")).unwrap_or_default()));
                    last_log = Instant::now();
                }
            }
        }
        let jitter = rand::random::<u32>() as f64 / u32::MAX as f64 * 0.4 + 0.8;
        tokio::select! {
            r = &mut stopping => { r?; break; }
            _ = tokio::time::sleep(Duration::from_secs_f64(settings.reconnect_secs as f64 * jitter)) => (),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_link(
        id: &str,
        name: &str,
        credential: &str,
    ) -> (link::Link, AbortTask<Result<()>>, crypto::SecurePair) {
        let db = Arc::new(
            crypto::AuthDb::new(vec![crate::config::Credential {
                id: credential.into(),
                name: None,
                password: zeroize::Zeroizing::new("test-password".into()),
            }])
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, remote) = listener.accept().await.unwrap();
        let (server, client) = tokio::join!(
            crypto::server(server, db),
            crypto::client(
                client,
                credential.into(),
                zeroize::Zeroizing::new("test-password".into())
            )
        );
        let (link, task) = link::start(
            server.unwrap().0,
            PeerInfo {
                id: id.into(),
                name: Some(name.into()),
                credential: credential.into(),
                allow_exec: true,
            },
            Some(remote),
            false,
            false,
            60,
            180,
        );
        (link, AbortTask::new(task), client.unwrap())
    }

    #[tokio::test]
    async fn reconnect_aborts_old_link_and_old_guard_cannot_remove_replacement() {
        for new_id in ["old-id", "new-id"] {
            let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
            let (old, mut old_task, _old_pair) = test_link("old-id", "alice", "alice-key").await;
            let old_registration = register(registry.clone(), old, 1).unwrap();
            let (new, _new_task, _new_pair) = test_link(new_id, "alice", "alice-key").await;
            let new_registration = register(registry.clone(), new.clone(), 1).unwrap();
            assert!((&mut old_task.handle).await.unwrap_err().is_cancelled());
            drop(old_registration);
            let peers = registry.lock().unwrap();
            assert_eq!(peers.len(), 1);
            assert!(peers[new_id].same_connection(&new));
            drop(peers);
            drop(new_registration);
            assert!(registry.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn different_credentials_cannot_take_over_by_id_or_name() {
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let (old, old_task, _old_pair) = test_link("old-id", "alice", "alice-key").await;
        let _registration = register(registry.clone(), old.clone(), 2).unwrap();
        for (id, name, reason) in [
            ("old-id", "clark", "duplicate device ID"),
            ("clark-id", "alice", "duplicate device name"),
            ("clark-id", "clark", "peer limit reached"),
        ] {
            let (other, _task, _pair) = test_link(id, name, "clark-key").await;
            let error = register(registry.clone(), other, 1)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains(reason), "{error}");
            assert!(error.contains("incoming [id="), "{error}");
            if reason != "peer limit reached" {
                assert!(
                    error.contains(
                        "existing [id=old-id name=alice credential=alice-key remote=127.0.0.1:"
                    ),
                    "{error}"
                );
                assert!(
                    error.contains("credential=clark-key remote=127.0.0.1:"),
                    "{error}"
                );
            }
            assert!(registry.lock().unwrap()["old-id"].same_connection(&old));
            assert!(!old_task.handle.is_finished());
        }
    }

    #[tokio::test]
    async fn conflicting_reconnect_preserves_both_existing_connections() {
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let (alice, alice_task, _alice_pair) = test_link("alice-id", "alice", "alice-key").await;
        let (clark, clark_task, _clark_pair) = test_link("clark-id", "clark", "clark-key").await;
        let _alice = register(registry.clone(), alice.clone(), 2).unwrap();
        let _clark = register(registry.clone(), clark.clone(), 2).unwrap();
        let (reconnect, _task, _pair) = test_link("clark-id", "alice", "alice-key").await;
        assert!(register(registry.clone(), reconnect, 2).is_err());
        let peers = registry.lock().unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers["alice-id"].same_connection(&alice));
        assert!(peers["clark-id"].same_connection(&clark));
        assert!(!alice_task.handle.is_finished() && !clark_task.handle.is_finished());
    }
}
