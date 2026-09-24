use crate::{
    config::{Settings, random_id, valid_label},
    control::{self, Registry},
    crypto, link,
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
    id: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.registry.lock().unwrap().remove(&self.id);
    }
}
fn register(registry: Registry, link: link::Link, max: usize) -> Result<Registration> {
    let id = link.info.id.clone();
    {
        let mut peers = registry.lock().unwrap();
        ensure!(peers.len() < max, "peer limit reached");
        ensure!(!peers.contains_key(&id), "duplicate device ID");
        ensure!(
            !peers
                .values()
                .any(|p| p.info.credential == link.info.credential),
            "credential already connected (one credential per device)"
        );
        ensure!(
            !peers
                .values()
                .any(|p| p.info.name.is_some() && p.info.name == link.info.name),
            "duplicate device name"
        );
        peers.insert(id.clone(), link);
    }
    Ok(Registration { registry, id })
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
    eprintln!(
        "marriedsh: listening on {}; control {}",
        listener.local_addr()?,
        settings.socket.display()
    );
    let handshakes = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
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
                    if let Err(e) = result.context("connection task panicked").and_then(|r| r) {
                        if log_time.elapsed() >= Duration::from_secs(5) { eprintln!("marriedsh: connection ended: {e:#}"); log_time = Instant::now(); }
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
                if registry.lock().unwrap().len() >= settings.max_peers { continue; }
                let db = db.clone(); let settings = settings.clone(); let registry = registry.clone(); let id = id.clone();
                tasks.spawn(async move {
                    stream.set_nodelay(true)?;
                    let ((r, w), info) = timeout(Duration::from_secs(settings.connect_timeout_secs), async {
                        let ((mut r, mut w), credential) = crypto::server(stream, db.clone()).await?;
                        let Frame::Hello(mut info) = r.recv().await? else { anyhow::bail!("missing device metadata"); };
                        validate(&info)?;
                        ensure!(info.credential == credential, "credential binding mismatch");
                        if db.names.len() > 1 { info.name = Some(db.names[&credential].clone().unwrap_or_else(|| credential.clone())); }
                        else if let Some(name) = &db.names[&credential] { info.name = Some(name.clone()); }
                        ensure!(info.allow_exec || settings.allow_exec, "both peers deny remote execution");
                        w.send(&Frame::Hello(PeerInfo { id, name: settings.name.clone(), credential, allow_exec: settings.allow_exec })).await?;
                        Ok::<_, anyhow::Error>(((r, w), info))
                    }).await.context("handshake timed out")??;
                    drop(permit);
                    let (link, task) = link::start((r,w), info, false, settings.allow_exec, settings.heartbeat_secs, settings.heartbeat_timeout_secs);
                    let mut task = AbortTask::new(task);
                    let _registration = register(registry, link, settings.max_peers)?;
                    (&mut task.handle).await?
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
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
    loop {
        let attempt = async {
            let (pair, info) = timeout(Duration::from_secs(settings.connect_timeout_secs), async {
                let stream = TcpStream::connect(&address).await?;
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
                Ok::<_, anyhow::Error>(((r, w), info))
            })
            .await
            .context("connection/handshake timed out")??;
            let (link, task) = link::start(
                pair,
                info,
                true,
                settings.allow_exec,
                settings.heartbeat_secs,
                settings.heartbeat_timeout_secs,
            );
            let mut task = AbortTask::new(task);
            let _registration = register(registry.clone(), link, 1)?;
            eprintln!("marriedsh: connected to {address}; device ID {id}");
            (&mut task.handle).await?
        };
        tokio::select! {
            result = &mut stopping => { result?; break; }
            result = &mut control.handle => { result??; anyhow::bail!("control listener stopped"); }
            result = attempt => {
                attempts += 1;
                if last_log.elapsed() >= Duration::from_secs(30) {
                    eprintln!("marriedsh: disconnected (attempt {attempts}): {}; retrying", result.err().map(|e| format!("{e:#}")).unwrap_or_default());
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
