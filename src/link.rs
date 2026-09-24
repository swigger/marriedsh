use crate::{
    crypto::SecurePair,
    protocol::{self, CommandSpec, Frame, MAX_SESSIONS, PeerInfo, WINDOW},
};
use anyhow::{Result, bail, ensure};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout},
};

pub enum Event {
    Opened(bool),
    Data(u8, Vec<u8>),
    Eof,
    Resize(u16, u16),
    Signal(i32),
    Exit(i32),
    Error(String),
}
enum Request {
    Open(CommandSpec, oneshot::Sender<Result<Session>>),
    Consumed(u64, usize),
    Finished(u64),
}
#[derive(Clone)]
pub struct Link {
    pub info: PeerInfo,
    requests: mpsc::UnboundedSender<Request>,
}
impl Link {
    pub async fn open(&self, spec: CommandSpec) -> Result<Session> {
        ensure!(self.info.allow_exec, "peer does not allow remote execution");
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(Request::Open(spec, tx))
            .map_err(|_| anyhow::anyhow!("device disconnected"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("device disconnected"))?
    }
}
pub struct Session {
    pub sender: Sender,
    pub events: mpsc::Receiver<Event>,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.sender.requests.send(Request::Finished(self.sender.id));
    }
}
#[derive(Clone)]
pub struct Sender {
    pub id: u64,
    net: mpsc::Sender<Frame>,
    credit: Arc<Semaphore>,
    requests: mpsc::UnboundedSender<Request>,
}
impl Sender {
    pub async fn frame(&self, frame: Frame) -> Result<()> {
        self.net
            .send(frame)
            .await
            .map_err(|_| anyhow::anyhow!("device disconnected"))
    }
    pub async fn data(&self, stream: u8, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= protocol::CHUNK,
            "invalid data size"
        );
        self.credit
            .acquire_many(protocol::charge(bytes.len()) as u32)
            .await?
            .forget();
        self.frame(Frame::Data {
            id: self.id,
            stream,
            bytes,
        })
        .await
    }
    pub fn consumed(&self, n: usize) -> Result<()> {
        self.requests
            .send(Request::Consumed(self.id, protocol::charge(n)))
            .map_err(|_| anyhow::anyhow!("device disconnected"))
    }
    pub async fn eof(&self) -> Result<()> {
        self.frame(Frame::Eof { id: self.id }).await
    }
}
struct Entry {
    events: mpsc::Sender<Event>,
    credit: Arc<Semaphore>,
    remaining: usize,
    executor: bool,
    task: Option<JoinHandle<()>>,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.credit.close();
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}
struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

pub fn start(
    pair: SecurePair,
    info: PeerInfo,
    client: bool,
    allow_exec: bool,
    heartbeat: u64,
    dead: u64,
) -> (Link, JoinHandle<Result<()>>) {
    let (requests, rx) = mpsc::unbounded_channel();
    let link = Link {
        info,
        requests: requests.clone(),
    };
    let task = tokio::spawn(run(pair, requests, rx, client, allow_exec, heartbeat, dead));
    (link, task)
}
fn session(
    id: u64,
    executor: bool,
    net: &mpsc::Sender<Frame>,
    requests: &mpsc::UnboundedSender<Request>,
) -> (Session, Entry) {
    let (tx, rx) = mpsc::channel(80);
    let credit = Arc::new(Semaphore::new(WINDOW));
    (
        Session {
            sender: Sender {
                id,
                net: net.clone(),
                credit: credit.clone(),
                requests: requests.clone(),
            },
            events: rx,
        },
        Entry {
            events: tx,
            credit,
            remaining: WINDOW,
            executor,
            task: None,
        },
    )
}
async fn run(
    pair: SecurePair,
    requests: mpsc::UnboundedSender<Request>,
    mut rx: mpsc::UnboundedReceiver<Request>,
    client: bool,
    allow_exec: bool,
    heartbeat: u64,
    dead: u64,
) -> Result<()> {
    let (mut reader, mut writer) = pair;
    let (net, mut out) = mpsc::channel::<Frame>(64);
    let (incoming, mut input) = mpsc::channel(8);
    let r = tokio::spawn(async move {
        loop {
            let frame = reader.recv().await;
            let bad = frame.is_err();
            if incoming.send(frame).await.is_err() || bad {
                break;
            }
        }
    });
    let (failed, mut failure) = mpsc::channel(1);
    let w = tokio::spawn(async move {
        while let Some(frame) = out.recv().await {
            if let Err(e) = async {
                timeout(Duration::from_secs(30), writer.send(&frame)).await??;
                Ok::<_, anyhow::Error>(())
            }
            .await
            {
                let _ = failed.send(e).await;
                break;
            }
        }
    });
    let _tasks = Tasks(vec![r, w]);
    let mut entries = HashMap::<u64, Entry>::new();
    let mut next = if client { 1u64 } else { 2u64 };
    let mut remote_last = 0;
    let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_alive = Instant::now();
    let mut pending_ping = None;
    let mut ping = 0u64;
    loop {
        tokio::select! {
            err = failure.recv() => bail!("network writer stopped: {}", err.map(|e| e.to_string()).unwrap_or_default()),
            _ = ticker.tick() => {
                ensure!(last_alive.elapsed() < Duration::from_secs(dead), "heartbeat timed out");
                if client && pending_ping.is_none() { ping = ping.wrapping_add(1); pending_ping = Some(ping); net.send(Frame::Ping(ping)).await?; }
            }
            request = rx.recv() => match request {
                Some(Request::Open(spec, reply)) => {
                    if entries.len() >= MAX_SESSIONS { let _ = reply.send(Err(anyhow::anyhow!("session limit reached"))); continue; }
                    spec.validate()?;
                    let id = next; next = next.checked_add(2).ok_or_else(|| anyhow::anyhow!("session ID exhausted"))?;
                    let (s, entry) = session(id, false, &net, &requests);
                    entries.insert(id, entry);
                    net.send(Frame::Open { id, spec }).await?;
                    let _ = reply.send(Ok(s));
                }
                Some(Request::Consumed(id, n)) => if let Some(e) = entries.get_mut(&id) {
                    ensure!(e.remaining + n <= WINDOW, "internal flow-control accounting error");
                    e.remaining += n; net.send(Frame::Credit { id, bytes: n as u32 }).await?;
                },
                Some(Request::Finished(id)) => if entries.remove(&id).is_some() { net.send(Frame::Close { id }).await?; },
                None => break,
            },
            frame = input.recv() => {
                let frame = frame.ok_or_else(|| anyhow::anyhow!("device disconnected"))??;
                match frame {
                    Frame::Ping(n) => { ensure!(!client, "unexpected ping direction"); last_alive = Instant::now(); net.send(Frame::Pong(n)).await?; }
                    Frame::Pong(n) => { ensure!(client && pending_ping == Some(n), "unexpected pong"); pending_ping = None; last_alive = Instant::now(); }
                    Frame::Open { id, spec } => {
                        ensure!(id > remote_last && id % 2 == if client { 0 } else { 1 }, "invalid or reused session ID");
                        remote_last = id;
                        if !allow_exec || entries.len() >= MAX_SESSIONS {
                            net.send(Frame::Error { id, message: if !allow_exec { "remote execution denied" } else { "session limit reached" }.into() }).await?; continue;
                        }
                        if let Err(e) = spec.validate() { net.send(Frame::Error { id, message: e.to_string() }).await?; continue; }
                        let (s, mut entry) = session(id, true, &net, &requests);
                        entry.task = Some(tokio::spawn(crate::process::execute(s, spec)));
                        entries.insert(id, entry);
                    }
                    Frame::Close { id } => { entries.remove(&id); }
                    Frame::Credit { id, bytes } => if let Some(e) = entries.get(&id) {
                        ensure!(bytes > 0 && bytes as usize <= WINDOW && e.credit.available_permits() + bytes as usize <= WINDOW, "invalid window update");
                        e.credit.add_permits(bytes as usize);
                    },
                    Frame::Data { id, stream, bytes } => if let Some(e) = entries.get_mut(&id) {
                        ensure!(!bytes.is_empty() && bytes.len() <= protocol::CHUNK && ((e.executor && stream == 0) || (!e.executor && (stream == 1 || stream == 2))), "invalid session data");
                        let n = protocol::charge(bytes.len()); ensure!(n <= e.remaining, "flow-control window exceeded"); e.remaining -= n;
                        e.events.try_send(Event::Data(stream, bytes)).map_err(|_| anyhow::anyhow!("session control queue overflow"))?;
                    },
                    Frame::Opened { id, pty } => deliver(&entries, id, false, Event::Opened(pty))?,
                    Frame::Exit { id, code } => deliver(&entries, id, false, Event::Exit(code))?,
                    Frame::Error { id, message } => { ensure!(message.len() <= 1024, "error too long"); deliver(&entries, id, false, Event::Error(message))?; }
                    Frame::Eof { id } => deliver(&entries, id, true, Event::Eof)?,
                    Frame::Resize { id, rows, cols } => deliver(&entries, id, true, Event::Resize(rows, cols))?,
                    Frame::Signal { id, signal } => {
                        ensure!([libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT].contains(&signal), "unsupported signal");
                        deliver(&entries, id, true, Event::Signal(signal))?;
                    }
                    _ => bail!("unexpected connection control frame"),
                }
            }
        }
    }
    Ok(())
}
fn deliver(entries: &HashMap<u64, Entry>, id: u64, executor: bool, event: Event) -> Result<()> {
    if let Some(e) = entries.get(&id) {
        ensure!(e.executor == executor, "invalid session direction");
        e.events
            .try_send(event)
            .map_err(|_| anyhow::anyhow!("session control queue overflow"))?;
    }
    Ok(())
}
