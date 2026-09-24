use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 65536;
pub const CHUNK: usize = 8192;
pub const WINDOW: usize = 65536;
pub const MAX_SESSIONS: usize = 8;
pub const CONTEXT: &[u8] =
    b"marriedsh/v1/opaque-ristretto255-sha512-argon2id-8192-2-1/chacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: Option<String>,
    pub credential: String,
    pub allow_exec: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
pub enum PtyMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<Vec<u8>>,
    pub pty: PtyMode,
    pub interactive: bool,
    pub term: String,
    pub rows: u16,
    pub cols: u16,
}

impl CommandSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.argv.len() <= 256, "too many arguments");
        ensure!(
            self.argv.iter().map(Vec::len).sum::<usize>() <= 32768,
            "arguments too long"
        );
        ensure!(self.argv.iter().all(|a| !a.contains(&0)), "NUL in argument");
        ensure!(
            self.term.len() <= 128 && !self.term.contains('\0'),
            "invalid TERM"
        );
        ensure!(
            self.argv.first().is_none_or(|a| !a.is_empty()),
            "empty executable"
        );
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Frame {
    Hello(PeerInfo),
    Ready,
    Open { id: u64, spec: CommandSpec },
    Opened { id: u64, pty: bool },
    Data { id: u64, stream: u8, bytes: Vec<u8> },
    Eof { id: u64 },
    Resize { id: u64, rows: u16, cols: u16 },
    Signal { id: u64, signal: i32 },
    Exit { id: u64, code: i32 },
    Error { id: u64, message: String },
    Close { id: u64 },
    Credit { id: u64, bytes: u32 },
    Ping(u64),
    Pong(u64),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalRequest {
    List,
    Open {
        name: Option<String>,
        id: Option<String>,
        spec: CommandSpec,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalReply {
    Peers(Vec<PeerInfo>),
    Credit(u32),
    Opened { pty: bool },
    Data { stream: u8, bytes: Vec<u8> },
    Exit(i32),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalInput {
    Data(Vec<u8>),
    Eof,
    Resize(u16, u16),
    Signal(i32),
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "encoded frame too large");
    Ok(bytes)
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_FRAME, "encoded frame too large");
    let (value, rest) = postcard::take_from_bytes(bytes)?;
    ensure!(rest.is_empty(), "trailing bytes in frame");
    Ok(value)
}
pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "invalid frame length"
    );
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(bytes).await?;
    Ok(())
}
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let n = r.read_u32().await? as usize;
    ensure!(n > 0 && n <= MAX_FRAME, "invalid frame length");
    let mut bytes = vec![0; n];
    r.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn write_local<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    write_packet(w, &encode(value)?).await
}
pub async fn read_local<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    decode(&read_packet(r).await?)
}

pub fn charge(n: usize) -> usize {
    n.max(1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_oversized_frame_before_allocation() {
        let mut b = &((MAX_FRAME + 1) as u32).to_be_bytes()[..];
        assert!(read_packet(&mut b).await.is_err());
    }
    #[test]
    fn rejects_trailing_bytes_and_invalid_command() {
        let mut b = encode(&Frame::Ready).unwrap();
        b.push(0);
        assert!(decode::<Frame>(&b).is_err());
        let s = CommandSpec {
            argv: vec![b"bad\0arg".to_vec()],
            pty: PtyMode::Never,
            interactive: false,
            term: "dumb".into(),
            rows: 24,
            cols: 80,
        };
        assert!(s.validate().is_err());
    }
}
