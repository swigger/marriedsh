use crate::{
    config::Credential,
    protocol::{self, CONTEXT, Frame},
};
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use zeroize::{Zeroize, Zeroizing};

pub struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}
// Fixed protocol parameters, never supplied by an unauthenticated peer.
fn ksf() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(8192, 2, 1, None).unwrap(),
    )
}
fn identities(id: &str) -> Identifiers<'_> {
    Identifiers {
        client: Some(id.as_bytes()),
        server: Some(b"marriedsh/bob/v1"),
    }
}
fn params(id: &str) -> ServerLoginParameters<'_, '_> {
    ServerLoginParameters {
        context: Some(CONTEXT),
        identifiers: identities(id),
    }
}

pub struct AuthDb {
    setup: ServerSetup<Suite>,
    records: HashMap<String, ServerRegistration<Suite>>,
    pub names: HashMap<String, Option<String>>,
}
impl AuthDb {
    pub fn new(credentials: Vec<Credential>) -> Result<Self> {
        let setup = ServerSetup::new(&mut OsRng);
        let mut records = HashMap::new();
        let mut names = HashMap::new();
        for c in credentials {
            let start = ClientRegistration::<Suite>::start(&mut OsRng, c.password.as_bytes())?;
            let reply = ServerRegistration::start(&setup, start.message, c.id.as_bytes())?;
            let mut finish = start.state.finish(
                &mut OsRng,
                c.password.as_bytes(),
                reply.message,
                ClientRegistrationFinishParameters::new(identities(&c.id), Some(&ksf())),
            )?;
            finish.export_key.zeroize();
            records.insert(c.id.clone(), ServerRegistration::finish(finish.message));
            names.insert(c.id, c.name);
        }
        Ok(Self {
            setup,
            records,
            names,
        })
    }
}
#[derive(Serialize, Deserialize)]
struct Start {
    magic: [u8; 8],
    credential: String,
    request: Vec<u8>,
}
const MAGIC: [u8; 8] = *b"MRSH0001";

pub struct SecureReader<R = OwnedReadHalf> {
    inner: R,
    cipher: ChaCha20Poly1305,
    seq: u64,
}
pub struct SecureWriter<W = OwnedWriteHalf> {
    inner: W,
    cipher: ChaCha20Poly1305,
    seq: u64,
}
pub type SecurePair = (SecureReader, SecureWriter);

fn cipher(key: &[u8], label: &[u8]) -> ChaCha20Poly1305 {
    let hkdf = Hkdf::<sha2::Sha256>::new(Some(CONTEXT), key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(label, &mut *output).expect("valid HKDF length");
    ChaCha20Poly1305::new_from_slice(&*output).unwrap()
}
fn channel(stream: TcpStream, key: &[u8], client: bool) -> SecurePair {
    let (r, w) = stream.into_split();
    let c2s = b"marriedsh/v1/join-to-daemon";
    let s2c = b"marriedsh/v1/daemon-to-join";
    (
        SecureReader {
            inner: r,
            cipher: cipher(key, if client { s2c } else { c2s }),
            seq: 0,
        },
        SecureWriter {
            inner: w,
            cipher: cipher(key, if client { c2s } else { s2c }),
            seq: 0,
        },
    )
}
fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}
fn aad(n: usize, seq: u64) -> [u8; 12] {
    let mut a = [0; 12];
    a[..4].copy_from_slice(&(n as u32).to_be_bytes());
    a[4..].copy_from_slice(&seq.to_be_bytes());
    a
}
impl<R: AsyncRead + Unpin> SecureReader<R> {
    pub async fn recv(&mut self) -> Result<Frame> {
        ensure!(
            self.seq < (1u64 << 32),
            "session key frame limit reached; reconnect required"
        );
        let bytes = protocol::read_packet(&mut self.inner).await?;
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce(self.seq)),
                Payload {
                    msg: &bytes,
                    aad: &aad(bytes.len(), self.seq),
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypted frame authentication failed"))?;
        self.seq += 1;
        protocol::decode(&plain)
    }
}
impl<W: AsyncWrite + Unpin> SecureWriter<W> {
    pub async fn send(&mut self, frame: &Frame) -> Result<()> {
        ensure!(
            self.seq < (1u64 << 32),
            "session key frame limit reached; reconnect required"
        );
        let plain = protocol::encode(frame)?;
        let bytes = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce(self.seq)),
                Payload {
                    msg: &plain,
                    aad: &aad(plain.len() + 16, self.seq),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.seq += 1;
        protocol::write_packet(&mut self.inner, &bytes).await
    }
}

pub async fn client(
    mut stream: TcpStream,
    id: String,
    password: Zeroizing<String>,
) -> Result<SecurePair> {
    let start = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes())?;
    protocol::write_local(
        &mut stream,
        &Start {
            magic: MAGIC,
            credential: id.clone(),
            request: start.message.serialize().to_vec(),
        },
    )
    .await?;
    let response = CredentialResponse::deserialize(&protocol::read_packet(&mut stream).await?)?;
    let mut finish = tokio::task::spawn_blocking(move || {
        start.state.finish(
            &mut OsRng,
            password.as_bytes(),
            response,
            ClientLoginFinishParameters::new(Some(CONTEXT), identities(&id), Some(&ksf())),
        )
    })
    .await?
    .map_err(|_| {
        anyhow::anyhow!("authentication failed (password, credential or peer mismatch)")
    })?;
    protocol::write_packet(&mut stream, &finish.message.serialize()).await?;
    let (mut r, mut w) = channel(stream, &finish.session_key, true);
    finish.session_key.zeroize();
    finish.export_key.zeroize();
    w.send(&Frame::Ready).await?;
    ensure!(
        matches!(r.recv().await?, Frame::Ready),
        "missing server key confirmation"
    );
    Ok((r, w))
}
pub async fn server(mut stream: TcpStream, db: Arc<AuthDb>) -> Result<(SecurePair, String)> {
    let start: Start = protocol::read_local(&mut stream).await?;
    ensure!(
        start.magic == MAGIC && crate::config::valid_label(&start.credential),
        "invalid handshake/version"
    );
    let id = start.credential;
    let record = db.records.get(&id).cloned();
    // Unknown identities follow OPAQUE's dummy-record path.
    let reply = ServerLogin::start(
        &mut OsRng,
        &db.setup,
        record,
        CredentialRequest::deserialize(&start.request)?,
        id.as_bytes(),
        params(&id),
    )?;
    protocol::write_packet(&mut stream, &reply.message.serialize()).await?;
    let mut finish = reply
        .state
        .finish(
            CredentialFinalization::deserialize(&protocol::read_packet(&mut stream).await?)?,
            params(&id),
        )
        .context("authentication failed")?;
    ensure!(db.records.contains_key(&id), "authentication failed");
    let (mut r, mut w) = channel(stream, &finish.session_key, false);
    finish.session_key.zeroize();
    ensure!(
        matches!(r.recv().await?, Frame::Ready),
        "missing client key confirmation"
    );
    w.send(&Frame::Ready).await?;
    Ok(((r, w), id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn authenticate(server_password: &str, client_password: &str, id: &str) -> bool {
        let db = Arc::new(
            AuthDb::new(vec![Credential {
                id: "pair".into(),
                password: Zeroizing::new(server_password.into()),
                name: None,
            }])
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server(stream, db).await
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let client_result = client(stream, id.into(), Zeroizing::new(client_password.into())).await;
        let server_result = task.await.unwrap();
        match (client_result, server_result) {
            (Ok((mut cr, mut cw)), Ok(((mut sr, mut sw), _))) => {
                cw.send(&Frame::Ping(123)).await.unwrap();
                assert!(matches!(sr.recv().await.unwrap(), Frame::Ping(123)));
                sw.send(&Frame::Pong(123)).await.unwrap();
                assert!(matches!(cr.recv().await.unwrap(), Frame::Pong(123)));
                true
            }
            (Err(_), Err(_)) => false,
            _ => panic!("authentication accepted by only one endpoint"),
        }
    }

    #[tokio::test]
    async fn opaque_mutual_authentication_and_unknown_credentials() {
        assert!(authenticate("correct", "correct", "pair").await);
        assert!(!authenticate("correct", "wrong", "pair").await);
        assert!(!authenticate("impostor-server", "correct", "pair").await);
        assert!(!authenticate("correct", "correct", "unknown").await);
    }

    #[tokio::test]
    async fn daemon_rejects_network_execution_even_if_client_bypasses_cli() {
        use crate::protocol::{CommandSpec, PeerInfo, PtyMode};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = channel(client, b"test-only-key", true);
        let pair = channel(server, b"test-only-key", false);
        let info = PeerInfo {
            id: "test".into(),
            name: None,
            credential: "pair".into(),
            allow_exec: true,
        };
        let (_link, task) = crate::link::start(pair, info, false, false, 1, 3);
        let _task = crate::runtime::AbortTask::new(task);
        w.send(&Frame::Open {
            id: 1,
            spec: CommandSpec {
                argv: vec![
                    b"sh".to_vec(),
                    b"-c".to_vec(),
                    b"printf must-not-execute".to_vec(),
                ],
                pty: PtyMode::Never,
                interactive: false,
                term: "dumb".into(),
                rows: 24,
                cols: 80,
            },
        })
        .await
        .unwrap();
        assert!(
            matches!(r.recv().await.unwrap(), Frame::Error { id: 1, message } if message == "remote execution denied")
        );
        w.send(&Frame::Ping(1)).await.unwrap();
        assert!(matches!(r.recv().await.unwrap(), Frame::Pong(1)));
    }

    #[tokio::test]
    async fn record_tamper_replay_and_direction_are_rejected() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut writer = SecureWriter {
            inner: a,
            cipher: cipher(b"key", b"forward"),
            seq: 0,
        };
        writer.send(&Frame::Ping(7)).await.unwrap();
        let bytes = protocol::read_packet(&mut b).await.unwrap();
        let (mut a, b) = tokio::io::duplex(4096);
        let mut reader = SecureReader {
            inner: b,
            cipher: cipher(b"key", b"forward"),
            seq: 0,
        };
        protocol::write_packet(&mut a, &bytes).await.unwrap();
        assert!(matches!(reader.recv().await.unwrap(), Frame::Ping(7)));
        protocol::write_packet(&mut a, &bytes).await.unwrap();
        assert!(reader.recv().await.is_err());
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        let (mut a, b) = tokio::io::duplex(4096);
        let mut reader = SecureReader {
            inner: b,
            cipher: cipher(b"key", b"forward"),
            seq: 0,
        };
        protocol::write_packet(&mut a, &bad).await.unwrap();
        assert!(reader.recv().await.is_err());
        let (mut a, b) = tokio::io::duplex(4096);
        let mut reader = SecureReader {
            inner: b,
            cipher: cipher(b"key", b"reverse"),
            seq: 0,
        };
        protocol::write_packet(&mut a, &bytes).await.unwrap();
        a.shutdown().await.unwrap();
        assert!(reader.recv().await.is_err());
    }
}
