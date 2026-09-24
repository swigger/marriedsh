use crate::protocol::PtyMode;
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Pair Unix machines over an authenticated channel")]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    /// Listen for paired devices (background by default).
    Daemon {
        #[command(flatten)]
        options: ConnectOptions,
        address: String,
    },
    /// Connect in the background and keep reconnecting until stopped.
    Join {
        #[command(flatten)]
        options: ConnectOptions,
        address: String,
    },
    /// List directly connected devices through the local Unix socket.
    List,
    /// Run a command or a login shell on a directly connected device.
    Console {
        #[arg(short = 'n', long, conflicts_with = "id")]
        name: Option<String>,
        #[arg(long)]
        id: Option<String>,
        #[arg(long, value_enum, default_value = "auto")]
        pty: PtyMode,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<OsString>,
    },
    /// Generate a random 256-bit pairing password.
    Keygen,
}
#[derive(Args)]
pub struct ConnectOptions {
    /// Stay attached to this terminal (for debugging or service managers).
    #[arg(short = 'f', long)]
    pub foreground: bool,
    /// Hold this flock for the service lifetime; silently succeed if already held.
    #[arg(long, value_name = "PATH")]
    pub lock: Option<PathBuf>,
    #[arg(short = 'n', long)]
    pub name: Option<String>,
    #[arg(short = 'p', long, conflicts_with = "psk_file")]
    pub psk: Option<String>,
    #[arg(long)]
    pub psk_file: Option<PathBuf>,
    /// Public credential selector; configure independent passwords for each pair.
    #[arg(long)]
    pub credential: Option<String>,
    #[arg(long)]
    pub reconnect_secs: Option<u64>,
    #[arg(long)]
    pub heartbeat_secs: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub name: Option<String>,
    pub psk: Option<String>,
    pub credential: Option<String>,
    pub socket: Option<PathBuf>,
    pub allow_remote_exec: Option<bool>,
    pub reconnect_secs: Option<u64>,
    pub heartbeat_secs: Option<u64>,
    pub heartbeat_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    pub max_peers: Option<usize>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub id: String,
    pub psk: String,
    pub name: Option<String>,
}

pub struct Credential {
    pub id: String,
    pub password: Zeroizing<String>,
    pub name: Option<String>,
}
pub struct Settings {
    pub name: Option<String>,
    pub credential: String,
    pub credentials: Vec<Credential>,
    pub socket: PathBuf,
    pub allow_exec: bool,
    pub reconnect_secs: u64,
    pub heartbeat_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_peers: usize,
}

pub fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn private_read(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "{} must be a regular file owned by this user with mode 0600",
        path.display()
    );
    ensure!(m.len() <= 1024 * 1024, "configuration too large");
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)?;
    Ok(text)
}
pub fn load(path: Option<&PathBuf>) -> Result<FileConfig> {
    let p = match path {
        Some(p) => p.clone(),
        None => config_home()?.join("marriedsh/config.toml"),
    };
    match private_read(&p) {
        Ok(text) => toml::from_str(&text).map_err(|_| anyhow::anyhow!("invalid config.toml (unknown field, type or syntax); values suppressed to protect secrets")),
        Err(e) if path.is_none() && e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => Ok(FileConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}
fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset; provide --config and --socket")
}
fn config_home() -> Result<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| home().map(|p| p.join(".config")))
}
pub fn socket_path(cli: &Cli, f: &FileConfig) -> Result<PathBuf> {
    if let Some(p) = cli.socket.as_ref().or(f.socket.as_ref()) {
        return Ok(p.clone());
    }
    if let Some(p) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(p).join("marriedsh/control.sock"));
    }
    Ok(home()?.join(".marriedsh/run/control.sock"))
}
pub fn settings(
    cli: &Cli,
    mut f: FileConfig,
    o: &ConnectOptions,
    daemon: bool,
) -> Result<Settings> {
    let socket = socket_path(cli, &f)?;
    let name = o.name.clone().or(f.name.take());
    ensure!(
        name.as_ref().is_none_or(|s| valid_label(s)),
        "invalid name (use 1–64 ASCII letters, digits, '.', '_' or '-')"
    );
    let credential = o
        .credential
        .clone()
        .or(f.credential.take())
        .unwrap_or_else(|| "pair".into());
    ensure!(valid_label(&credential), "invalid credential ID");
    let has_cli_password = o.psk.is_some() || o.psk_file.is_some();
    ensure!(
        !daemon || f.peers.is_empty() || (!has_cli_password && f.psk.is_none()),
        "use either a single PSK or [[peers]], not both"
    );
    let mut credentials = Vec::new();
    if daemon && !f.peers.is_empty() {
        for p in f.peers.drain(..) {
            credentials.push(Credential {
                id: p.id,
                password: Zeroizing::new(p.psk),
                name: p.name,
            });
        }
    } else {
        let password = if let Some(p) = &o.psk {
            Zeroizing::new(p.clone())
        } else if let Some(p) = &o.psk_file {
            let mut s = private_read(p)?;
            while s.ends_with(['\r', '\n']) {
                s.pop();
            }
            s
        } else if let Some(p) = f.psk.take() {
            Zeroizing::new(p)
        } else {
            ensure!(
                std::io::IsTerminal::is_terminal(&std::io::stdin()),
                "no PSK configured; use -p, --psk-file or config.toml"
            );
            Zeroizing::new(rpassword::prompt_password("Pairing password: ")?)
        };
        credentials.push(Credential {
            id: credential.clone(),
            password,
            name: None,
        });
    }
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for c in &credentials {
        ensure!(
            valid_label(&c.id) && ids.insert(c.id.clone()),
            "invalid or duplicate credential ID"
        );
        ensure!(
            !c.password.is_empty() && c.password.len() <= 1024,
            "password must contain 1–1024 bytes"
        );
        if let Some(n) = &c.name {
            ensure!(
                valid_label(n) && names.insert(n.clone()),
                "invalid or duplicate configured peer name"
            );
        }
    }
    for (i, a) in credentials.iter().enumerate() {
        for b in &credentials[..i] {
            ensure!(
                a.password != b.password,
                "each pair must use a different PSK"
            );
        }
    }
    let reconnect_secs = o.reconnect_secs.or(f.reconnect_secs).unwrap_or(5);
    let heartbeat_secs = o.heartbeat_secs.or(f.heartbeat_secs).unwrap_or(60);
    let heartbeat_timeout_secs = f
        .heartbeat_timeout_secs
        .unwrap_or(heartbeat_secs.saturating_mul(3));
    let connect_timeout_secs = f.connect_timeout_secs.unwrap_or(15);
    let max_peers = f.max_peers.unwrap_or(32);
    ensure!(
        (1..=86400).contains(&reconnect_secs) && (1..=86400).contains(&heartbeat_secs),
        "invalid reconnect/heartbeat interval"
    );
    ensure!(
        heartbeat_timeout_secs > heartbeat_secs
            && heartbeat_timeout_secs <= 604800
            && (1..=300).contains(&connect_timeout_secs),
        "invalid timeout"
    );
    ensure!((1..=256).contains(&max_peers), "max_peers must be 1–256");
    let allow_exec = f.allow_remote_exec.unwrap_or(!daemon);
    if daemon && allow_exec {
        bail!(
            "Bob-side remote execution requires OS-level isolation and is not enabled in v1; set allow_remote_exec=false"
        );
    }
    Ok(Settings {
        name,
        credential,
        credentials,
        socket,
        allow_exec,
        reconnect_secs,
        heartbeat_secs,
        heartbeat_timeout_secs,
        connect_timeout_secs,
        max_peers,
    })
}
