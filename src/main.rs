#![cfg(unix)]
mod background;
mod config;
mod console;
mod control;
mod crypto;
mod link;
mod process;
mod protocol;
mod runtime;
mod unix_io;

use anyhow::Result;
use clap::Parser;
use config::{Cli, Command};

fn main() -> std::process::ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("marriedsh: {e:#}");
            std::process::ExitCode::from(255)
        }
    }
}

fn execute(cli: Cli) -> Result<i32> {
    // Resolve files and read the password while still attached to the terminal.
    // No runtime or worker thread may exist when detach() forks.
    let config = if matches!(cli.command, Command::Keygen) {
        config::FileConfig::default()
    } else {
        config::load(cli.config.as_ref())?
    };
    let socket = if matches!(cli.command, Command::List | Command::Console { .. }) {
        Some(config::socket_path(&cli, &config)?)
    } else {
        None
    };
    let mut startup = background::Startup::default();
    let settings = match &cli.command {
        Command::Daemon { options, .. } | Command::Join { options, .. } => {
            let daemon = matches!(cli.command, Command::Daemon { .. });
            let mut settings = config::settings(&cli, config, options, daemon)?;
            if !options.foreground {
                if settings.socket.is_relative() {
                    settings.socket = std::env::current_dir()?.join(&settings.socket);
                }
                match background::detach(&settings.socket, if daemon { "daemon" } else { "join" })?
                {
                    background::Fork::Parent => return Ok(0),
                    background::Fork::Child(child) => startup = child,
                }
            }
            Some(settings)
        }
        _ => None,
    };
    let original_flags = [0, 1, 2].map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) });
    let result = (|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()?;
        let result = runtime.block_on(run(cli, settings, socket, &mut startup));
        // Drop runtime first so cancelled session tasks reap/kill their child processes.
        drop(runtime);
        result
    })();
    if let Err(error) = &result {
        startup.failed(error);
    }
    // dup() shares file status flags, and stdin/stdout may share the same terminal.
    // Restore after all cancelled I/O tasks have been dropped.
    for (fd, flags) in original_flags.into_iter().enumerate() {
        if flags >= 0 {
            unsafe {
                libc::fcntl(fd as i32, libc::F_SETFL, flags);
            }
        }
    }
    result
}
async fn run(
    cli: Cli,
    settings: Option<config::Settings>,
    socket: Option<std::path::PathBuf>,
    startup: &mut background::Startup,
) -> Result<i32> {
    if matches!(cli.command, Command::Keygen) {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        println!(
            "{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        return Ok(0);
    }
    match &cli.command {
        Command::Daemon { address, .. } => {
            runtime::daemon(settings.unwrap(), address.clone(), startup).await?
        }
        Command::Join { address, .. } => {
            runtime::join(settings.unwrap(), address.clone(), startup).await?
        }
        Command::List => console::list(socket.as_ref().unwrap()).await?,
        Command::Console { name, id, pty, cmd } => {
            return console::console(
                socket.as_ref().unwrap(),
                name.clone(),
                id.clone(),
                *pty,
                cmd,
            )
            .await;
        }
        Command::Keygen => unreachable!(),
    }
    Ok(0)
}
