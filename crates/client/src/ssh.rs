//! SSH session management built on `russh`.
//!
//! Each session runs as a tokio task: a reader half pumps remote output into a
//! channel for the UI, and the main task drains the input channel and writes
//! keystrokes to the shell. Host keys are verified trust-on-first-use against a
//! local `known_hosts` store (see [`crate::known_hosts`]).

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use protocol::types::{AuthMethod, HostConfig};
use russh::keys::key;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::known_hosts::{KeyCheck, KnownHosts};

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Connecting,
    Connected,
    Error(String),
    Ended,
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: Arc<Mutex<KnownHosts>>,
    reject_reason: Arc<Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint();
        let decision = {
            let store = self.known_hosts.lock().unwrap();
            match store.check(&self.host, self.port, &fp) {
                KeyCheck::Trusted => Decision::Accept,
                KeyCheck::New => Decision::Trust,
                KeyCheck::Mismatch { expected, received } => Decision::Reject(format!(
                    "host key mismatch for {}:{}\n  expected: {}\n  received: {}\n\
                         refusing to connect (delete the known_hosts entry to forget the old key)",
                    self.host, self.port, expected, received
                )),
            }
        };
        match decision {
            Decision::Accept => Ok(true),
            Decision::Trust => {
                {
                    let mut store = self.known_hosts.lock().unwrap();
                    store.add(&self.host, self.port, &fp);
                }
                info!("TOFU: recorded host key for {}:{}", self.host, self.port);
                Ok(true)
            }
            Decision::Reject(reason) => {
                warn!("{reason}");
                *self.reject_reason.lock().unwrap() = Some(reason);
                Ok(false)
            }
        }
    }
}

enum Decision {
    Accept,
    Trust,
    Reject(String),
}

/// Spawn an SSH session. Output bytes flow out via `output_tx`; the UI sends
/// keystrokes via `input_tx`'s sender. Lifecycle events go to `status_tx`.
pub async fn run_session(
    host: HostConfig,
    passphrase: Option<String>,
    cols: u32,
    rows: u32,
    mut input_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    output_tx: mpsc::UnboundedSender<Vec<u8>>,
    status_tx: mpsc::UnboundedSender<SessionEvent>,
) {
    let _ = status_tx.send(SessionEvent::Connecting);
    if let Err(e) = run_inner(
        &host,
        passphrase,
        cols,
        rows,
        &mut input_rx,
        &output_tx,
        &status_tx,
    )
    .await
    {
        let _ = status_tx.send(SessionEvent::Error(e.to_string()));
    }
    let _ = status_tx.send(SessionEvent::Ended);
}

async fn run_inner(
    host: &HostConfig,
    passphrase: Option<String>,
    cols: u32,
    rows: u32,
    input_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    output_tx: &mpsc::UnboundedSender<Vec<u8>>,
    status_tx: &mpsc::UnboundedSender<SessionEvent>,
) -> Result<()> {
    let config = Arc::new(russh::client::Config::default());
    let addr = format!("{}:{}", host.host, host.port);
    info!(
        "connecting to {addr} as {} ({}x{})",
        host.username, cols, rows
    );

    let known_hosts = Arc::new(Mutex::new(KnownHosts::load()));
    let reject_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        host: host.host.clone(),
        port: host.port,
        known_hosts: known_hosts.clone(),
        reject_reason: reject_reason.clone(),
    };

    let mut handle = match russh::client::connect(config, &addr, handler).await {
        Ok(h) => h,
        Err(e) => {
            if let Some(reason) = reject_reason.lock().unwrap().take() {
                return Err(anyhow!(reason));
            }
            return Err(anyhow!("connect to {addr} failed: {e}"));
        }
    };
    // Persist any newly-recorded TOFU entries.
    let _ = known_hosts.lock().unwrap().save();

    let authed = match host.auth_method {
        AuthMethod::Password => {
            let pw = host.password.as_deref().unwrap_or("");
            handle
                .authenticate_password(&host.username, pw)
                .await
                .map_err(|e| anyhow!("password auth failed: {e}"))?
        }
        AuthMethod::Key => {
            let path = host
                .key_path
                .as_ref()
                .ok_or_else(|| anyhow!("key auth selected but no key_path set"))?;
            let kp = russh::keys::load_secret_key(path, passphrase.as_deref())
                .with_context(|| format!("load key {path}"))?;
            handle
                .authenticate_publickey(&host.username, Arc::new(kp))
                .await
                .map_err(|e| anyhow!("publickey auth failed: {e}"))?
        }
    };
    if !authed {
        return Err(anyhow!("authentication rejected by server"));
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| anyhow!("channel_open_session: {e}"))?;
    channel
        .request_pty(false, "xterm", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| anyhow!("request_pty: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| anyhow!("request_shell: {e}"))?;

    let _ = status_tx.send(SessionEvent::Connected);

    // Split the channel into read/write halves so output and input can run
    // concurrently without borrowing the same object.
    let stream = channel.into_stream();
    let (mut reader, mut writer) = tokio::io::split(stream);

    let out = output_tx.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if out.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        match input_rx.recv().await {
            Some(bytes) => {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
            None => break,
        }
    }

    read_task.abort();
    let _ = read_task.await;
    Ok(())
}
