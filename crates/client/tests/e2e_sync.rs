//! End-to-end test: start the sync server in-process and verify that a second
//! device, logging in with the same master password, can pull and decrypt both
//! an SSH host password and an SSH key passphrase. The server only ever holds
//! ciphertext.

use std::sync::Arc;

use client::store::LocalVaultEntry;
use client::sync::SyncClient;
use protocol::types::{AuthMethod, HostConfig};
use server::{auth::JwtConfig, build_app, db::Db, AppState};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::TcpListener;

static SEQ: AtomicU64 = AtomicU64::new(0);

async fn spawn_server() -> String {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("ssh-sync-e2e-{}-{}.db", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    let db = Db::open(&path).unwrap();
    db.init_schema().unwrap();
    let jwt = JwtConfig::new("testsecret".into(), 3600);
    let state = AppState {
        db: Arc::new(tokio::sync::Mutex::new(db)),
        jwt,
    };
    let app = build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

#[tokio::test]
async fn register_push_pull_decrypts_on_second_device() {
    let base = spawn_server().await;

    // Device A registers and pushes a host password + a key passphrase.
    let mut a = SyncClient::new(&base).unwrap();
    a.register("alice", "correct horse").await.unwrap();
    let host = HostConfig {
        id: "h1".into(),
        name: "prod".into(),
        host: "prod.example.com".into(),
        port: 22,
        username: "root".into(),
        auth_method: AuthMethod::Password,
        password: Some("s3cret-pw".into()),
        key_path: None,
        key_password_id: Some("v1".into()),
        group: String::new(),
        updated_at: 0,
    };
    let vault = vec![LocalVaultEntry {
        id: "v1".into(),
        label: "prod-key".into(),
        passphrase: "passphrase!".into(),
        updated_at: 0,
    }];
    a.push(&[host], &vault).await.unwrap();

    // Device B logs in with the SAME password, derives the same vault key from
    // the server-stored salt, and pulls + decrypts.
    let mut b = SyncClient::new(&base).unwrap();
    b.login("alice", "correct horse").await.unwrap();
    let pulled = b.pull().await.unwrap();

    assert_eq!(pulled.hosts.len(), 1);
    assert_eq!(pulled.hosts[0].password.as_deref(), Some("s3cret-pw"));
    assert_eq!(pulled.hosts[0].key_password_id.as_deref(), Some("v1"));
    assert_eq!(pulled.vault.len(), 1);
    assert_eq!(pulled.vault[0].id, "v1");
    assert_eq!(pulled.vault[0].passphrase, "passphrase!");

    // A wrong master password cannot even log in, so no vault key is ever
    // derived and no secret can be decrypted.
    let mut c = SyncClient::new(&base).unwrap();
    assert!(c.login("alice", "wrong password").await.is_err());
}

#[tokio::test]
async fn last_write_wins_on_push() {
    let base = spawn_server().await;
    let mut a = SyncClient::new(&base).unwrap();
    a.register("bob", "p@ssword").await.unwrap();

    let mut h = HostConfig {
        id: "h".into(),
        name: "old".into(),
        host: "h.example.com".into(),
        port: 22,
        username: "u".into(),
        auth_method: AuthMethod::Password,
        password: Some("old-pw".into()),
        key_path: None,
        key_password_id: None,
        group: String::new(),
        updated_at: 100,
    };
    a.push(std::slice::from_ref(&h), &[]).await.unwrap();

    // Newer version supersedes the older one.
    h.name = "new".into();
    h.password = Some("new-pw".into());
    h.updated_at = 200;
    a.push(std::slice::from_ref(&h), &[]).await.unwrap();

    let pulled = a.pull().await.unwrap();
    assert_eq!(pulled.hosts.len(), 1);
    assert_eq!(pulled.hosts[0].name, "new");
    assert_eq!(pulled.hosts[0].password.as_deref(), Some("new-pw"));

    // An older update must NOT overwrite a newer stored row.
    h.updated_at = 150;
    h.name = "stale".into();
    a.push(std::slice::from_ref(&h), &[]).await.unwrap();
    let pulled2 = a.pull().await.unwrap();
    assert_eq!(pulled2.hosts[0].name, "new");
}
