//! Thin SQLite wrapper. Uses `bundled` rusqlite so no system lib is required.

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use protocol::types::{AuthMethod, HostConfig, VaultEntry};
use rusqlite::{params, Connection};

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                vault_salt    TEXT NOT NULL,
                created_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id              TEXT NOT NULL,
                user_id         INTEGER NOT NULL,
                name            TEXT NOT NULL,
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL,
                username        TEXT NOT NULL,
                auth_method     TEXT NOT NULL,
                password        TEXT,
                key_path        TEXT,
                key_password_id TEXT,
                grp             TEXT NOT NULL DEFAULT '',
                updated_at      INTEGER NOT NULL,
                PRIMARY KEY (user_id, id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vault (
                id         TEXT NOT NULL,
                user_id    INTEGER NOT NULL,
                label      TEXT NOT NULL,
                nonce      TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            "#,
        )?;
        Ok(())
    }

    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        vault_salt: &str,
        now: i64,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, vault_salt, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, vault_salt, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn find_user_by_name(&self, username: &str) -> Result<Option<UserRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, vault_salt FROM users WHERE username = ?1",
        )?;
        let mut rows = stmt.query(params![username])?;
        if let Some(r) = rows.next()? {
            Ok(Some(UserRow {
                id: r.get(0)?,
                username: r.get(1)?,
                password_hash: r.get(2)?,
                vault_salt: r.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn set_vault_salt(&self, user_id: i64, salt: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET vault_salt = ?1 WHERE id = ?2",
            params![salt, user_id],
        )?;
        Ok(())
    }

    pub fn list_hosts(&self, user_id: i64) -> Result<Vec<HostConfig>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, host, port, username, auth_method, password, key_path, key_password_id, grp, updated_at
             FROM hosts WHERE user_id = ?1 ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map(params![user_id], |r| {
            let auth: String = r.get(5)?;
            Ok(HostConfig {
                id: r.get(0)?,
                name: r.get(1)?,
                host: r.get(2)?,
                port: r.get(3)?,
                username: r.get(4)?,
                auth_method: if auth == "key" {
                    AuthMethod::Key
                } else {
                    AuthMethod::Password
                },
                password: r.get(6)?,
                key_path: r.get(7)?,
                key_password_id: r.get(8)?,
                group: r.get(9)?,
                updated_at: r.get(10)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Last-write-wins upsert: only replace the stored row when the incoming
    /// `updated_at` is newer (or equal) than what we have.
    pub fn upsert_host(&self, user_id: i64, host: &HostConfig) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row(
                "SELECT updated_at FROM hosts WHERE user_id = ?1 AND id = ?2",
                params![user_id, host.id],
                |r| r.get(0),
            )
            .ok();
        if let Some(stored) = existing {
            if stored > host.updated_at {
                return Ok(false); // stale
            }
        }
        let auth = match host.auth_method {
            AuthMethod::Password => "password",
            AuthMethod::Key => "key",
        };
        conn.execute(
            "INSERT INTO hosts (id, user_id, name, host, port, username, auth_method, password, key_path, key_password_id, grp, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(user_id, id) DO UPDATE SET
               name=excluded.name, host=excluded.host, port=excluded.port,
               username=excluded.username, auth_method=excluded.auth_method,
               password=excluded.password, key_path=excluded.key_path,
               key_password_id=excluded.key_password_id, grp=excluded.grp,
               updated_at=excluded.updated_at",
            params![
                host.id,
                user_id,
                host.name,
                host.host,
                host.port,
                host.username,
                auth,
                host.password,
                host.key_path,
                host.key_password_id,
                host.group,
                host.updated_at,
            ],
        )?;
        Ok(true)
    }

    pub fn delete_host(&self, user_id: i64, id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "DELETE FROM hosts WHERE user_id = ?1 AND id = ?2",
            params![user_id, id],
        )? > 0)
    }

    pub fn list_vault(&self, user_id: i64) -> Result<Vec<VaultEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, label, nonce, ciphertext, updated_at FROM vault WHERE user_id = ?1 ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map(params![user_id], |r| {
            Ok(VaultEntry {
                id: r.get(0)?,
                label: r.get(1)?,
                nonce: r.get(2)?,
                ciphertext: r.get(3)?,
                updated_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn upsert_vault_entry(&self, user_id: i64, entry: &VaultEntry) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row(
                "SELECT updated_at FROM vault WHERE user_id = ?1 AND id = ?2",
                params![user_id, entry.id],
                |r| r.get(0),
            )
            .ok();
        if let Some(stored) = existing {
            if stored > entry.updated_at {
                return Ok(false);
            }
        }
        conn.execute(
            "INSERT INTO vault (id, user_id, label, nonce, ciphertext, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id, id) DO UPDATE SET
               label=excluded.label, nonce=excluded.nonce,
               ciphertext=excluded.ciphertext, updated_at=excluded.updated_at",
            params![
                entry.id,
                user_id,
                entry.label,
                entry.nonce,
                entry.ciphertext,
                entry.updated_at
            ],
        )?;
        Ok(true)
    }

    pub fn delete_vault_entry(&self, user_id: i64, id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "DELETE FROM vault WHERE user_id = ?1 AND id = ?2",
            params![user_id, id],
        )? > 0)
    }
}

pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub vault_salt: String,
}
