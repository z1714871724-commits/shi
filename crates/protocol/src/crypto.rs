//! End-to-end encryption primitives.
//!
//! The server never sees a plaintext SSH key password. The client derives a
//! 256-bit vault key from the user's master password and a per-user salt using
//! Argon2id, then encrypts each secret with AES-256-GCM. Only the salt, nonce
//! and ciphertext are ever uploaded.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("argon2 derivation failed: {0}")]
    Argon2(String),
    #[error("aes-gcm encryption failed: {0}")]
    Encrypt(String),
    #[error("aes-gcm decryption failed: {0}")]
    Decrypt(String),
    #[error("invalid hex/base64 payload: {0}")]
    Encoding(String),
}

/// Output size of the derived vault key in bytes (AES-256).
pub const KEY_LEN: usize = 32;
/// Argon2 salt length in bytes.
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Parameters tuned for interactive logins on a laptop. Memory-hard, 3 lanes.
fn argon2_params() -> Params {
    Params::new(64 * 1024, 3, 4, Some(KEY_LEN)).expect("valid argon2 params")
}

/// Derive a 32-byte vault key from the master password and salt.
/// The salt is stored on the server (it is not secret); the password never
/// leaves the client device.
pub fn derive_vault_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = argon2_params();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(out)
}

/// Generate a fresh random salt for a new user vault.
pub fn new_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a fresh random AES-GCM nonce.
pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt a plaintext string with the vault key. Returns `(nonce_b64, ct_b64)`.
/// `aad` (e.g. the entry label) is authenticated but not encrypted, binding a
/// ciphertext to its label so entries cannot be swapped on the server.
pub fn encrypt_secret(
    key: &[u8; KEY_LEN],
    plaintext: &str,
    aad: &[u8],
) -> Result<(String, String), CryptoError> {
    let nonce = new_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    Ok((B64.encode(nonce), B64.encode(ct)))
}

/// Decrypt a secret previously produced by [`encrypt_secret`].
pub fn decrypt_secret(
    key: &[u8; KEY_LEN],
    nonce_b64: &str,
    ct_b64: &str,
    aad: &[u8],
) -> Result<String, CryptoError> {
    let nonce = B64
        .decode(nonce_b64)
        .map_err(|e| CryptoError::Encoding(e.to_string()))?;
    let ct = B64
        .decode(ct_b64)
        .map_err(|e| CryptoError::Encoding(e.to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Encoding("bad nonce length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(&nonce);
    let pt = cipher
        .decrypt(nonce_obj, aes_gcm::aead::Payload { msg: &ct, aad })
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    String::from_utf8(pt).map_err(|e| CryptoError::Encoding(e.to_string()))
}

/// Hash a login password for server-side storage (separate from the vault key:
/// the server uses this only to verify the user, never to decrypt secrets).
pub fn hash_login_password(password: &str) -> Result<String, CryptoError> {
    let salt = new_salt();
    let params = argon2_params();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    // Store as salt$hash in hex; both halves are needed to verify.
    Ok(format!("{}${}", hex::encode(salt), hex::encode(out)))
}

/// Verify a login password against a `salt$hash` string produced by
/// [`hash_login_password`].
pub fn verify_login_password(password: &str, stored: &str) -> Result<bool, CryptoError> {
    let mut parts = stored.split('$');
    let salt_hex = parts
        .next()
        .ok_or_else(|| CryptoError::Encoding("missing salt".into()))?;
    let hash_hex = parts
        .next()
        .ok_or_else(|| CryptoError::Encoding("missing hash".into()))?;
    let salt = hex::decode(salt_hex).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    let expected = hex::decode(hash_hex).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    let params = argon2_params();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; expected.len()];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(out == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_secret() {
        let key = derive_vault_key("correct horse battery staple", &new_salt()).unwrap();
        let (nonce, ct) = encrypt_secret(&key, "hunter2", b"label-a").unwrap();
        let pt = decrypt_secret(&key, &nonce, &ct, b"label-a").unwrap();
        assert_eq!(pt, "hunter2");
        // AAD tampering must fail.
        assert!(decrypt_secret(&key, &nonce, &ct, b"label-b").is_err());
    }

    #[test]
    fn login_password_roundtrip() {
        let stored = hash_login_password("p@ss").unwrap();
        assert!(verify_login_password("p@ss", &stored).unwrap());
        assert!(!verify_login_password("wrong", &stored).unwrap());
    }
}
