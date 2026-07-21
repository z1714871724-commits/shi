//! Shared protocol between the sync server and the Slint SSH client.
//!
//! Contains API DTOs, host-config types, and the end-to-end crypto helpers
//! used to keep SSH key passwords encrypted at rest on the server.

pub mod api;
pub mod crypto;
pub mod types;

pub use api::*;
pub use crypto::*;
pub use types::*;
