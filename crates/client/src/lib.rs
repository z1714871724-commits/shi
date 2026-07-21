//! SSH client library: Slint UI, sync client, SSH session management and the
//! terminal emulator. The binary entry point lives in `src/main.rs`.

pub mod app;
pub mod i18n;
pub mod known_hosts;
pub mod ssh;
pub mod store;
pub mod sync;
pub mod terminal;

slint::include_modules!();
