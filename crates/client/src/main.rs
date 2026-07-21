//! SSH client binary: load local state and hand off to the UI controller.

// On Windows, release builds use the GUI subsystem so no console window is
// spawned alongside the Slint window. Debug builds keep the console so logs
// (tracing/eprintln) stay visible during development.
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "client=info".into()),
        )
        .init();

    let local = match client::store::LocalState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: failed to load local state: {e}");
            client::store::LocalState::default()
        }
    };

    match client::app::AppController::new(local) {
        Ok(c) => c.run(),
        Err(e) => {
            eprintln!("fatal: failed to start UI: {e}");
            std::process::exit(1);
        }
    }
}
