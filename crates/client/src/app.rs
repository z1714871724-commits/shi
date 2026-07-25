//! Glue between the Slint UI, the tokio runtime, the sync client and the SSH
//! session tasks.
//!
//! All UI-facing state lives on the Slint event-loop thread in
//! `Rc<RefCell<UiState>>`. Async work runs on tokio tasks and reports back
//! through an `mpsc` channel of `UiEvent`s; a Slint timer drains that channel
//! (and every session's output) every ~20ms. Multiple SSH sessions can run at
//! once and are surfaced as tabs in the UI; `active` tracks the visible one.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use chrono::Utc;
use protocol::api::AuthResponse;
use protocol::types::{AuthMethod, HostConfig};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel, Weak};
use tokio::sync::mpsc;
use tracing::error;

use crate::i18n;
use crate::ssh::{self, SessionEvent};
use crate::store::{LocalState, LocalVaultEntry};
use crate::sync::{PulledState, SyncClient};
use crate::terminal::TerminalBuffer;
use crate::{HostRow, TabRow};

/// Events delivered from tokio tasks back to the UI thread.
enum UiEvent {
    Login(Result<(SyncClient, AuthResponse), anyhow::Error>),
    Register(Result<(SyncClient, AuthResponse), anyhow::Error>),
    Sync(Result<PulledState, anyhow::Error>),
    Deleted(Result<(), anyhow::Error>),
}

struct ActiveSession {
    id: String,
    label: String,
    buffer: Rc<RefCell<TerminalBuffer>>,
    input_tx: mpsc::UnboundedSender<Vec<u8>>,
    resize_tx: mpsc::UnboundedSender<(u32, u32)>,
    output_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    status_rx: mpsc::UnboundedReceiver<SessionEvent>,
    task: tokio::task::JoinHandle<()>,
    connected: bool,
    ended_msg: Option<String>,
    dirty: bool,
    /// Last PTY size sent to the remote shell, so we only resend on change.
    pty_size: Option<(u32, u32)>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct UiState {
    runtime: tokio::runtime::Runtime,
    local: LocalState,
    sync: Option<SyncClient>,
    sessions: Vec<ActiveSession>,
    active: Option<usize>,
    event_rx: mpsc::UnboundedReceiver<UiEvent>,
    event_tx: mpsc::UnboundedSender<UiEvent>,
    /// Ids of the hosts currently shown in the list, in display order. Kept in
    /// sync with the Slint model so list indices survive search filtering.
    displayed_host_ids: Vec<String>,
    /// Set when the tab bar / active-session chrome needs rebuilding.
    tabs_dirty: bool,
}

pub struct AppController {
    ui: crate::App,
    state: Rc<RefCell<UiState>>,
    _timer: slint::Timer,
}

impl AppController {
    pub fn new(local: LocalState) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (event_tx, event_rx) = mpsc::unbounded_channel::<UiEvent>();

        let ui = crate::App::new()?;

        // Pre-fill the login form from saved state, but keep the Slint-defined
        // defaults (e.g. http://127.0.0.1:8787) when nothing is saved yet.
        if !local.server_url.is_empty() {
            ui.set_server_url(local.server_url.clone().into());
        }
        if !local.username.is_empty() {
            ui.set_username(local.username.clone().into());
        }
        ui.set_terminal_font(local.terminal_font_or_default().into());

        // i18n: load the translation table, register the pure `t` callback and
        // bump `version` so every `AppI18n.tr(...)` binding evaluates.
        let lang = local.lang_or_default();
        let dark = local.theme_or_default() != "light";
        i18n::set_lang(&lang);
        let i18n_global = ui.global::<crate::AppI18n>();
        i18n_global.on_t(|key: SharedString, _args: ModelRc<SharedString>| i18n::t(&key).into());
        i18n_global.set_locale(lang.clone().into());
        i18n_global.set_version(1);

        // theme: apply the saved mode to the Theme global (colours rebind) and
        // keep the std-widgets in sync via Palette.color-scheme.
        ui.global::<crate::Theme>().set_dark_mode(dark);
        // Re-apply Palette.color-scheme now that dark-mode is the saved value:
        // std-widgets (Button/LineEdit/ComboBox) read it, and it can only be
        // set from Slint, so we invoke the public function after seeding state.
        ui.invoke_apply_palette();

        let state = Rc::new(RefCell::new(UiState {
            runtime,
            local,
            sync: None,
            sessions: Vec::new(),
            active: None,
            event_rx,
            event_tx,
            displayed_host_ids: Vec::new(),
            tabs_dirty: true,
        }));

        let controller = Self {
            ui,
            state,
            _timer: slint::Timer::default(),
        };
        controller.refresh_host_list();
        controller.refresh_tabs();
        controller.wire_callbacks();
        controller.start_timer();
        Ok(controller)
    }

    pub fn run(&self) {
        self.ui.run().unwrap();
    }

    fn ui_weak(&self) -> Weak<crate::App> {
        self.ui.as_weak()
    }

    fn wire_callbacks(&self) {
        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_login_clicked(move || {
            handle_auth(&ui, &state, false);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_register_clicked(move || {
            handle_auth(&ui, &state, true);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_logout_clicked(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            {
                let mut st = state.borrow_mut();
                st.sync = None;
                st.sessions.clear();
                st.active = None;
                st.tabs_dirty = true;
                st.local.username.clear();
            }
            ui.set_screen(0);
            ui.set_password(SharedString::default());
            ui.set_status(SharedString::default());
            ui.set_connected(false);
            ui.set_term_host_label("not connected".into());
            set_terminal_text(&ui, SharedString::default());
            refresh_tabs_from(&state.borrow(), &ui);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_add_host_clicked(move || {
            handle_add_host(&ui, &state);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_connect_clicked(move |i: i32| {
            handle_connect(&ui, &state, i as usize);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_edit_host_clicked(move |i: i32| {
            handle_edit(&ui, &state, i as usize);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_delete_host_clicked(move |i: i32| {
            handle_delete(&ui, &state, i as usize);
        });

        let ui = self.ui_weak();
        self.ui.on_new_host_clicked(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            ui.set_editing_id(SharedString::default());
            ui.set_hf_name(SharedString::default());
            ui.set_hf_host(SharedString::default());
            ui.set_hf_port_text("22".into());
            ui.set_hf_user(SharedString::default());
            ui.set_hf_auth("password".into());
            ui.set_hf_password(SharedString::default());
            ui.set_hf_keypath(SharedString::default());
            ui.set_hf_passphrase(SharedString::default());
            ui.set_status(i18n::tr("status.adding-host", &[]).into());
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_select_tab(move |i: i32| {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let mut st = state.borrow_mut();
            let i = i as usize;
            if i >= st.sessions.len() {
                return;
            }
            st.active = Some(i);
            st.tabs_dirty = true;
            drop(st);
            // Reflect the newly active session immediately.
            pump(&ui.as_weak(), &state);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_close_tab(move |i: i32| {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            {
                let mut st = state.borrow_mut();
                let i = i as usize;
                if i >= st.sessions.len() {
                    return;
                }
                st.sessions.remove(i); // Drop aborts the session task
                st.active = match st.active {
                    None => None,
                    Some(a) => {
                        let removed_before = if i < a { 1 } else { 0 };
                        recompute_active(Some(a), removed_before, st.sessions.len())
                    }
                };
                st.tabs_dirty = true;
            }
            pump(&ui.as_weak(), &state);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_sync_clicked(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let mut st = state.borrow_mut();
            spawn_pull(&mut st, &ui);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_search_changed(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let mut st = state.borrow_mut();
            refresh_host_list_from(&mut st, &ui);
        });

        let state = self.state.clone();
        self.ui.on_term_key(
            move |text: SharedString, ctrl: bool, shift: bool, alt: bool| {
                if let Some(bytes) = key_to_bytes(&text, ctrl, shift, alt) {
                    let st = state.borrow();
                    if let Some(i) = st.active {
                        if let Some(s) = st.sessions.get(i) {
                            let _ = s.input_tx.send(bytes);
                        }
                    }
                }
            },
        );

        let state = self.state.clone();
        self.ui.on_send_button(move |name: SharedString| {
            if let Some(bytes) = button_to_bytes(&name) {
                let st = state.borrow();
                if let Some(i) = st.active {
                    if let Some(s) = st.sessions.get(i) {
                        let _ = s.input_tx.send(bytes);
                    }
                }
            }
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_clear_terminal_clicked(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(i) = st.active {
                    if let Some(s) = st.sessions.get_mut(i) {
                        s.buffer.borrow_mut().reset();
                        s.dirty = true;
                    }
                }
            }
            set_terminal_text(&ui, SharedString::default());
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_font_changed(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let font = ui.get_terminal_font().to_string();
            let mut st = state.borrow_mut();
            st.local.terminal_font = font;
            if let Err(e) = st.local.save() {
                ui.set_status(i18n::tr("status.font-saved-error", &[e.to_string()]).into());
            }
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_theme_changed(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let dark = ui.global::<crate::Theme>().get_dark_mode();
            let mut st = state.borrow_mut();
            st.local.theme = if dark {
                "dark".to_string()
            } else {
                "light".to_string()
            };
            let _ = st.local.save();
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_toggle_lang(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let cur = ui.global::<crate::AppI18n>().get_locale().to_string();
            let new_lang = if cur == "zh" { "en" } else { "zh" };
            i18n::set_lang(new_lang);
            let g = ui.global::<crate::AppI18n>();
            g.set_locale(new_lang.into());
            g.set_version(g.get_version() + 1);
            let mut st = state.borrow_mut();
            st.local.lang = new_lang.to_string();
            let _ = st.local.save();
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_term_sel_start(move |col: f32, line: f32| {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let col = col.floor() as i32;
            let line = line.floor() as i32;
            ui.set_sel_start_line(line);
            ui.set_sel_start_col(col);
            ui.set_sel_end_line(line);
            ui.set_sel_end_col(col);
            recompute_selection(&ui, &state);
        });

        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_term_sel_move(move |col: f32, line: f32| {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            if ui.get_sel_start_line() < 0 {
                return;
            }
            ui.set_sel_end_line(line.floor() as i32);
            ui.set_sel_end_col(col.floor() as i32);
            recompute_selection(&ui, &state);
        });

       let ui = self.ui_weak();
       self.ui.on_copy_selection(move || {
           let ui = match ui.upgrade() {
               Some(u) => u,
               None => return,
           };
           handle_copy(&ui);
       });
        let ui = self.ui_weak();
        let state = self.state.clone();
        self.ui.on_select_all_term(move || {
            let ui = match ui.upgrade() {
                Some(u) => u,
                None => return,
            };
            let lines = ui.get_term_line_count().max(1);
            let cols = active_cols(&state);
            ui.set_sel_start_line(0);
            ui.set_sel_start_col(0);
           ui.set_sel_end_line(lines - 1);
           ui.set_sel_end_col(cols);
           recompute_selection(&ui, &state);
       });
        let state = self.state.clone();
        self.ui.on_paste(move || {
            // Read the system clipboard and feed it to the active session's
            // PTY as raw bytes (CR-terminated lines, like a real terminal).
           let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
               Ok(t) => t,
               Err(e) => {
                   tracing::warn!("clipboard read failed: {e}");
                   return;
               }
           };
            if text.is_empty() {
                return;
            }
            // Normalise CRLF/LF to CR (the PTY line ending) before sending.
            let bytes: Vec<u8> = text
                .replace("\r\n", "\n")
                .replace('\r', "\n")
               .replace('\n', "\r")
               .into_bytes();
            let st = state.borrow();
           if let Some(i) = st.active {
               if let Some(s) = st.sessions.get(i) {
                   let _ = s.input_tx.send(bytes);
               }
           }
        });
    }

    fn start_timer(&self) {
        let ui = self.ui_weak();
        let state = self.state.clone();
        self._timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(20),
            move || {
                pump(&ui, &state);
            },
        );
    }

    fn refresh_host_list(&self) {
        let mut st = self.state.borrow_mut();
        refresh_host_list_from(&mut st, &self.ui);
    }

    fn refresh_tabs(&self) {
        let st = self.state.borrow();
        refresh_tabs_from(&st, &self.ui);
    }
}

/// Periodic pump: drain async events, feed every session's output into its
/// terminal buffer, drop ended sessions, and re-render the active one.
fn pump(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let mut st = state.borrow_mut();

    while let Ok(ev) = st.event_rx.try_recv() {
        handle_event(&ui, &mut st, ev);
    }

    // Drain output + status for every session.
    let mut ended_info: Vec<(usize, String, Option<String>)> = Vec::new();
    let mut any_connected = false;
    for (i, s) in st.sessions.iter_mut().enumerate() {
        let mut buf = Vec::new();
        while let Ok(bytes) = s.output_rx.try_recv() {
            buf.extend_from_slice(&bytes);
        }
        if !buf.is_empty() {
            s.buffer.borrow_mut().feed(&buf);
            s.dirty = true;
        }
        while let Ok(ev) = s.status_rx.try_recv() {
            match ev {
                SessionEvent::Connecting => {}
                SessionEvent::Connected => {
                    s.connected = true;
                    any_connected = true;
                }
                SessionEvent::Error(m) => {
                    s.ended_msg = Some(m);
                }
                SessionEvent::Ended => {
                    ended_info.push((i, s.label.clone(), s.ended_msg.clone()));
                }
            }
        }
    }
    if any_connected {
        st.tabs_dirty = true;
    }

    // Remove ended sessions, adjusting the active index.
    if !ended_info.is_empty() {
        let ended_idx: Vec<usize> = ended_info.iter().map(|(i, _, _)| *i).collect();
        let prev_active = st.active;
        let mut new_sessions = Vec::with_capacity(st.sessions.len());
        let mut removed_before_active = 0isize;
        let mut active_msg: Option<String> = None;
        for (i, s) in st.sessions.drain(..).enumerate() {
            if ended_idx.contains(&i) {
                if let Some(a) = prev_active {
                    if i < a {
                        removed_before_active += 1;
                    } else if i == a {
                        active_msg = Some(
                            ended_info
                                .iter()
                                .find(|(ei, _, _)| *ei == i)
                                .and_then(|(_, _, m)| m.clone())
                                .unwrap_or_else(|| i18n::tr("status.session-ended", &[])),
                        );
                    }
                }
            } else {
                new_sessions.push(s);
            }
        }
        st.sessions = new_sessions;
        st.active = recompute_active(prev_active, removed_before_active, st.sessions.len());
        st.tabs_dirty = true;
        if let Some(m) = active_msg {
            ui.set_status(m.into());
        } else if let Some((_, label, _)) = ended_info.first() {
            ui.set_status(i18n::tr("status.session-ended-label", &[label.to_string()]).into());
        }
        if st.sessions.is_empty() {
            set_terminal_text(&ui, SharedString::default());
        }
    }

    // Re-render the active session's buffer when it changed.
    // Keep every connected session's PTY size in sync with the live terminal
    // widget: recompute the desired size from the actual term-rect geometry +
    // measured line height, and when it changes resize the local buffer and
    // notify the remote shell via window-change. This is naturally throttled
    // (a resend only happens when the computed size actually differs).
    let desired = pty_size_from_ui(&ui);
    for s in st.sessions.iter_mut() {
        if s.connected && s.pty_size != Some(desired) {
            s.buffer
                .borrow_mut()
                .resize(desired.0 as usize, desired.1 as usize);
            let _ = s.resize_tx.send(desired);
            s.pty_size = Some(desired);
            s.dirty = true;
        }
    }

    if let Some(i) = st.active {
        if let Some(s) = st.sessions.get_mut(i) {
            if s.dirty {
                s.dirty = false;
                let text = s.buffer.borrow().render();
                set_terminal_text(&ui, text.into());
            }
        }
    }

    // Rebuild the tab bar + active-session chrome when the set/active changed.
    if st.tabs_dirty {
        st.tabs_dirty = false;
        refresh_tabs_from(&st, &ui);
        if let Some(i) = st.active {
            if let Some(s) = st.sessions.get(i) {
                ui.set_connected(s.connected);
                ui.set_term_host_label(s.label.clone().into());
                let text = s.buffer.borrow().render();
                set_terminal_text(&ui, text.into());
            }
        } else {
            ui.set_connected(false);
            ui.set_term_host_label("not connected".into());
            set_terminal_text(&ui, SharedString::default());
        }
    }
}

fn handle_event(ui: &crate::App, st: &mut UiState, ev: UiEvent) {
    match ev {
        UiEvent::Login(Ok((sync, auth))) | UiEvent::Register(Ok((sync, auth))) => {
            st.sync = Some(sync);
            st.local.server_url = ui.get_server_url().to_string();
            st.local.username = auth.username.clone();
            ui.set_username(auth.username.clone().into());
            let _ = st.local.save();
            ui.set_busy(false);
            ui.set_status(i18n::tr("status.signed-in", &[]).into());
            ui.set_screen(1);
            refresh_host_list_from(st, ui);
            // Auto-pull so hosts from other devices appear immediately.
            spawn_pull(st, ui);
        }
        UiEvent::Login(Err(e)) | UiEvent::Register(Err(e)) => {
            ui.set_busy(false);
            ui.set_status(i18n::tr("status.login-failed", &[e.to_string()]).into());
        }
        UiEvent::Sync(Ok(pulled)) => {
            merge_remote(st, pulled);
            let _ = st.local.save();
            ui.set_busy(false);
            refresh_host_list_from(st, ui);
            ui.set_status(i18n::tr("status.sync-complete", &[]).into());
        }
        UiEvent::Sync(Err(e)) => {
            ui.set_busy(false);
            ui.set_status(i18n::tr("status.sync-failed", &[e.to_string()]).into());
        }
        UiEvent::Deleted(Ok(())) => {
            ui.set_busy(false);
            refresh_host_list_from(st, ui);
            ui.set_status(i18n::tr("status.deleted", &[]).into());
        }
        UiEvent::Deleted(Err(e)) => {
            ui.set_busy(false);
            ui.set_status(i18n::tr("status.error", &[format!("delete failed: {e}")]).into());
        }
    }
}

fn refresh_host_list_from(st: &mut UiState, ui: &crate::App) {
    let q = ui.get_search().to_string().to_lowercase();
    let mut ids = Vec::new();
    let rows: Vec<HostRow> = st
        .local
        .hosts
        .iter()
        .filter(|h| {
            if q.is_empty() {
                return true;
            }
            h.name.to_lowercase().contains(&q)
                || h.host.to_lowercase().contains(&q)
                || h.username.to_lowercase().contains(&q)
        })
        .map(|h| {
            ids.push(h.id.clone());
            HostRow {
                id: h.id.clone().into(),
                name: h.name.clone().into(),
                detail: format!("{}@{}:{}", h.username, h.host, h.port).into(),
                auth: match h.auth_method {
                    AuthMethod::Password => "password",
                    AuthMethod::Key => "key",
                }
                .into(),
            }
        })
        .collect();
    st.displayed_host_ids = ids;
    let model = VecModel::from(rows);
    ui.set_host_list(ModelRc::from(Rc::new(model)));
}

fn refresh_tabs_from(st: &UiState, ui: &crate::App) {
    let rows: Vec<TabRow> = st
        .sessions
        .iter()
        .map(|s| TabRow {
            id: s.id.clone().into(),
            label: s.label.clone().into(),
            connected: s.connected,
        })
        .collect();
    let model = VecModel::from(rows);
    ui.set_tabs(ModelRc::from(Rc::new(model)));
    ui.set_active_tab(st.active.map(|i| i as i32).unwrap_or(-1));
}

fn merge_remote(st: &mut UiState, pulled: PulledState) {
    for r in pulled.hosts {
        if let Some(l) = st.local.hosts.iter_mut().find(|h| h.id == r.id) {
            if r.updated_at > l.updated_at {
                *l = r;
            }
        } else {
            st.local.hosts.push(r);
        }
    }
    for v in pulled.vault {
        st.local.upsert_vault(v);
    }
}

fn spawn_pull(st: &mut UiState, ui: &crate::App) {
    let Some(sync) = st.sync.clone() else {
        ui.set_status(i18n::tr("status.not-signed-in", &[]).into());
        return;
    };
    let hosts = st.local.hosts.clone();
    let vault = st.local.vault.clone();
    let event_tx = st.event_tx.clone();
    let runtime = st.runtime.handle().clone();
    ui.set_busy(true);
    ui.set_status(i18n::tr("status.syncing", &[]).into());
    runtime.spawn(async move {
        let res = async {
            sync.push(&hosts, &vault).await?;
            sync.pull().await
        }
        .await;
        let _ = event_tx.send(UiEvent::Sync(res.map_err(Into::into)));
    });
}

fn handle_auth(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>, register: bool) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let server_url = ui.get_server_url().to_string();
    let user = ui.get_username().to_string();
    let pass = ui.get_password().to_string();
    if user.is_empty() || pass.is_empty() {
        ui.set_status(i18n::tr("status.enter-creds", &[]).into());
        return;
    }
    let mut sync = match SyncClient::new(&server_url) {
        Ok(s) => s,
        Err(e) => {
            ui.set_status(i18n::tr("status.invalid-url", &[e.to_string()]).into());
            return;
        }
    };
    ui.set_status(
        i18n::tr(
            if register {
                "status.registering"
            } else {
                "status.signing-in"
            },
            &[],
        )
        .into(),
    );
    ui.set_busy(true);
    let event_tx = state.borrow().event_tx.clone();
    let runtime = state.borrow().runtime.handle().clone();
    runtime.spawn(async move {
        let res = if register {
            sync.register(&user, &pass).await.map(|a| (sync, a))
        } else {
            sync.login(&user, &pass).await.map(|a| (sync, a))
        };
        let event = if register {
            UiEvent::Register(res)
        } else {
            UiEvent::Login(res)
        };
        if event_tx.send(event).is_err() {
            error!("UI event channel closed");
        }
    });
}

fn handle_add_host(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let editing_id = ui.get_editing_id().to_string();
    let name = ui.get_hf_name().to_string();
    let host = ui.get_hf_host().to_string();
    let port: u16 = ui.get_hf_port_text().to_string().parse().unwrap_or(22);
    let username = ui.get_hf_user().to_string();
    let auth_str = ui.get_hf_auth().to_string();
    let password = ui.get_hf_password().to_string();
    let key_path = ui.get_hf_keypath().to_string();
    let passphrase = ui.get_hf_passphrase().to_string();

    if name.is_empty() || host.is_empty() || username.is_empty() {
        ui.set_status(i18n::tr("status.name-required", &[]).into());
        return;
    }
    let auth = if auth_str == "key" {
        AuthMethod::Key
    } else {
        AuthMethod::Password
    };
    let id = if editing_id.is_empty() {
        new_id()
    } else {
        editing_id.clone()
    };
    let now = Utc::now().timestamp();

    // Preserve an existing vault link when editing a key-auth host.
    let existing_vid = if !editing_id.is_empty() {
        state
            .borrow()
            .local
            .hosts
            .iter()
            .find(|h| h.id == editing_id)
            .and_then(|h| h.key_password_id.clone())
    } else {
        None
    };

    let mut host_cfg = HostConfig {
        id: id.clone(),
        name,
        host,
        port,
        username,
        auth_method: auth,
        password: None,
        key_path: None,
        key_password_id: existing_vid.clone(),
        group: String::new(),
        updated_at: now,
    };
    let mut st = state.borrow_mut();
    match auth {
        AuthMethod::Password => {
            if !password.is_empty() {
                host_cfg.password = Some(password);
            }
            host_cfg.key_password_id = None;
        }
        AuthMethod::Key => {
            host_cfg.key_path = Some(key_path);
            if !passphrase.is_empty() {
                let vid = existing_vid.unwrap_or_else(new_id);
                st.local.upsert_vault(LocalVaultEntry {
                    id: vid.clone(),
                    label: host_cfg.name.clone(),
                    passphrase,
                    updated_at: now,
                });
                host_cfg.key_password_id = Some(vid);
            }
        }
    }
    st.local.upsert_host(host_cfg);
    if let Err(e) = st.local.save() {
        ui.set_status(i18n::tr("status.save-failed", &[e.to_string()]).into());
    }
    drop(st);
    ui.set_editing_id(SharedString::default());
    ui.set_hf_name(SharedString::default());
    ui.set_hf_host(SharedString::default());
    ui.set_hf_user(SharedString::default());
    ui.set_hf_password(SharedString::default());
    ui.set_hf_keypath(SharedString::default());
    ui.set_hf_passphrase(SharedString::default());
    refresh_host_list_from(&mut state.borrow_mut(), &ui);
    ui.set_status(
        i18n::tr(
            if editing_id.is_empty() {
                "status.host-saved"
            } else {
                "status.host-updated"
            },
            &[],
        )
        .into(),
    );
}

fn handle_edit(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>, index: usize) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let host = {
        let st = state.borrow();
        let Some(id) = st.displayed_host_ids.get(index).cloned() else {
            return;
        };
        st.local.hosts.iter().find(|h| h.id == id).cloned()
    };
    let Some(h) = host else { return };
    let passphrase = state
        .borrow()
        .local
        .passphrase_for(&h)
        .map(|s| s.to_string())
        .unwrap_or_default();
    ui.set_editing_id(h.id.clone().into());
    ui.set_hf_name(h.name.clone().into());
    ui.set_hf_host(h.host.clone().into());
    ui.set_hf_port_text(h.port.to_string().into());
    ui.set_hf_user(h.username.clone().into());
    ui.set_hf_auth(
        match h.auth_method {
            AuthMethod::Password => "password",
            AuthMethod::Key => "key",
        }
        .into(),
    );
    ui.set_hf_password(h.password.unwrap_or_default().into());
    ui.set_hf_keypath(h.key_path.unwrap_or_default().into());
    ui.set_hf_passphrase(passphrase.into());
    ui.set_status(i18n::tr("status.editing", &[]).into());
}

fn handle_connect(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>, index: usize) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let (host, passphrase, label) = {
        let st = state.borrow();
        let Some(id) = st.displayed_host_ids.get(index).cloned() else {
            ui.set_status(i18n::tr("status.no-host", &[]).into());
            return;
        };
        let Some(host) = st.local.hosts.iter().find(|h| h.id == id).cloned() else {
            ui.set_status(i18n::tr("status.no-host", &[]).into());
            return;
        };
        let passphrase = st.local.passphrase_for(&host).map(|s| s.to_string());
        let label = format!(
            "{} · {}@{}:{}",
            host.name, host.username, host.host, host.port
        );
       (host, passphrase, label)
   };
    let (cols, rows) = pty_size_from_ui(&ui);

    let mut st = state.borrow_mut();
    let buffer = Rc::new(RefCell::new(TerminalBuffer::new(
        cols as usize,
        rows as usize,
    )));
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (resize_tx, resize_rx) = mpsc::unbounded_channel::<(u32, u32)>();
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    let (status_tx, status_rx) = mpsc::unbounded_channel();
    let task = st.runtime.spawn(ssh::run_session(
        host.clone(),
        passphrase,
        cols,
        rows,
        input_rx,
        resize_rx,
        output_tx,
        status_tx,
    ));
    let session = ActiveSession {
        id: new_id(),
        label: label.clone(),
        buffer,
        input_tx,
        resize_tx,
        output_rx,
        status_rx,
        task,
        connected: false,
        ended_msg: None,
        dirty: false,
        pty_size: Some((cols, rows)),
    };
    st.sessions.push(session);
    st.active = Some(st.sessions.len() - 1);
    st.tabs_dirty = true;
    drop(st);

    set_terminal_text(&ui, SharedString::default());
    ui.set_term_host_label(label.into());
    ui.set_connected(false);
    ui.set_status(
        i18n::tr(
            "status.connecting",
            &[host.host.clone(), cols.to_string(), rows.to_string()],
        )
        .into(),
    );
    pump(&ui.as_weak(), state);
}

fn handle_delete(ui: &Weak<crate::App>, state: &Rc<RefCell<UiState>>, index: usize) {
    let ui = match ui.upgrade() {
        Some(u) => u,
        None => return,
    };
    let (id, vault_id) = {
        let st = state.borrow();
        let Some(id) = st.displayed_host_ids.get(index).cloned() else {
            return;
        };
        let vault_id = st
            .local
            .hosts
            .iter()
            .find(|h| h.id == id)
            .and_then(|h| h.key_password_id.clone());
        (id, vault_id)
    };
    let mut st = state.borrow_mut();
    st.local.delete_host(&id);
    let _ = st.local.save();
    let sync = st.sync.clone();
    let event_tx = st.event_tx.clone();
    let runtime = st.runtime.handle().clone();
    drop(st);

    if let Some(sync) = sync {
        ui.set_busy(true);
        runtime.spawn(async move {
            let res = async {
                sync.delete_host(&id).await?;
                if let Some(vid) = vault_id {
                    let _ = sync.delete_vault(&vid).await; // best-effort
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let _ = event_tx.send(UiEvent::Deleted(res.map_err(Into::into)));
        });
    } else {
        refresh_host_list_from(&mut state.borrow_mut(), &ui);
        ui.set_status(i18n::tr("status.deleted-local", &[]).into());
    }
}

/// After removing `removed_before` sessions ahead of it, recompute the active
/// index for a session vector of length `len`. Falls back to the last session.
fn recompute_active(prev: Option<usize>, removed_before: isize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    match prev {
        None => Some(len - 1),
        Some(a) => {
            let new_a = ((a as isize) - removed_before).max(0) as usize;
            if new_a < len {
                Some(new_a)
            } else {
                Some(len - 1)
            }
        }
    }
}

/// Convert the terminal area's pixel size into PTY columns/rows. Falls back to
/// 120x40 before the window has been laid out.
fn compute_pty_size(width_px: f32, height_px: f32) -> (u32, u32) {
    const CHAR_W: f32 = 7.8;
    const LINE_H: f32 = 16.0;
    let cols = if width_px > 1.0 {
        (width_px / CHAR_W) as u32
    } else {
        120
    };
    let rows = if height_px > 1.0 {
        (height_px / LINE_H) as u32
    } else {
        40
    };
    (cols.clamp(20, 400), rows.clamp(8, 120))
}

/// Derive the PTY size from the live window geometry, subtracting the sidebar
/// and the terminal-pane chrome so the remote shell wraps to the visible area.
fn pty_size_from_window(win: &slint::Window) -> (u32, u32) {
    let phys = win.size();
    let scale = win.scale_factor().max(1.0);
    let logical_w = phys.width as f32 / scale;
    let logical_h = phys.height as f32 / scale;
    // sidebar (350) + terminal box horizontal padding (20)
    let term_w = (logical_w - 350.0 - 20.0).max(240.0);
    // top bar (46) + tab bar (36) + toolbar (42) + status bar (22) + padding (20)
    let term_h = (logical_h - 46.0 - 36.0 - 42.0 - 22.0 - 20.0).max(160.0);
    compute_pty_size(term_w, term_h)
}

/// Derive the PTY size from the *actual* terminal widget geometry and the
/// measured per-line height, so the remote shell's screen matches the visible
/// area exactly. Falls back to the window-based estimate before the widget has
/// been laid out (sizes == 0).
fn pty_size_from_ui(ui: &crate::App) -> (u32, u32) {
    const CHAR_W: f32 = 7.8;
    const FALLBACK_LINE_H: f32 = 16.0;
    let area_w = ui.get_term_area_w();
    let area_h = ui.get_term_area_h();
    if area_w < 10.0 || area_h < 10.0 {
        return pty_size_from_window(&ui.window());
    }
    let line_h = {
        let lh = ui.get_term_line_h();
        if lh > 1.0 { lh } else { FALLBACK_LINE_H }
    };
    // 10px inner padding on each side + 1px border
    let usable_w = (area_w - 22.0).max(80.0);
    let usable_h = (area_h - 22.0).max(60.0);
    let cols = ((usable_w / CHAR_W) as u32).clamp(20, 400);
    let rows = ((usable_h / line_h) as u32).clamp(8, 120);
    (cols, rows)
}

/// Set the terminal text and keep the line-count + selection state in sync.
/// New output invalidates any active selection, so it is cleared here.
fn set_terminal_text(ui: &crate::App, text: SharedString) {
    let lines = if text.is_empty() {
        0
    } else {
        text.matches('\n').count() + 1
    };
    ui.set_terminal_text(text);
    ui.set_term_line_count(lines as i32);
    ui.set_sel_start_line(-1);
    ui.set_sel_start_col(-1);
    ui.set_sel_end_line(-1);
    ui.set_sel_end_col(-1);
    ui.set_term_sel_lines(ModelRc::new(VecModel::from(Vec::<crate::SelLine>::new())));
    ui.set_term_sel_text(SharedString::default());
}

/// Grid columns of the active session (used for full-width selection bars).
fn active_cols(state: &Rc<RefCell<UiState>>) -> i32 {
    let st = state.borrow();
    (match st.active {
        Some(i) => st
            .sessions
            .get(i)
            .map(|s| s.buffer.borrow().cols())
            .unwrap_or(80),
        None => 80,
    }) as i32
}

/// Recompute the selection highlight rects and the selected text from the
/// `sel-start-*` / `sel-end-*` properties and the rendered terminal text.
fn recompute_selection(ui: &crate::App, state: &Rc<RefCell<UiState>>) {
    let (sl, sc, el, ec) = (
        ui.get_sel_start_line(),
        ui.get_sel_start_col(),
        ui.get_sel_end_line(),
        ui.get_sel_end_col(),
    );
    if sl < 0 || el < 0 {
        return;
    }
    let text = ui.get_terminal_text().to_string();
    if text.is_empty() {
        return;
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let nlines = lines.len() as i32;
    if nlines == 0 {
        return;
    }
    let cols = active_cols(state);
    let (mut sline, mut scol) = (sl, sc);
    let (mut eline, mut ecol) = (el, ec);
    if (sline, scol) > (eline, ecol) {
        std::mem::swap(&mut sline, &mut eline);
        std::mem::swap(&mut scol, &mut ecol);
    }
    sline = sline.clamp(0, nlines - 1);
    eline = eline.clamp(0, nlines - 1);
    let mut sel_lines = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    for line in sline..=eline {
        let cs = if line == sline { scol } else { 0 };
        let ce = if line == eline { ecol } else { cols };
        sel_lines.push(crate::SelLine {
            line,
            col_start: cs,
            col_end: ce,
        });
        let row: Vec<char> = lines[line as usize].chars().collect();
        let from = (cs as usize).min(row.len());
        let to = (ce as usize).min(row.len()).max(from);
        parts.push(row[from..to].iter().collect());
    }
    ui.set_term_sel_lines(ModelRc::new(VecModel::from(sel_lines)));
    ui.set_term_sel_text(parts.join("\n").into());
}

/// Copy the current selection (or the whole terminal if nothing is selected)
/// to the system clipboard via the cross-platform `arboard` crate.
fn handle_copy(ui: &crate::App) {
    let sel = ui.get_term_sel_text().to_string();
    let text = if sel.is_empty() {
        ui.get_terminal_text().to_string()
    } else {
        sel
    };
    if text.is_empty() {
        return;
    }
    let n = text.chars().count();
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
        Ok(_) => ui.set_status(i18n::tr("status.copied", &[n.to_string()]).into()),
        Err(e) => ui.set_status(i18n::tr("status.error", &[format!("copy failed: {e}")]).into()),
    }
}

/// Translate a Slint key event into the bytes to send to the remote PTY.
///
/// Slint encodes special keys as single Unicode characters in `KeyEvent.text`
/// (see `i-slint-common/key_codes.rs`): control characters for Backspace/Tab/
/// Return/Escape and Private-Use-Area code points (U+F700...) for the arrow,
/// navigation and function keys. We map those to the byte sequences an
/// xterm-style PTY expects. Plain modifier key presses (Shift/Control/Alt/Meta
/// alone, U+0010..=U+0018) are dropped so they never reach the shell.
fn key_to_bytes(text: &str, ctrl: bool, shift: bool, _alt: bool) -> Option<Vec<u8>> {
    let c = text.chars().next()?;
    // Drop bare modifier keys (Shift/Control/Alt/AltGr/CapsLock/...) first, so
    // pressing a modifier alone never sends anything to the shell.
    if ('\u{0010}'..='\u{0018}').contains(&c) {
        return None;
    }
    if ctrl {
        // Single ASCII letter -> control byte (Ctrl+C = 0x03, ...).
        if text.chars().nth(1).is_none() && c.is_ascii_alphabetic() {
            return Some(vec![(c as u8) & 0x1f]);
        }
        // Some platforms deliver the control character directly (e.g. Ctrl+C
        // as U+0003); pass it through unchanged.
        if text.chars().nth(1).is_none() && (c as u32) < 0x20 {
            return Some(vec![c as u8]);
        }
        return None;
    }
    let bytes: Vec<u8> = match c {
        '\u{0008}' => vec![0x7f],                  // Backspace -> DEL
        '\u{0009}' if shift => b"\x1b[Z".to_vec(), // Shift+Tab (back-tab)
        '\u{0009}' => b"\t".to_vec(),              // Tab
        '\u{000a}' => b"\r".to_vec(),              // Return -> CR
        '\u{0019}' => b"\x1b[Z".to_vec(),          // Backtab
        '\u{001b}' => vec![0x1b],                  // Escape
        '\u{007f}' => b"\x1b[3~".to_vec(),         // Delete (forward)
        '\u{F700}' => b"\x1b[A".to_vec(),          // Up
        '\u{F701}' => b"\x1b[B".to_vec(),          // Down
        '\u{F702}' => b"\x1b[D".to_vec(),          // Left
        '\u{F703}' => b"\x1b[C".to_vec(),          // Right
        '\u{F704}' => b"\x1bOP".to_vec(),          // F1
        '\u{F705}' => b"\x1bOQ".to_vec(),          // F2
        '\u{F706}' => b"\x1bOR".to_vec(),          // F3
        '\u{F707}' => b"\x1bOS".to_vec(),          // F4
        '\u{F708}' => b"\x1b[15~".to_vec(),        // F5
        '\u{F709}' => b"\x1b[17~".to_vec(),        // F6
        '\u{F70A}' => b"\x1b[18~".to_vec(),        // F7
        '\u{F70B}' => b"\x1b[19~".to_vec(),        // F8
        '\u{F70C}' => b"\x1b[20~".to_vec(),        // F9
        '\u{F70D}' => b"\x1b[21~".to_vec(),        // F10
        '\u{F70E}' => b"\x1b[23~".to_vec(),        // F11
        '\u{F70F}' => b"\x1b[24~".to_vec(),        // F12
        '\u{F727}' => b"\x1b[2~".to_vec(),         // Insert
        '\u{F729}' => b"\x1b[H".to_vec(),          // Home
        '\u{F72B}' => b"\x1b[F".to_vec(),          // End
        '\u{F72C}' => b"\x1b[5~".to_vec(),         // PageUp
        '\u{F72D}' => b"\x1b[6~".to_vec(),         // PageDown
        _ if ('\u{F700}'..='\u{F7FF}').contains(&c) => return None, // unmapped fn/nav key
        _ => text.as_bytes().to_vec(),
    };
    Some(bytes)
}

fn button_to_bytes(name: &str) -> Option<Vec<u8>> {
    Some(match name {
        "ctrl-c" => vec![0x03],
        "ctrl-d" => vec![0x04],
        "ctrl-z" => vec![0x1a],
        "ctrl-l" => vec![0x0c],
        "tab" => b"\t".to_vec(),
        "esc" => vec![0x1b],
        "enter" => b"\r".to_vec(),
        _ => return None,
    })
}

fn new_id() -> String {
    use rand::Rng;
    let now = Utc::now().timestamp_millis();
    let r: u64 = rand::thread_rng().gen();
    format!("{now:x}-{r:016x}")
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn arrow_keys_emit_ansi_cursor_sequences() {
        assert_eq!(
            key_to_bytes("\u{F700}", false, false, false),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            key_to_bytes("\u{F701}", false, false, false),
            Some(b"\x1b[B".to_vec())
        );
        assert_eq!(
            key_to_bytes("\u{F702}", false, false, false),
            Some(b"\x1b[D".to_vec())
        );
        assert_eq!(
            key_to_bytes("\u{F703}", false, false, false),
            Some(b"\x1b[C".to_vec())
        );
    }

    #[test]
    fn tab_returns_cr_backspace_del() {
        // Tab must reach the shell as a real tab so zsh completion fires.
        assert_eq!(
            key_to_bytes("\u{0009}", false, false, false),
            Some(b"\t".to_vec())
        );
        // Enter is CR on a PTY, not LF.
        assert_eq!(
            key_to_bytes("\u{000a}", false, false, false),
            Some(b"\r".to_vec())
        );
        // Backspace sends DEL (xterm convention).
        assert_eq!(
            key_to_bytes("\u{0008}", false, false, false),
            Some(vec![0x7f])
        );
    }

    #[test]
    fn bare_modifiers_are_dropped() {
        assert_eq!(key_to_bytes("\u{0010}", false, true, false), None); // Shift
        assert_eq!(key_to_bytes("\u{0011}", true, false, false), None); // Control
        assert_eq!(key_to_bytes("\u{0012}", false, false, true), None); // Alt
        assert_eq!(key_to_bytes("\u{0017}", false, false, false), None); // Meta
    }

    #[test]
    fn printable_chars_pass_through() {
        assert_eq!(key_to_bytes("a", false, false, false), Some(b"a".to_vec()));
        assert_eq!(key_to_bytes("A", false, true, false), Some(b"A".to_vec()));
        assert_eq!(key_to_bytes(" ", false, false, false), Some(b" ".to_vec()));
    }

    #[test]
    fn shift_tab_is_backtab() {
        assert_eq!(
            key_to_bytes("\u{0009}", false, true, false),
            Some(b"\x1b[Z".to_vec())
        );
    }

    #[test]
    fn ctrl_letter_is_control_byte() {
        assert_eq!(key_to_bytes("c", true, false, false), Some(vec![0x03]));
        assert_eq!(key_to_bytes("d", true, false, false), Some(vec![0x04]));
    }
}
