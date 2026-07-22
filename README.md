# SSH Client + Sync Server (Rust + Slint)

A Slint-based SSH client and a companion sync server. The server synchronises
per-user SSH host configurations and **end-to-end encrypted** SSH key
passphrases (and host passwords) across devices. The server never sees any
plaintext secret.

```
┌────────────┐   register/login (Argon2id)   ┌────────────────┐
│  client    │ ────────────────────────────▶ │  sync server   │
│  (Slint)   │   push/pull ciphertext        │  (axum+sqlite)  │
│            │ ◀──────────────────────────── │                 │
│  russh SSH │                               │  stores: users, │
│  terminal  │                               │  host configs,  │
└────────────┘                               │  ciphertext     │
                                             └────────────────┘
   vault key = Argon2id(master_password, vault_salt)
   - derived on the client, never transmitted
   - AES-256-GCM encrypts host passwords + key passphrases
```

## Workspace layout

```
crates/
  protocol/   shared API DTOs, HostConfig/VaultEntry types, E2E crypto
  server/     axum + rusqlite sync server (lib + `ssh-sync-server` bin)
  client/     Slint UI + russh SSH + sync client (`ssh-client` bin)
              ui/main.slint   the Slint design
              src/terminal.rs compact VT100/VT220 terminal buffer
              src/sync.rs     HTTP client + E2E encryption
              src/ssh.rs      russh session (password & key auth, PTY)
              src/app.rs      Slint ↔ tokio ↔ SSH glue
```

## Security model

- **Login password** is hashed with Argon2id on the client (`hash_login_password`)
  and only the hash is stored on the server. The plaintext password never leaves
  the device.
- **Vault key** is derived locally with `Argon2id(master_password, vault_salt)`.
  The `vault_salt` is generated at registration and stored on the server so other
  devices can re-derive the same key after login. The vault key itself never
  leaves the device.
- **SSH host passwords** (for `auth_method = password`) are encrypted with
  AES-256-GCM using the vault key, AAD-bound to the host id, before upload.
- **SSH key passphrases** are stored as vault entries, encrypted with the vault
  key, AAD-bound to the entry label.
- The server therefore only ever persists ciphertext; a wrong master password
  fails at login (before any decryption is attempted), so it cannot decrypt
  secrets. See `crates/client/tests/e2e_sync.rs` for a cross-device round-trip
  test.
- **Last-write-wins** conflict resolution by `updated_at` (set at edit time on
  the client).

## Build

Requires Rust 1.88+ (tested with 1.90) and, on macOS, the Xcode command-line
tools (Slint links the system UI backend). The workspace uses only crates that
compile from source; `rusqlite` is bundled so no system SQLite is needed.

```sh
cargo build --workspace        # debug build
cargo test  --workspace        # unit + end-to-end tests
```

## Run the sync server

```sh
cargo run -p server -- --addr 127.0.0.1:8787 --db sync.db
# optional: --secret <jwt-secret>  (random per start if omitted)
# optional: --token-ttl <seconds>  (default 7 days)
```

API (all under `/api/v1`):

| Method | Path            | Auth | Purpose                              |
|--------|-----------------|------|--------------------------------------|
| GET    | `/health`       | -    | liveness                             |
| POST   | `/register`     | -    | create user, upload vault salt       |
| POST   | `/login`        | -    | returns JWT + vault salt             |
| GET    | `/vault/salt`   | JWT  | read vault salt                      |
| POST   | `/vault/salt`   | JWT  | replace vault salt                   |
| GET    | `/hosts`        | JWT  | list host configs (ciphertext pw)    |
| PUT    | `/hosts`        | JWT  | upsert a host config (LWW)           |
| DELETE | `/hosts/:id`    | JWT  | delete a host config                 |
| GET    | `/vault`        | JWT  | list encrypted vault entries         |
| PUT    | `/vault`        | JWT  | upsert a vault entry (LWW)           |
| DELETE | `/vault/:id`    | JWT  | delete a vault entry                 |

## Run the client

```sh
cargo run -p client
```

1. On the login screen enter the sync server URL, username and password, then
   **Login** (or **Register** for a new account). Use **Show** to reveal the
   password. After sign-in the client auto-pulls your remote hosts.
2. Add hosts with the form on the left: name, host, port, username, auth method
   (`password` or `key`). For key auth, give the private-key path and an optional
   passphrase (the passphrase is stored in the encrypted vault and synced).
   Click **Edit** on a host to load it back into the form; **New** clears the
   form to add another.
3. Use the **search** box to filter hosts by name, host or username.
4. Click **Sync** to push local hosts to the server and pull remote hosts (merged
   by `updated_at`). Host passwords and key passphrases are encrypted before they
   leave the machine.
5. Click **Connect** on a host to open an SSH session in the terminal pane. The
   PTY is sized to the visible terminal area. Click the terminal area to focus
   it, then type. Use the **Ctrl-C / Ctrl-D / Ctrl-Z / Tab / Esc** buttons for
   control keys that GUI key events cannot deliver.
6. On first connect to a host its key fingerprint is recorded (trust on first
   use). A later mismatch is refused with a clear error; delete the
   `known_hosts` entry to forget a changed key.

Local client state (working copy, with plaintext secrets) is persisted to
`~/Library/Application Support/ssh-client/state.json` (macOS) or the equivalent
config dir on other platforms; trusted host keys live in `known_hosts` next to
it. Synced state on the server is always ciphertext.

## Theming & internationalisation

- **Dark / light theme** is driven by a single `Theme` global in
  `crates/client/ui/main.slint`: every colour (panels, cards, terminal
  background/foreground, borders, accents) is a ternary on `Theme.dark-mode`, so
  one toggle re-skins the whole app. The std-widgets (`Button` / `LineEdit` /
  `ComboBox`) follow via `Palette.color-scheme`, re-applied through the public
  `apply-palette` Slint function - called by the theme toggle and by Rust right
  after loading the saved theme on startup. The choice is persisted in local
  state (`theme` field) and restored on launch.
- **Terminal colours** are theme-aware too: `Theme.term-bg` / `term-fg` /
  `term-border` flip between a dark terminal (dark theme) and a white background
  with dark text (light theme).
- **i18n** is dependency-free (`crates/client/src/i18n.rs`): the UI never holds
  translated strings directly - it calls `AppI18n.tr("key")`, a pure callback
  implemented in Rust. English is always loaded first as the fallback; the
  selected language's table overrides matching keys. Bumping `AppI18n.version`
  after a language change forces every binding to re-evaluate, and status
  messages set from Rust use `i18n::tr(...)`. English and Chinese (`zh`) ship
  today; **adding a language** is a new `xx()` table plus a match arm in
  `set_lang` - nothing else needs to change. The choice is saved to local state
  (`lang` field).

## Limitations / TODO

- **Host-key verification** is trust-on-first-use against a local `known_hosts`
  file. A fingerprint mismatch is refused; there is no interactive "accept new
  key?" prompt yet (delete the entry to forget a legitimately-changed key).
- **Terminal emulation** is a compact VT100/VT220 subset (cursor movement, line
  and screen erase, SGR colour stripping, OSC, insert/delete) backed by a
  character grid, so multibyte glyphs (Nerd Font icons, CJK) keep one column.
  It is not a full xterm; some advanced applications may render imperfectly.
- **Text selection & copy**: drag the mouse over the terminal to select (the
  highlight tracks the rendered glyphs), then click **Copy** to copy the
  selection to the system clipboard (or all visible text if nothing is
  selected). Selecting is cleared automatically when new output arrives.
- **Terminal font** is configurable from the terminal toolbar (e.g. set it to a
  Nerd Font like `JetBrainsMono Nerd Font` to see prompt icons). The choice is
  saved to local state and persists across launches.
- **Multiple sessions** run as tabs: click a host's Connect button to open a new
  tab, switch tabs by clicking them, and close one with the `x` on the tab or the
  Disconnect button. The terminal auto-scrolls to keep new output in view.
- **Keyboard input**: Slint encodes special keys as single Unicode code points
  (arrows = U+F700…, Tab/Return/Backspace = control chars), which are mapped to
  xterm PTY sequences - so arrows, Tab completion, Enter, Backspace, Delete, Home/
  End, PageUp/Down and F1-F12 all work. Ctrl-key combos arrive with empty text in
  Slint, so Ctrl-C / Ctrl-D / Ctrl-Z are exposed as toolbar buttons.
- **PTY size** is computed from the window geometry at connect time; live
  window-resize to `window-change` is not wired (reconnect to resize).
- **TLS** is not enabled on the sync server; run it behind a reverse proxy
  (e.g. `caddy` / `nginx`) for production, or add `axum-server` with rustls.
- Sync deletes are best-effort: deleting a host locally also deletes the linked
  vault entry on the server when signed in.
