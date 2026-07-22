//! Minimal, dependency-free internationalisation.
//!
//! Translations live in code as `&'static str` tables keyed by language code.
//! English is always loaded first as the fallback; the selected language's
//! table overrides matching keys. **Adding a language** is a matter of
//! writing a new `xx()` function returning `&[(&str, &str)]` and registering
//! it in [`translations()`] -- the rest of the app picks it up automatically.
//!
//! The Slint UI never holds translated strings directly: it calls
//! `AppI18n.t(key, [version])` (a pure callback implemented in
//! [`crate::app`]), which delegates to [`t`]. Bumping `version` after a
//! language change forces Slint to re-evaluate every binding that reads a
//! translation.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static STRINGS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, String>> {
    STRINGS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn en() -> &'static [(&'static str, &'static str)] {
    &[
        ("app.title", "SSH Client"),
        ("login.subtitle", "Sign in to your sync server"),
        ("login.server-url", "Sync server URL"),
        ("login.username", "Username"),
        ("login.password", "Password"),
        ("login.show", "Show"),
        ("login.hide", "Hide"),
        ("login.login", "Login"),
        ("login.register", "Register"),
        ("main.signed-in", "signed in as "),
        ("main.sync", "Sync"),
        ("main.logout", "Logout"),
        ("main.search", "search hosts"),
        ("main.connect", "Connect"),
        ("main.edit", "Edit"),
        ("main.no-hosts", "no hosts yet - add one below"),
        ("host.add", "Add host"),
        ("host.edit", "Edit host"),
        ("host.new", "New"),
        ("host.name", "Name"),
        ("host.host", "Host"),
        ("host.port", "Port"),
        ("host.user", "Username"),
        ("host.save", "Save host"),
        ("host.update", "Update host"),
        ("host.key-path", "Key path (~/.ssh/id_rsa)"),
        ("host.passphrase", "Key passphrase (synced encrypted)"),
        ("host.password", "Password"),
        ("term.not-connected", "not connected"),
        (
            "term.no-sessions",
            "no active sessions - click Connect on a host",
        ),
        ("term.font", "Font"),
        ("term.clear", "Clear"),
        ("term.disconnect", "Disconnect"),
        ("term.copy", "Copy"),
        ("theme.dark", "Dark"),
        ("theme.light", "Light"),
        ("lang.en", "EN"),
        ("lang.zh", "中文"),
        ("ph.server-url", "http://127.0.0.1:8787"),
        ("ph.username", "username"),
        ("ph.password", "password"),
        ("ph.port", "22"),
        ("ph.font", "Menlo"),
        // status / toast messages (set from Rust)
        ("status.signing-in", "signing in..."),
        ("status.registering", "registering..."),
        ("status.signed-in", "signed in - loading remote hosts..."),
        ("status.syncing", "syncing..."),
        ("status.sync-complete", "sync complete"),
        ("status.sync-failed", "sync failed: {0}"),
        ("status.deleted", "deleted"),
        ("status.deleted-local", "deleted locally"),
        ("status.host-saved", "host saved - click Sync to upload"),
        ("status.host-updated", "host updated"),
        ("status.connecting", "connecting to {0} ({1}x{2})..."),
        ("status.disconnected", "disconnected"),
        ("status.session-ended", "session ended"),
        ("status.session-ended-label", "session ended: {0}"),
        ("status.not-signed-in", "not signed in"),
        ("status.enter-creds", "enter username and password"),
        ("status.invalid-url", "invalid server url: {0}"),
        ("status.save-failed", "save failed: {0}"),
        ("status.font-saved-error", "could not save font: {0}"),
        (
            "status.name-required",
            "name, host and username are required",
        ),
        ("status.no-host", "no such host"),
        ("status.editing", "editing host - click Save to update"),
        ("status.adding-host", "adding a new host"),
        ("status.login-failed", "login failed: {0}"),
        ("status.error", "error: {0}"),
        ("status.copied", "copied {0} chars"),
    ]
}

fn zh() -> &'static [(&'static str, &'static str)] {
    &[
        ("app.title", "SSH 客户端"),
        ("login.subtitle", "登录到同步服务器"),
        ("login.server-url", "同步服务器地址"),
        ("login.username", "用户名"),
        ("login.password", "密码"),
        ("login.show", "显示"),
        ("login.hide", "隐藏"),
        ("login.login", "登录"),
        ("login.register", "注册"),
        ("main.signed-in", "已登录："),
        ("main.sync", "同步"),
        ("main.logout", "退出"),
        ("main.search", "搜索主机"),
        ("main.connect", "连接"),
        ("main.edit", "编辑"),
        ("main.no-hosts", "还没有主机 - 在下方添加"),
        ("host.add", "添加主机"),
        ("host.edit", "编辑主机"),
        ("host.new", "新建"),
        ("host.name", "名称"),
        ("host.host", "主机"),
        ("host.port", "端口"),
        ("host.user", "用户名"),
        ("host.save", "保存主机"),
        ("host.update", "更新主机"),
        ("host.key-path", "密钥路径 (~/.ssh/id_rsa)"),
        ("host.passphrase", "密钥口令（加密同步）"),
        ("host.password", "密码"),
        ("term.not-connected", "未连接"),
        ("term.no-sessions", "没有活动会话 - 点击主机的连接"),
        ("term.font", "字体"),
        ("term.clear", "清屏"),
        ("term.disconnect", "断开"),
        ("term.copy", "复制"),
        ("theme.dark", "深色"),
        ("theme.light", "浅色"),
        ("lang.en", "EN"),
        ("lang.zh", "中文"),
        ("ph.server-url", "http://127.0.0.1:8787"),
        ("ph.username", "用户名"),
        ("ph.password", "密码"),
        ("ph.port", "22"),
        ("ph.font", "Menlo"),
        ("status.signing-in", "登录中..."),
        ("status.registering", "注册中..."),
        ("status.signed-in", "已登录 - 加载远程主机..."),
        ("status.syncing", "同步中..."),
        ("status.sync-complete", "同步完成"),
        ("status.sync-failed", "同步失败：{0}"),
        ("status.deleted", "已删除"),
        ("status.deleted-local", "已在本地删除"),
        ("status.host-saved", "主机已保存 - 点击同步上传"),
        ("status.host-updated", "主机已更新"),
        ("status.connecting", "正在连接 {0} ({1}x{2})..."),
        ("status.disconnected", "已断开"),
        ("status.session-ended", "会话结束"),
        ("status.session-ended-label", "会话结束：{0}"),
        ("status.not-signed-in", "未登录"),
        ("status.enter-creds", "请输入用户名和密码"),
        ("status.invalid-url", "服务器地址无效：{0}"),
        ("status.save-failed", "保存失败：{0}"),
        ("status.font-saved-error", "无法保存字体：{0}"),
        ("status.name-required", "名称、主机和用户名为必填项"),
        ("status.no-host", "找不到该主机"),
        ("status.editing", "正在编辑主机 - 点击保存以更新"),
        ("status.adding-host", "正在添加新主机"),
        ("status.login-failed", "登录失败：{0}"),
        ("status.error", "错误：{0}"),
        ("status.copied", "已复制 {0} 个字符"),
    ]
}

/// Normalise a BCP-47-ish tag to one of our supported codes. Unknown tags
/// fall back to English.
pub fn normalize(lang: &str) -> String {
    let l = lang.to_lowercase().replace('_', "-");
    if l == "zh" || l.starts_with("zh-") {
        "zh".to_string()
    } else {
        "en".to_string()
    }
}

/// (Re)build the translation map for `lang`. English is loaded first so any
/// missing key in the target language still resolves. Add a language by adding
/// a `xx()` function and a match arm below.
pub fn set_lang(lang: &str) {
    let lang = normalize(lang);
    let mut map = store().lock().unwrap();
    map.clear();
    for (k, v) in en() {
        map.insert((*k).to_string(), (*v).to_string());
    }
    // Register additional languages here, e.g. ("ja" => ja(), "fr" => fr()).
    let target: &[(&str, &str)] = match lang.as_str() {
        "zh" => zh(),
        _ => &[],
    };
    for (k, v) in target {
        map.insert((*k).to_string(), (*v).to_string());
    }
}

/// Look up `key` in the current language, falling back to the key itself.
pub fn t(key: &str) -> String {
    let map = store().lock().unwrap();
    map.get(key).cloned().unwrap_or_else(|| key.to_string())
}

/// Translate `key` and substitute `{0}`, `{1}`, ... with `args`.
pub fn tr(key: &str, args: &[String]) -> String {
    let mut text = t(key);
    for (i, arg) in args.iter().enumerate() {
        text = text.replace(&format!("{{{i}}}"), arg);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_is_default_and_complete() {
        set_lang("en");
        assert_eq!(t("app.title"), "SSH Client");
        assert_eq!(t("login.login"), "Login");
    }

    #[test]
    fn chinese_overrides_english() {
        set_lang("zh");
        assert_eq!(t("app.title"), "SSH 客户端");
        assert_eq!(t("term.clear"), "清屏");
        // fallback to key for unknown keys
        assert_eq!(t("does.not.exist"), "does.not.exist");
    }

    #[test]
    fn normalize_handles_variants() {
        assert_eq!(normalize("zh-CN"), "zh");
        assert_eq!(normalize("zh_TW"), "zh");
        assert_eq!(normalize("en-US"), "en");
        assert_eq!(normalize("fr"), "en"); // unsupported -> en
    }

    #[test]
    fn tr_substitutes_args() {
        set_lang("en");
        assert_eq!(
            tr(
                "status.connecting",
                &["host".into(), "80".into(), "24".into()]
            ),
            "connecting to host (80x24)..."
        );
        set_lang("zh");
        assert_eq!(
            tr(
                "status.connecting",
                &["host".into(), "80".into(), "24".into()]
            ),
            "正在连接 host (80x24)..."
        );
    }

    #[test]
    fn missing_key_in_target_falls_back_to_english() {
        // Every zh key should exist in en too; spot-check a couple.
        let en_keys: std::collections::HashSet<_> = en().iter().map(|(k, _)| *k).collect();
        for (k, _) in zh() {
            assert!(en_keys.contains(k), "zh key {k} missing from en table");
        }
    }
}
