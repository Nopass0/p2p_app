use std::{fs, path::PathBuf};
use serde::{Deserialize, Serialize};
use wry::{
    application::{
        dpi::LogicalSize,
        event_loop::EventLoopWindowTarget,
        window::WindowBuilder,
    },
    webview::{WebView, WebViewBuilder},
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct TelegramCookieStore {
    pub cookies: Vec<Cookie>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expiration_date: Option<f64>,
    pub host_only: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub secure: Option<bool>,
    pub session: Option<bool>,
    pub store_id: Option<String>,
}

fn save_telegram_cookies(cookies: &TelegramCookieStore) -> std::io::Result<()> {
    let path = PathBuf::from("telegram_cookie.json");
    let json = serde_json::to_string_pretty(cookies)?;
    fs::write(path, json)?;
    Ok(())
}

fn load_telegram_cookies() -> TelegramCookieStore {
    let path = PathBuf::from("telegram_cookie.json");
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cookies) = serde_json::from_str::<TelegramCookieStore>(&content) {
                return cookies;
            }
        }
    }
    TelegramCookieStore::default()
}

/// Создает и отображает окно с веб-версией Telegram, используя переданный target.
/// Возвращает WebView или ошибку.
pub fn show_telegram(
    target: &EventLoopWindowTarget<super::Command>,
) -> wry::Result<WebView> {
    let window = WindowBuilder::new()
        .with_title("Telegram")
        .with_inner_size(LogicalSize::new(1024.0, 768.0))
        .build(target)?;
    let cookies = load_telegram_cookies();
    let cookie_script = cookies
        .cookies
        .iter()
        .map(|c| format!("document.cookie = '{}={}; path={}';", c.name, c.value, c.path))
        .collect::<Vec<_>>()
        .join("\n");

    let telegram_url = "https://web.telegram.org/";
    let webview = WebViewBuilder::new(window)?
        .with_url(telegram_url)?
        .with_initialization_script(&cookie_script)
        .with_initialization_script(
            r#"
            document.addEventListener('contextmenu', event => { event.preventDefault(); });
            "#,
        )
        .build()?;
    webview.evaluate_script(&cookie_script)?;
    Ok(webview)
}
