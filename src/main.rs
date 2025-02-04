use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use tokio::time;
use hyper::{
    header::{HeaderValue, SET_COOKIE},
    Body, Request, Response, Server, StatusCode,
};
use hyper::service::{make_service_fn, service_fn};
use reqwest::header::HeaderMap;
use wry::{
    application::{
        dpi::LogicalSize,
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    },
    webview::WebView,
    webview::WebViewBuilder,
};

mod idex;
use idex::run_idex;

// Подключаем модуль telegram.rs
mod telegram;
use telegram::show_telegram;

// Работа с куками для прокси
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct CookieStore {
    cookies: Vec<Cookie>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expiration_date: Option<f64>,
    host_only: Option<bool>,
    http_only: Option<bool>,
    same_site: Option<String>,
    secure: Option<bool>,
    session: Option<bool>,
    store_id: Option<String>,
}

fn save_cookies(cookies: &CookieStore) -> std::io::Result<()> {
    let path = PathBuf::from("cookies.json");
    let json = serde_json::to_string_pretty(cookies)?;
    fs::write(path, json)?;
    Ok(())
}

fn load_cookies() -> std::io::Result<CookieStore> {
    let path = PathBuf::from("cookies.json");
    if path.exists() {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(CookieStore::default())
    }
}

/// Прокси-состояние
#[derive(Clone)]
pub struct ProxyState {
    pub cookies: Arc<Mutex<CookieStore>>,
    pub base_url: String,
}

impl ProxyState {
    pub fn new(base_url: String) -> Self {
        let store = load_cookies().unwrap_or_default();
        Self {
            cookies: Arc::new(Mutex::new(store)),
            base_url,
        }
    }

    pub fn update_from_headers(&self, headers: &HeaderMap<HeaderValue>, domain: &str) {
        let new_cookies: Vec<Cookie> = headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(|cookie_str| {
                let mut parts = cookie_str.split(';');
                let kv = parts.next().unwrap_or("");
                let mut iter = kv.splitn(2, '=');
                let name = iter.next().unwrap_or("").trim().to_string();
                let value = iter.next().unwrap_or("").trim().to_string();
                Cookie {
                    name,
                    value,
                    domain: domain.to_string(),
                    path: "/".to_string(),
                    expiration_date: None,
                    host_only: None,
                    http_only: Some(cookie_str.to_lowercase().contains("httponly")),
                    same_site: None,
                    secure: Some(cookie_str.to_lowercase().contains("secure")),
                    session: None,
                    store_id: None,
                }
            })
            .collect();

        let mut store = self.cookies.lock().unwrap();
        if !new_cookies.is_empty() {
            for nc in new_cookies {
                if let Some(pos) = store.cookies.iter().position(|c| c.name == nc.name) {
                    store.cookies[pos] = nc;
                } else {
                    store.cookies.push(nc);
                }
            }
            if let Err(e) = save_cookies(&store) {
                eprintln!("Failed to save cookies: {}", e);
            } else {
                println!("Cookies saved successfully: {:#?}", store.cookies);
            }
        } else {
            println!("No new cookies found, keeping existing ones.");
        }
    }
}

/// Прокси-обработчик: ретранслирует HTTP-запросы.
async fn proxy_handler(
    req: Request<Body>,
    state: ProxyState,
) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    let req_headers = req.headers().clone();
    let req_path = req.uri().path().trim_start_matches('/');

    let target_url = if req_path.contains("://") {
        match url::Url::parse(req_path) {
            Ok(url) => url,
            Err(e) => {
                return Ok(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(format!("Invalid URL: {}", e)))
                        .unwrap(),
                );
            }
        }
    } else {
        let base = url::Url::parse(&state.base_url).expect("Invalid base URL");
        match base.join(req.uri().path()) {
            Ok(url) => url,
            Err(e) => {
                return Ok(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(format!("URL join error: {}", e)))
                        .unwrap(),
                );
            }
        }
    };

    println!("Proxying request to: {}", target_url);

    let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
    let client = reqwest::Client::new();
    let mut request_builder = client.request(method.clone(), target_url.clone());
    for (key, value) in req_headers.iter() {
        if key == hyper::header::HOST {
            request_builder = request_builder.header(key, "panel.gate.cx");
        } else if let Ok(val_str) = value.to_str() {
            request_builder = request_builder.header(key, val_str);
        }
    }
    if target_url.domain() == Some("panel.gate.cx") {
        let store = state.cookies.lock().unwrap();
        let cookie_str = store
            .cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie_str.is_empty() {
            request_builder = request_builder.header("Cookie", cookie_str);
        }
    }
    if !whole_body.is_empty() {
        request_builder = request_builder.body(whole_body);
    }
    let response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Ok(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("Request error: {}", err)))
                    .unwrap(),
            );
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(err) => {
            return Ok(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("Body error: {}", err)))
                    .unwrap(),
            );
        }
    };

    state.update_from_headers(&headers, target_url.domain().unwrap_or(""));

    let mut builder = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if key != hyper::header::TRANSFER_ENCODING {
            builder = builder.header(key, value);
        }
    }
    let resp = builder.body(Body::from(body_bytes)).unwrap();
    Ok(resp)
}

async fn run_proxy(state: ProxyState, addr: SocketAddr) {
    let make_service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy_handler(req, state.clone())
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_service);
    println!("Proxy server listening on http://{}", addr);
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}

/// Команды для event loop.
#[derive(Debug)]
enum Command {
    ShowIdex,
    ShowTelegram,
    Exit,
}

/// Общая структура для хранения глобального состояния окон
struct AppState {
    idex_webview: Option<WebView>,
    telegram_webview: Option<WebView>,
}

impl AppState {
    fn new() -> Self {
        Self {
            idex_webview: None,
            telegram_webview: None,
        }
    }
}

fn main() -> wry::Result<()> {
    // --- Запуск Tokio runtime в отдельном потоке для асинхронных задач ---
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Не удалось создать Tokio runtime"),
    );
    {
        let rt_clone = rt.clone();
        thread::spawn(move || {
            rt_clone.block_on(async {
                let target_site = "https://panel.gate.cx/".to_string();
                let proxy_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
                let proxy_state = ProxyState::new(target_site.clone());

                // Запускаем прокси
                tokio::spawn(run_proxy(proxy_state.clone(), proxy_addr));

                // Запускаем модуль транзакций (IDEX)
                tokio::spawn(run_idex(proxy_state));

                // Бесконечный цикл, чтобы runtime не завершился
                loop {
                    time::sleep(Duration::from_secs(1)).await;
                }
            });
        });
    }

    // --- Создание главного event loop с пользовательскими командами ---
    let event_loop = EventLoop::<Command>::with_user_event();
    let proxy_event = event_loop.create_proxy();

    // Создаём глобальное состояние для хранения webview окон
    let app_state = Arc::new(Mutex::new(AppState::new()));

    // Отправляем команды на автоматическое открытие обоих окон по запуску.
    {
        let proxy_clone = proxy_event.clone();
        thread::spawn(move || {
            // Немного задержки перед отправкой команд
            thread::sleep(Duration::from_millis(100));
            proxy_clone
                .send_event(Command::ShowIdex)
                .expect("Send failed");
            proxy_clone
                .send_event(Command::ShowTelegram)
                .expect("Send failed");
        });
    }

    // --- Запуск системного трея ---
    let tray_proxy = proxy_event.clone();
    thread::spawn(move || {
        let mut tray = systray::Application::new().expect("Не удалось создать трей-приложение");
        tray.set_icon_from_file("icon.ico")
            .expect("Не удалось установить иконку");

        // Добавляем обработчики для каждого пункта меню
        {
            let proxy = tray_proxy.clone();
            tray.add_menu_item("Показать IDEX", move |_| {
                println!("Tray: Показать IDEX");
                proxy.send_event(Command::ShowIdex).expect("Send failed");
                Ok::<(), systray::Error>(())
            })
            .unwrap();
        }

        {
            let proxy = tray_proxy.clone();
            tray.add_menu_item("Показать Telegram", move |_| {
                println!("Tray: Показать Telegram");
                proxy.send_event(Command::ShowTelegram).expect("Send failed");
                Ok::<(), systray::Error>(())
            })
            .unwrap();
        }

        {
            let proxy = tray_proxy.clone();
            tray.add_menu_item("Выйти", move |_| {
                println!("Tray: Выход");
                proxy.send_event(Command::Exit).expect("Send failed");
                Ok::<(), systray::Error>(())
            })
            .unwrap();
        }

        tray.wait_for_message().expect("Ошибка в цикле обработки трея");
    });

    // --- Запуск главного event loop ---
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(cmd) => match cmd {
                Command::ShowIdex => {
                    let mut state = app_state.lock().unwrap();
                    // Если окно IDEX ещё не открыто, создаём его
                    if state.idex_webview.is_none() {
                        let window = WindowBuilder::new()
                            .with_title("IDEX")
                            .with_inner_size(LogicalSize::new(1024.0, 768.0))
                            .build(target)
                            .expect("Не удалось создать окно IDEX");

                        let initial_cookies =
                            load_cookies().unwrap_or_default().cookies;
                        let cookie_script = initial_cookies
                            .iter()
                            .map(|c| {
                                format!(
                                    "document.cookie = '{}={}; path={}';",
                                    c.name, c.value, c.path
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n");

                        let proxy_url = format!(
                            "http://{}/{}",
                            "127.0.0.1:8080", "https://panel.gate.cx/"
                        );
                        let webview = WebViewBuilder::new(window)
                            .expect("Ошибка создания webview")
                            .with_url(&proxy_url)
                            .expect("Не удалось загрузить URL")
                            .with_initialization_script(&cookie_script)
                            .with_initialization_script(
                                r#"
                                document.addEventListener('contextmenu', event => {
                                    event.preventDefault();
                                });
                                "#,
                            )
                            .build()
                            .expect("Ошибка сборки webview");

                        // Сохраняем webview в global state, чтобы он не был уничтожен
                        state.idex_webview = Some(webview);
                        println!("Открыт IDEX");
                    }
                }
                Command::ShowTelegram => {
                    let mut state = app_state.lock().unwrap();
                    if state.telegram_webview.is_none() {
                        // Функция show_telegram должна возвращать Result<WebView, wry::Error>
                        match show_telegram(target) {
                            Ok(tv) => {
                                state.telegram_webview = Some(tv);
                                println!("Открыт Telegram");
                            }
                            Err(e) => {
                                eprintln!("Ошибка при открытии Telegram: {:#?}", e);
                            }
                        }
                    }
                }
                Command::Exit => {
                    println!("Завершение работы приложения...");
                    // Очищаем все окна перед выходом
                    let mut state = app_state.lock().unwrap();
                    state.idex_webview = None;
                    state.telegram_webview = None;
                    // Принудительно завершаем процесс после очистки
                    process::exit(0);
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                println!("Окно закрыто: {:?}", window_id);
                // Очищаем состояние окна при его закрытии
                let mut state = app_state.lock().unwrap();
                if let Some(ref webview) = state.idex_webview {
                    if webview.window().id() == window_id {
                        state.idex_webview = None;
                    }
                }
                if let Some(ref webview) = state.telegram_webview {
                    if webview.window().id() == window_id {
                        state.telegram_webview = None;
                    }
                }
            }
            _ => (),
        }
    });
}
