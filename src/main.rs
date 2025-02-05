use std::{
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
    convert::Infallible,
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

// -----------------------------
// Работа с куками для прокси
// -----------------------------
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

// -----------------------------
// Прокси-состояние
// -----------------------------
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

// -----------------------------
// Прокси-обработчик
// -----------------------------
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

// -----------------------------
// Команды для event loop.
// -----------------------------
#[derive(Debug)]
enum Command {
    ShowIdex,
    Exit,
}

// -----------------------------
// Глобальное состояние окон. 
// -----------------------------
struct AppState {
    idex_webview: Option<WebView>,
}

impl AppState {
    fn new() -> Self {
        Self { idex_webview: None }
    }
}

// -----------------------------
// Функция для проверки токена через API.
// -----------------------------
async fn verify_device_token(api_url: &str, device_token: &str) -> bool {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({ "deviceToken": device_token });
    match client.post(api_url).json(&payload).send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                // Если сервер вернул поле valid: true — токен валиден.
                json.get("valid").and_then(|v| v.as_bool()) == Some(true)
            } else {
                false
            }
        }
        Err(err) => {
            eprintln!("Ошибка запроса проверки токена: {}", err);
            false
        }
    }
}

// -----------------------------
// Функция для ввода токена через консоль.
// -----------------------------
fn ask_token_from_console() -> String {
    print!("Введите Device Token: ");
    io::stdout().flush().unwrap();
    let mut token = String::new();
    io::stdin()
        .read_line(&mut token)
        .expect("Ошибка чтения из консоли");
    token.trim().to_string()
}

// -----------------------------
// Main
// -----------------------------
fn main() -> wry::Result<()> {
    // Создаем Tokio runtime.
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Не удалось создать Tokio runtime"),
    );

    // Определяем URL API для проверки токена.
    #[cfg(debug_assertions)]
    let token_api_url = "http://localhost/api/deviceToken".to_string();
    #[cfg(not(debug_assertions))]
    let token_api_url = "https://p2pp.vercel.app/api/deviceToken".to_string();

    // Проверка токена: если файла нет или токен не валиден, запрашиваем ввод через консоль.
    let device_token_path = PathBuf::from("device.token");
    let mut device_token = String::new();
    let token_valid = if device_token_path.exists() {
        match fs::read_to_string(&device_token_path) {
            Ok(token) => {
                device_token = token.trim().to_string();
                rt.block_on(verify_device_token(&token_api_url, &device_token))
            }
            Err(e) => {
                eprintln!("Ошибка чтения device.token: {}", e);
                false
            }
        }
    } else {
        false
    };

    if !token_valid {
        println!("Device token отсутствует или не валиден.");
        loop {
            let input_token = ask_token_from_console();
            if input_token.is_empty() {
                eprintln!("Токен не введён, завершение работы.");
                process::exit(1);
            }
            let validated = rt.block_on(verify_device_token(&token_api_url, &input_token));
            if validated {
                device_token = input_token.clone();
                if let Err(e) = fs::write(&device_token_path, &device_token) {
                    eprintln!("Ошибка записи device.token: {}", e);
                    process::exit(1);
                }
                println!("Device token подтвержден и сохранен.");
                break;
            } else {
                eprintln!("Получен невалидный токен, попробуйте снова.");
            }
        }
    } else {
        println!("Device token существует и валиден.");
    }

    // Запуск Tokio runtime для асинхронных задач.
    {
        let rt_clone = rt.clone();
        thread::spawn(move || {
            rt_clone.block_on(async {
                let target_site = "https://panel.gate.cx/".to_string();
                let proxy_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
                let proxy_state = ProxyState::new(target_site.clone());

                // Запускаем прокси.
                tokio::spawn(run_proxy(proxy_state.clone(), proxy_addr));

                // Запускаем модуль транзакций (IDEX).
                tokio::spawn(run_idex(proxy_state));

                // Чтобы runtime не завершился.
                loop {
                    time::sleep(Duration::from_secs(1)).await;
                }
            });
        });
    }

    // Создаем event loop для пользовательских команд.
    let event_loop = EventLoop::<Command>::with_user_event();
    let proxy_event = event_loop.create_proxy();

    // Глобальное состояние для окон.
    let app_state = Arc::new(Mutex::new(AppState::new()));

    // Автоматически открываем окно IDEX.
    {
        let proxy_clone = proxy_event.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            proxy_clone
                .send_event(Command::ShowIdex)
                .expect("Send failed");
        });
    }

    // Основной event loop.
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(cmd) => match cmd {
                Command::ShowIdex => {
                    let mut state = app_state.lock().unwrap();
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

                        state.idex_webview = Some(webview);
                        println!("Открыт IDEX");
                    }
                }
                Command::Exit => {
                    println!("Завершение работы приложения...");
                    let mut state = app_state.lock().unwrap();
                    state.idex_webview = None;
                    process::exit(0);
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                println!("Окно закрыто: {:?}", window_id);
                let mut state = app_state.lock().unwrap();
                if let Some(ref webview) = state.idex_webview {
                    if webview.window().id() == window_id {
                        state.idex_webview = None;
                    }
                }
            }
            _ => {}
        }
    });
}
