use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use hyper::{
    header::{HeaderValue, SET_COOKIE},
    Body, Request, Response, Server, StatusCode,
};
use hyper::service::{make_service_fn, service_fn};
use reqwest::header::HeaderMap;
use tokio::{task, time};
use wry::{
    application::{
        dpi::LogicalSize,
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    },
    webview::WebViewBuilder,
};

// Подключаем модуль idex, который находится в файле src/idex.rs
mod idex;
use idex::run_idex;

// ============================
// Structures for cookies
// ============================

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
    // поля в snake_case
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

// ============================
// Proxy state
// ============================

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

    /// Обновляет хранилище cookie на основе заголовков ответа.
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

/// Прокси-обработчик: ретранслирует все HTTP-запросы.
/// Если путь запроса содержит абсолютный URL — используется он, иначе URL строится относительно base_url.
/// Для запросов к panel.gate.cx переписывается заголовок Host и добавляются сохранённые Cookie.
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
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Invalid URL: {}", e)))
                    .unwrap());
            }
        }
    } else {
        let base = url::Url::parse(&state.base_url).expect("Invalid base URL");
        match base.join(req.uri().path()) {
            Ok(url) => url,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("URL join error: {}", e)))
                    .unwrap());
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
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Request error: {}", err)))
                .unwrap());
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(err) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Body error: {}", err)))
                .unwrap());
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
            Ok::<_, Infallible>(service_fn(move |req| proxy_handler(req, state.clone())))
        }
    });
    let server = Server::bind(&addr).serve(make_service);
    println!("Proxy server listening on http://{}", addr);
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> wry::Result<()> {
    let target_site = "https://panel.gate.cx/".to_string();
    let proxy_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let proxy_state = ProxyState::new(target_site.clone());
    let state_for_proxy = proxy_state.clone();
    task::spawn(async move {
        run_proxy(state_for_proxy, proxy_addr).await;
    });
    // Запускаем модуль транзакций (idex) в отдельном таске.
    let state_for_tx = proxy_state.clone();
    task::spawn(async move {
        run_idex(state_for_tx).await;
    });
    time::sleep(Duration::from_secs(1)).await;
    let proxy_url = format!("http://{}/{}", proxy_addr, target_site);
    let event_loop = wry::application::event_loop::EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("IDEX")
        .with_inner_size(LogicalSize::new(1024.0, 768.0))
        .build(&event_loop)?;
    let initial_cookies = {
        let store = load_cookies().unwrap_or_default();
        store.cookies
    };
    let cookie_script = initial_cookies
        .iter()
        .map(|c| format!("document.cookie = '{}={}; path={}';", c.name, c.value, c.path))
        .collect::<Vec<_>>()
        .join("\n");
    let webview = WebViewBuilder::new(window)?
        .with_url(&proxy_url)?
        .with_initialization_script(&cookie_script)
        .with_initialization_script(
            r#"
            document.addEventListener('contextmenu', event => {
                event.preventDefault();
            });
        "#,
        )
        .with_ipc_handler(|_window, message: String| {
            println!("Received IPC message: {}", message);
        })
        .build()?;
    webview.evaluate_script(&cookie_script)?;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = wry::application::event_loop::ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => println!("Приложение инициализировано"),
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                *control_flow = wry::application::event_loop::ControlFlow::Exit
            }
            _ => (),
        }
    });
}
