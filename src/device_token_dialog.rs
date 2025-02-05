use wry::application::{
    dpi::LogicalSize,
    event_loop::EventLoopWindowTarget,
    window::WindowBuilder,
};
use wry::webview::{WebView, WebViewBuilder};

const HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        input {
            width: 100%;
            padding: 8px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .error {
            color: red;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h3>Device Token Required</h3>
        <p>Please enter your device token to continue:</p>
        <input type="text" id="tokenInput" placeholder="Enter device token">
        <button onclick="saveToken()">Save Token</button>
        <div id="error" class="error"></div>
    </div>
    <script>
        async function saveToken() {
            const token = document.getElementById('tokenInput').value.trim();
            if (!token) {
                document.getElementById('error').textContent = 'Please enter a token';
                return;
            }
            
            try {
                const response = await window.ipc.postMessage(JSON.stringify({
                    type: 'save_token',
                    token: token
                }));
                
                if (response && response.error) {
                    document.getElementById('error').textContent = response.error;
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Failed to save token';
            }
        }
    </script>
</body>
</html>
"#;

pub fn show_device_token_dialog(
    event_loop: &EventLoopWindowTarget<super::Command>,
) -> wry::Result<()> {
    // Создаём окно
    let window = WindowBuilder::new()
        .with_title("Device Token")
        .with_inner_size(LogicalSize::new(400.0, 300.0))
        .with_resizable(false)
        .build(event_loop)?;

    // Строим WebView с HTML и IPC-обработчиком.
    // В обработчике первым параметром теперь является WebView (а не Window)
    let _webview: WebView = WebViewBuilder::new(window)?
        .with_html(HTML)?
        .with_ipc_handler(move |webview, msg| {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&msg) {
                if let Some(token) = data.get("token").and_then(|t| t.as_str()) {
                    let device_token = super::device_token::DeviceToken {
                        token: token.to_string(),
                    };
                    
                    // Спавним новый асинхронный таск для верификации
                    let webview = webview.clone();
                    tokio::spawn(async move {
                        match device_token.verify().await {
                            Ok(_) => {
                                if let Err(e) = device_token.save() {
                                    let script = format!(
                                        "document.getElementById('error').textContent = 'Failed to save token: {}'",
                                        e
                                    );
                                    let _ = webview.evaluate_script(&script);
                                    return;
                                }
                                // Закрываем окно через JavaScript
                                let _ = webview.evaluate_script("window.close();");
                            }
                            Err(e) => {
                                let script = format!(
                                    "document.getElementById('error').textContent = '{}'",
                                    e
                                );
                                let _ = webview.evaluate_script(&script);
                            }
                        }
                    });
                }
            }
        })
        .build()?;

    Ok(())
}
