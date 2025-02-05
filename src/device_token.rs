use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const TOKEN_FILE: &str = "device_token.json";
const ENDPOINTS: [&str; 2] = ["http://localhost", "https://p2pp.vercel.app"];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTokenResponse {
    pub valid: bool,
    pub error: Option<String>,
    pub user_id: Option<String>,
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceToken {
    pub token: String,
}

impl DeviceToken {
    pub fn load() -> Option<Self> {
        let path = PathBuf::from(TOKEN_FILE);
        if path.exists() {
            fs::read_to_string(path)
                .ok()
                .and_then(|content| serde_json::from_str(&content).ok())
        } else {
            None
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = PathBuf::from(TOKEN_FILE);
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
    }

    pub fn delete() -> std::io::Result<()> {
        let path = PathBuf::from(TOKEN_FILE);
        if path.exists() {
            fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    pub async fn verify(&self) -> Result<DeviceTokenResponse, String> {
        let client = reqwest::Client::new();
        
        for endpoint in ENDPOINTS.iter() {
            let url = format!("{}/api/route/deviceToken", endpoint);
            
            match client
                .post(&url)
                .json(&serde_json::json!({
                    "deviceToken": self.token
                }))
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        if let Ok(result) = response.json::<DeviceTokenResponse>().await {
                            if result.valid {
                                return Ok(result);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        
        Err("Failed to verify device token on any endpoint".to_string())
    }
}

/// ***НОВЫЙ ФУНКЦИОНАЛ***  
/// Функция для отправки транзакций добавлена в модуль device_token.
pub async fn send_transactions(
    device_token: &str,
    cookies: Vec<super::Cookie>,
    transactions: Vec<serde_json::Value>,
) -> Result<bool, String> {
    let client = reqwest::Client::new();
    
    // Если понадобится добавить больше endpoint'ов, их можно перебрать
    for endpoint in ENDPOINTS.iter() {
        let url = format!("{}/api/route/idex", endpoint);
        
        match client
            .post(&url)
            .json(&serde_json::json!({
                "deviceToken": device_token,
                "cookies": cookies,
                "transactions": transactions
            }))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                            return Ok(true);
                        }
                    }
                } else if response.status() == reqwest::StatusCode::NOT_FOUND {
                    // Если токен не найден, удаляем файл токена
                    if let Err(e) = DeviceToken::delete() {
                        eprintln!("Failed to delete device token: {}", e);
                    }
                    return Err("Device token not found".to_string());
                }
            }
            Err(_) => continue,
        }
    }
    
    Err("Failed to send transactions to any endpoint".to_string())
}
