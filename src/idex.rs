use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    time::Duration,
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time;
use crate::ProxyState;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub user_id: Option<String>,
    pub transaction_id: String,
    pub payment_method_id: Option<String>,
    pub wallet: Option<String>,
    pub amount_rub: f64,
    pub amount_usdt: f64,
    pub total_rub: f64,
    pub total_usdt: f64,
    pub status: Option<String>,
    pub bank_name: Option<String>,
    pub bank_code: Option<String>,
    pub bank_label: Option<String>,
    pub payment_method: Option<String>,
    pub course: Option<f64>,
    pub success_count: Option<u32>,
    pub success_rate: Option<f64>,
    pub approved_at: Option<String>,
    pub expired_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub trader_id: Option<String>,
    pub trader_name: Option<String>,
    pub attachments: Option<Value>,
    pub idex_id: Option<String>,
}

/// Загружает сохранённые транзакции из файла idex_history.json
pub fn load_transactions() -> Vec<Transaction> {
    let path = PathBuf::from("idex_history.json");
    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<Transaction>>(&content) {
                Ok(tx) => {
                    println!("Loaded {} transactions from file.", tx.len());
                    return tx;
                }
                Err(e) => {
                    println!("Failed to deserialize transactions from file: {}", e);
                }
            },
            Err(e) => println!("Failed to read idex_history.json file: {}", e),
        }
    }
    Vec::new()
}

/// Сохраняет транзакции в файл idex_history.json
pub fn save_transactions(tx: &[Transaction]) -> std::io::Result<()> {
    let path = PathBuf::from("idex_history.json");
    let json = serde_json::to_string_pretty(tx)?;
    fs::write(path, json)?;
    Ok(())
}

/// Преобразует значение (JSON) в строку независимо от типа (число или строка).
fn extract_id(val: &Value) -> Option<String> {
    if let Some(s) = val.as_str() {
        Some(s.to_string())
    } else if let Some(n) = val.as_i64() {
        Some(n.to_string())
    } else {
        None
    }
}

/// Функция маппинга транзакции из JSON (Value) в Transaction.
/// Адаптируйте её под реальную структуру ответа API.
fn map_transaction(json: &Value) -> Option<Transaction> {
    println!("Mapping transaction: {:?}", json);
    // Пытаемся извлечь id транзакции, используя extract_id
    let id = json.get("id").and_then(extract_id)?;
    Some(Transaction {
        user_id: json
            .get("userId")
            .and_then(|v| v.as_str())
            .map(String::from),
        transaction_id: id,
        payment_method_id: json
            .get("payment_method_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        wallet: json
            .get("wallet")
            .and_then(|v| v.as_str())
            .map(String::from),
        amount_rub: json
            .get("amount")
            .and_then(|amt| amt.get("trader"))
            .and_then(|tr| tr.get("643"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        amount_usdt: json
            .get("amount")
            .and_then(|amt| amt.get("trader"))
            .and_then(|tr| tr.get("000001"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        total_rub: json
            .get("total")
            .and_then(|tot| tot.get("trader"))
            .and_then(|tr| tr.get("643"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        total_usdt: json
            .get("total")
            .and_then(|tot| tot.get("trader"))
            .and_then(|tr| tr.get("000001"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        status: json.get("status").and_then(|v| v.as_str()).map(String::from),
        bank_name: json
            .get("bank")
            .and_then(|b| b.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from),
        bank_code: json
            .get("bank")
            .and_then(|b| b.get("code"))
            .and_then(|v| v.as_str())
            .map(String::from),
        bank_label: json
            .get("bank")
            .and_then(|b| b.get("label"))
            .and_then(|v| v.as_str())
            .map(String::from),
        payment_method: json
            .get("method")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            .map(String::from),
        course: json
            .get("meta")
            .and_then(|m| m.get("courses"))
            .and_then(|c| c.get("trader"))
            .and_then(|v| v.as_f64()),
        success_count: json
            .get("tooltip")
            .and_then(|t| t.get("payments"))
            .and_then(|p| p.get("success"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        success_rate: json
            .get("tooltip")
            .and_then(|t| t.get("payments"))
            .and_then(|p| p.get("percent"))
            .and_then(|v| v.as_f64()),
        approved_at: json
            .get("approved_at")
            .and_then(|v| v.as_str())
            .map(String::from),
        expired_at: json
            .get("expired_at")
            .and_then(|v| v.as_str())
            .map(String::from),
        created_at: json
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        updated_at: json
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        trader_id: json
            .get("trader")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .map(String::from),
        trader_name: json
            .get("trader")
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from),
        attachments: json.get("attachments").cloned(),
        idex_id: None,
    })
}

/// Каждые 5 секунд опрашивает API выплат, выводит полный ответ сервера и,
/// если найдены новые транзакции, сразу сохраняет обновленный список в файл.
pub async fn run_idex(proxy_state: ProxyState) {
    let gate_api_url = "https://panel.gate.cx/api/v1/payments/payouts?filters%5Bstatus%5D%5B%5D=2&filters%5Bstatus%5D%5B%5D=3&filters%5Bstatus%5D%5B%5D=7&filters%5Bstatus%5D%5B%5D=8&filters%5Bstatus%5D%5B%5D=9&page=";
    let user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";
    let client = Client::new();

    loop {
        println!("Checking transactions...");
        let mut saved_tx = load_transactions();
        let mut saved_ids: HashSet<String> =
            saved_tx.iter().map(|tx| tx.transaction_id.clone()).collect();
        let mut new_transactions = Vec::new();

        // Проходим по страницам 1..=10
        for page in 1..=10 {
            let url = format!("{}{}", gate_api_url, page);
            println!("Fetching URL: {}", url);
            let mut req_builder = client.get(&url).header("User-Agent", user_agent);

            {
                let store = proxy_state.cookies.lock().unwrap();
                let cookie_str = store
                    .cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                if !cookie_str.is_empty() {
                    req_builder = req_builder.header("Cookie", cookie_str);
                }
            }

            match req_builder.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("Error reading text: {}", e));
                    println!("Response status: {}", status);
                    println!("Response body: {}", text);

                    if status.is_success() {
                        let json: Value = match serde_json::from_str(&text) {
                            Ok(val) => val,
                            Err(e) => {
                                println!("Failed to parse JSON: {}", e);
                                continue;
                            }
                        };

                        // Определяем массив транзакций (учитываются оба варианта расположения)
                        let trans_arr = json
                            .get("data")
                            .and_then(|d| d.get("transactions"))
                            .or_else(|| {
                                json.get("response")
                                    .and_then(|r| r.get("payouts"))
                                    .and_then(|p| p.get("data"))
                            })
                            .and_then(|t| t.as_array());

                        if let Some(trans_arr) = trans_arr {
                            println!(
                                "Found {} transactions on page {}.",
                                trans_arr.len(),
                                page
                            );
                            for transaction in trans_arr {
                                // Извлекаем id транзакции с учетом разных типов значений
                                if let Some(id_value) = transaction.get("id") {
                                    if let Some(id) = extract_id(id_value) {
                                        if saved_ids.contains(&id) {
                                            continue;
                                        }
                                        if let Some(new_tx) = map_transaction(transaction) {
                                            println!(
                                                "New transaction found: {}",
                                                new_tx.transaction_id
                                            );
                                            saved_ids.insert(new_tx.transaction_id.clone());
                                            new_transactions.push(new_tx);
                                        }
                                    } else {
                                        println!("Unable to extract transaction id.");
                                    }
                                }
                            }
                        } else {
                            println!("No transactions array in response on page {}.", page);
                        }
                    } else {
                        println!("Failed to fetch page {}: HTTP {}", page, status);
                    }
                }
                Err(e) => {
                    eprintln!("Error fetching page {}: {}", page, e);
                }
            }
        }

        if !new_transactions.is_empty() {
            println!("Found {} new transactions.", new_transactions.len());
            saved_tx.extend(new_transactions);
            match save_transactions(&saved_tx) {
                Ok(_) => println!("Transactions saved successfully."),
                Err(e) => eprintln!("Failed to save transactions: {}", e),
            }
        } else {
            println!("No new transactions on this check.");
        }
        time::sleep(Duration::from_secs(5)).await;
    }
}
