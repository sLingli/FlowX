use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use crate::monitor::ConnectionManager;

const API_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ApiServer {
    pub bind_addr: SocketAddr,
    pub monitor: Arc<ConnectionManager>,
}

impl ApiServer {
    pub fn new(bind_addr: SocketAddr, monitor: Arc<ConnectionManager>) -> Self {
        Self { bind_addr, monitor }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!("[API 接口] FlowX 状态与控制 HTTP API 服务已在 http://{} 启动", self.bind_addr);

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    error!("[API 接口] 接收 HTTP API 请求失败: {}", e);
                    continue;
                }
            };

            let monitor = Arc::clone(&self.monitor);
            tokio::spawn(async move {
                if let Err(e) = tokio::time::timeout(API_TIMEOUT, handle_api_request(stream, monitor)).await {
                    error!("[API 接口] 处理请求超时或异常: {}", e);
                }
            });
        }
    }
}

async fn handle_api_request(mut stream: TcpStream, monitor: Arc<ConnectionManager>) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or_default();
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    let (status, content_type, body) = match (method, path) {
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        ("GET", "/") | ("GET", "/dashboard") => {
            let html = include_str!("../../frontend/index.html");
            ("200 OK", "text/html; charset=utf-8", html.to_string())
        }
        ("GET", "/api/health") => ("200 OK", "application/json; charset=utf-8", r#"{"status":"ok","engine":"FlowX"}"#.to_string()),
        ("GET", "/api/stats") => {
            let stats = monitor.global_stats();
            let json = serde_json_to_string(&stats);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        ("GET", "/api/connections") => {
            let list = monitor.list_snapshots();
            let json = serde_json_to_string(&list);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        _ => ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"Not Found"}"#.to_string()),
    };

    let response = format!(
        "HTTP/1.1 {}\r\n\
Content-Type: {}\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: *\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        status,
        content_type,
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn serde_json_to_string<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_server_creation() {
        let mgr = Arc::new(ConnectionManager::new());
        let srv = ApiServer::new("127.0.0.1:40080".parse().unwrap(), mgr);
        assert_eq!(srv.bind_addr.port(), 40080);
    }
}
