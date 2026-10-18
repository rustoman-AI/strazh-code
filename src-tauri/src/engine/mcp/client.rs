use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use serde_json::json;
use tokio::sync::Mutex;

use super::protocol::{JsonRpcRequest, McpToolDef, McpToolsListResult, MCP_PROTOCOL_VERSION};
use super::transport::StdioTransport;

// ── McpServer ──────────────────────────────────────────────────────────────

struct McpServerInner {
    name: String,
    transport: StdioTransport,
    next_id: AtomicU64,
    tools: Vec<McpToolDef>,
}

#[derive(Clone)]
pub struct McpServer {
    inner: Arc<Mutex<McpServerInner>>,
}

impl McpServer {
    pub async fn connect(name: &str, command: &str, args: &[String]) -> Result<Self> {
        let mut transport = StdioTransport::new(command, args)?;

        let id = 1u64;
        let init_req = JsonRpcRequest::new(
            id,
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "cyclonedx-tauri",
                    "version": "0.1.0"
                }
            }),
        );

        let init_resp = transport.send_and_recv(&init_req).await?;
        if init_resp.error.is_some() {
            bail!("MCP server `{name}` rejected initialize: {:?}", init_resp.error);
        }

        let notif = JsonRpcRequest::notification("notifications/initialized", json!({}));
        let _ = transport.send_and_recv(&notif).await;

        let id = 2u64;
        let list_req = JsonRpcRequest::new(id, "tools/list", json!({}));
        let list_resp = transport.send_and_recv(&list_req).await?;

        let result = list_resp.result.ok_or_else(|| anyhow!("tools/list returned no result"))?;
        let tool_list: McpToolsListResult = serde_json::from_value(result)?;

        let inner = McpServerInner {
            name: name.to_string(),
            transport,
            next_id: AtomicU64::new(3),
            tools: tool_list.tools,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub async fn tools(&self) -> Vec<McpToolDef> {
        self.inner.lock().await.tools.clone()
    }

    pub async fn name(&self) -> String {
        self.inner.lock().await.name.clone()
    }

    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest::new(
            id,
            "tools/call",
            json!({ "name": tool_name, "arguments": arguments }),
        );

        let resp = inner.transport.send_and_recv(&req).await?;
        if let Some(err) = resp.error {
            bail!("MCP tool error {}: {}", err.code, err.message);
        }
        Ok(resp.result.unwrap_or(serde_json::Value::Null))
    }
}

// ── McpRegistry ───────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct McpRegistry {
    servers: Arc<Mutex<HashMap<String, McpServer>>>,
}

impl McpRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, name: &str, command: &str, args: &[String]) -> Result<Vec<McpToolDef>> {
        let server = McpServer::connect(name, command, args).await?;
        let tools = server.tools().await;
        
        let mut servers = self.servers.lock().await;
        servers.insert(name.to_string(), server);
        
        Ok(tools)
    }

    pub async fn list_tools(&self, server_name: &str) -> Result<Vec<McpToolDef>> {
        let servers = self.servers.lock().await;
        let server = servers.get(server_name).ok_or_else(|| anyhow!("MCP server not found"))?;
        Ok(server.tools().await)
    }

    pub async fn call_tool(
        &self,
        server_name: &str,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let servers = self.servers.lock().await;
        let server = servers.get(server_name).ok_or_else(|| anyhow!("MCP server not found"))?;
        server.call_tool(tool_name, arguments).await
    }
}
