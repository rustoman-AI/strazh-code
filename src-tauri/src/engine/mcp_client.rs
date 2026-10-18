use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MCPTool {
    pub name: String,
    pub description: String,
    pub payload_schema: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MCPServer {
    pub id: String,
    pub name: String,
    pub url: String,
    pub transport: String,
    pub status: String,
    pub version: String,
    pub tools: Vec<MCPTool>,
}

pub struct MCPConfigManager;

impl MCPConfigManager {
    pub fn get_default_servers() -> Vec<MCPServer> {
        vec![
            MCPServer {
                id: "mcp-github-01".into(),
                name: "GitHub PR Integration".into(),
                url: "github.com/api/v3".into(),
                transport: "HTTP".into(),
                status: "Connected".into(),
                version: "1.2.0".into(),
                tools: vec![
                    MCPTool {
                        name: "create_pull_request".into(),
                        description: "Generate a PR for a specific remediation patch".into(),
                        payload_schema: "{ repo: string, patch: string }".into(),
                    },
                    MCPTool {
                        name: "list_open_prs".into(),
                        description: "List currently open PRs for the repository".into(),
                        payload_schema: "{ repo: string }".into(),
                    }
                ]
            },
            MCPServer {
                id: "mcp-jira-db".into(),
                name: "Jira Security Triage".into(),
                url: "jira.internal.corp".into(),
                transport: "Stdio".into(),
                status: "Disconnected".into(),
                version: "0.9.5".into(),
                tools: vec![
                    MCPTool {
                        name: "create_ticket".into(),
                        description: "Create a High priority security incident ticket".into(),
                        payload_schema: "{ summary: string, severity: string }".into(),
                    }
                ]
            }
        ]
    }

    pub async fn simulate_connect(url: &str) -> Result<MCPServer, String> {
        // Mock a 2 second connection handshake
        tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

        Ok(MCPServer {
            id: format!("mcp-custom-{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>()),
            name: "Custom MCP Integration".into(),
            url: url.to_string(),
            transport: if url.starts_with("http") { "HTTP".into() } else { "Stdio".into() },
            status: "Connected".into(),
            version: "1.0.0".into(),
            tools: vec![
                MCPTool {
                    name: "custom_fetch".into(),
                    description: "Fetch arbitrary context from the registered external hook".into(),
                    payload_schema: "{ query: string }".into(),
                }
            ]
        })
    }
}
