use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::Manager;

// ══════════════════════════════════════════════════════
//  AppConfig — persistent application configuration
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolPaths {
    pub cyclonedx: String,
    pub cdxgen: String,
    pub sbom_checker: String,
    pub trivy: String,
}

impl Default for ToolPaths {
    fn default() -> Self {
        Self {
            cyclonedx: "(sidecar)".into(),
            cdxgen: "cdxgen".into(),
            sbom_checker: "sbom-checker-go".into(),
            trivy: "trivy".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    pub https_proxy: String,
    pub http_proxy: String,
    pub no_proxy: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            https_proxy: String::new(),
            http_proxy: String::new(),
            no_proxy: "localhost,127.0.0.1".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SslConfig {
    pub trust_all: bool,
    pub ca_cert_path: String,
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            trust_all: false,
            ca_cert_path: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub tool_paths: ToolPaths,
    pub air_gap_mode: bool,
    pub proxy: ProxyConfig,
    pub ssl: SslConfig,
    pub default_output_format: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tool_paths: ToolPaths::default(),
            air_gap_mode: false,
            proxy: ProxyConfig::default(),
            ssl: SslConfig::default(),
            default_output_format: "json".into(),
        }
    }
}

// ══════════════════════════════════════════════════════
//  Config file path helper
// ══════════════════════════════════════════════════════

fn config_path(app: &tauri::AppHandle) -> PathBuf {
    let dir = app.path().app_data_dir().expect("app data dir");
    dir.join("config.json")
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn get_config(app: tauri::AppHandle) -> Result<AppConfig, String> {
    let path = config_path(&app);
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let config: AppConfig = serde_json::from_str(&content)
            .unwrap_or_default();
        Ok(config)
    } else {
        Ok(AppConfig::default())
    }
}

#[tauri::command]
pub fn save_config(app: tauri::AppHandle, config: AppConfig) -> Result<(), String> {
    let path = config_path(&app);
    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;
    }
    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Apply proxy env vars if configured
    if !config.proxy.https_proxy.is_empty() {
        std::env::set_var("HTTPS_PROXY", &config.proxy.https_proxy);
    }
    if !config.proxy.http_proxy.is_empty() {
        std::env::set_var("HTTP_PROXY", &config.proxy.http_proxy);
    }
    if !config.proxy.no_proxy.is_empty() {
        std::env::set_var("NO_PROXY", &config.proxy.no_proxy);
    }

    Ok(())
}

#[tauri::command]
pub async fn check_tool_versions() -> Result<HashMap<String, ToolStatus>, String> {
    let tools = vec![
        ("cdxgen", vec!["--version"]),
        ("cyclonedx", vec!["--version"]),
        ("trivy", vec!["--version"]),
        ("sbom-checker-go", vec!["--version"]),
    ];

    let mut results = HashMap::new();

    for (name, args) in tools {
        let status = match tokio::process::Command::new(name)
            .args(&args)
            .output()
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let version = stdout.lines().next().unwrap_or("").to_string();
                if output.status.success() {
                    ToolStatus {
                        available: true,
                        version: if version.is_empty() { "unknown".into() } else { version },
                        path: resolve_which(name),
                    }
                } else {
                    ToolStatus {
                        available: true,
                        version: "error".into(),
                        path: resolve_which(name),
                    }
                }
            }
            Err(_) => ToolStatus {
                available: false,
                version: String::new(),
                path: String::new(),
            },
        };
        results.insert(name.to_string(), status);
    }

    Ok(results)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolStatus {
    pub available: bool,
    pub version: String,
    pub path: String,
}

/// Try to resolve the full path of a tool using `which`
fn resolve_which(name: &str) -> String {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}
