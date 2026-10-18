use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ══════════════════════════════════════════════════════
//  ExportFormat — supported output formats
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Sarif,
    Csv,
    Markdown,
}

// ══════════════════════════════════════════════════════
//  ReportExporter — factory for converting pipeline
//  results into various output formats
// ══════════════════════════════════════════════════════

pub struct ReportExporter;

impl ReportExporter {
    /// Export a compliance report to the specified format
    pub fn export(
        report: &serde_json::Value,
        format: &ExportFormat,
        output_path: &Path,
    ) -> io::Result<()> {
        let content = match format {
            ExportFormat::Json => Self::to_json(report)?,
            ExportFormat::Sarif => Self::to_sarif(report)?,
            ExportFormat::Csv => Self::to_csv(report)?,
            ExportFormat::Markdown => Self::to_markdown(report)?,
        };
        std::fs::write(output_path, content)
    }

    fn to_json(report: &serde_json::Value) -> io::Result<String> {
        serde_json::to_string_pretty(report)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn to_sarif(report: &serde_json::Value) -> io::Result<String> {
        let sarif = crate::engine::nodes::compliance_to_sarif(report);
        serde_json::to_string_pretty(&sarif)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn to_csv(report: &serde_json::Value) -> io::Result<String> {
        let mut out = String::from("Check,Status,Requirement,Detail\n");
        if let Some(checks) = report["checks"].as_array() {
            for check in checks {
                let name = check["check"].as_str().unwrap_or("");
                let status = check["status"].as_str().unwrap_or("");
                let req = check["requirement"].as_str().unwrap_or("");
                let detail = check["detail"].as_str().unwrap_or("");
                // Escape CSV fields
                out.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",\"{}\"\n",
                    name.replace('"', "\"\""),
                    status,
                    req,
                    detail.replace('"', "\"\"")
                ));
            }
        }
        Ok(out)
    }

    fn to_markdown(report: &serde_json::Value) -> io::Result<String> {
        let mut md = String::from("# Compliance Report\n\n");

        // Summary
        if let Some(summary) = report.get("summary") {
            md.push_str("## Summary\n\n");
            md.push_str(&format!(
                "| Metric | Value |\n|--------|-------|\n| Pass | {} |\n| Fail | {} |\n| Total | {} |\n| Score | {} |\n\n",
                summary["pass"], summary["fail"], summary["total"],
                summary["score"].as_str().unwrap_or("—")
            ));
        }

        // Checks table
        if let Some(checks) = report["checks"].as_array() {
            md.push_str("## Checks\n\n");
            md.push_str("| Check | Status | Requirement | Detail |\n");
            md.push_str("|-------|--------|-------------|--------|\n");
            for check in checks {
                let status = check["status"].as_str().unwrap_or("");
                let icon = match status {
                    "PASS" => "✅",
                    "FAIL" => "❌",
                    _ => "⚠️",
                };
                md.push_str(&format!(
                    "| {} | {} {} | {} | {} |\n",
                    check["check"].as_str().unwrap_or(""),
                    icon, status,
                    check["requirement"].as_str().unwrap_or(""),
                    check["detail"].as_str().unwrap_or("—"),
                ));
            }
        }

        Ok(md)
    }
}

// ══════════════════════════════════════════════════════
//  DiagnosticsCollector — collect pipeline logs and
//  artifacts into a ZIP for debugging
// ══════════════════════════════════════════════════════

pub struct DiagnosticsCollector;

impl DiagnosticsCollector {
    /// Collect all files from workspace artifacts/ into a ZIP buffer
    pub fn collect_zip(workspace: &Path, logs: &[LogEntry]) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            // Add log entries as JSON
            let logs_json = serde_json::to_string_pretty(logs)
                .unwrap_or_else(|_| "[]".to_string());
            zip.start_file("pipeline.log.json", options)?;
            zip.write_all(logs_json.as_bytes())?;

            // Add artifacts
            let artifacts_dir = workspace.join("artifacts");
            if artifacts_dir.exists() {
                Self::add_dir_to_zip(&mut zip, &artifacts_dir, "artifacts", options)?;
            }

            zip.finish()?;
        }
        Ok(buf)
    }

    fn add_dir_to_zip<W: Write + io::Seek>(
        zip: &mut zip::ZipWriter<W>,
        dir: &Path,
        prefix: &str,
        options: zip::write::SimpleFileOptions,
    ) -> io::Result<()> {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = format!(
                    "{}/{}",
                    prefix,
                    entry.file_name().to_string_lossy()
                );
                if path.is_file() {
                    let content = std::fs::read(&path)?;
                    zip.start_file(&name, options)?;
                    zip.write_all(&content)?;
                } else if path.is_dir() {
                    Self::add_dir_to_zip(zip, &path, &name, options)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub node_id: String,
    pub level: String,
    pub message: String,
}

// ══════════════════════════════════════════════════════
//  WebhookSender — POST pipeline results to external
//  systems (CI/CD, Jira, custom endpoints)
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WebhookConfig {
    pub url: String,
    pub method: String,  // POST, PUT
    pub headers: std::collections::HashMap<String, String>,
    pub include_report: bool,
    pub include_sarif: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        Self {
            url: String::new(),
            method: "POST".into(),
            headers,
            include_report: true,
            include_sarif: false,
        }
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn export_report(
    input_path: String,
    output_path: String,
    format: ExportFormat,
) -> Result<String, String> {
    let content = tokio::fs::read_to_string(&input_path)
        .await
        .map_err(|e| format!("Failed to read report: {}", e))?;

    let report: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    ReportExporter::export(&report, &format, Path::new(&output_path))
        .map_err(|e| format!("Export failed: {}", e))?;

    Ok(format!("Exported to {}", output_path))
}

#[tauri::command]
pub async fn collect_diagnostics(
    workspace: String,
    output_path: String,
    logs: Vec<LogEntry>,
) -> Result<String, String> {
    let zip_data = DiagnosticsCollector::collect_zip(Path::new(&workspace), &logs)
        .map_err(|e| format!("Failed to collect diagnostics: {}", e))?;

    tokio::fs::write(&output_path, &zip_data)
        .await
        .map_err(|e| format!("Failed to write ZIP: {}", e))?;

    Ok(format!("Diagnostics saved: {} bytes", zip_data.len()))
}

#[tauri::command]
pub async fn send_webhook(
    config: WebhookConfig,
    payload: serde_json::Value,
) -> Result<String, String> {
    if config.url.is_empty() {
        return Err("Webhook URL is empty".into());
    }

    let client = reqwest::Client::new();
    let mut req = match config.method.to_uppercase().as_str() {
        "PUT" => client.put(&config.url),
        _ => client.post(&config.url),
    };

    for (k, v) in &config.headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let resp = req
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Webhook request failed: {}", e))?;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status >= 200 && status < 300 {
        Ok(format!("Webhook sent: HTTP {} ({})", status, body.chars().take(200).collect::<String>()))
    } else {
        Err(format!("Webhook failed: HTTP {} — {}", status, body.chars().take(500).collect::<String>()))
    }
}
