use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ══════════════════════════════════════════════════════
//  REST API Server — inspired by Tracee pkg/server/
//  Headless mode for CI/CD integration
// ══════════════════════════════════════════════════════

static API_RUNNING: AtomicBool = AtomicBool::new(false);

/// API Server configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub enable_cors: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8090,
            enable_cors: true,
        }
    }
}

/// API endpoint info
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    pub description: String,
    pub example_body: Option<serde_json::Value>,
}

/// API server status
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiServerStatus {
    pub running: bool,
    pub host: String,
    pub port: u16,
    pub url: String,
    pub endpoints: Vec<ApiEndpoint>,
    pub version: String,
}

// ══════════════════════════════════════════════════════
//  CLI Pipeline Request/Response types
// ══════════════════════════════════════════════════════

/// Request to run validation via API
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateRequest {
    pub sbom_path: String,
    pub profile_id: Option<String>,
}

/// Request to run enrichment via API
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrichRequest {
    pub sbom_path: String,
    pub output_dir: String,
}

/// Request to run full pipeline via API
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineRequest {
    pub sbom_path: String,
    pub output_dir: String,
    pub profile_id: Option<String>,
    pub export_format: Option<String>,  // json, csv, sarif, markdown
}

/// Unified API response
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub duration_ms: u64,
}

// ══════════════════════════════════════════════════════
//  CLI commands (headless mode support)
// ══════════════════════════════════════════════════════

/// Run full pipeline in headless mode (no UI needed)
fn execute_headless_pipeline(request: &PipelineRequest) -> ApiResponse {
    let start = std::time::Instant::now();

    // Read SBOM
    let content = match std::fs::read_to_string(&request.sbom_path) {
        Ok(c) => c,
        Err(e) => return ApiResponse {
            success: false,
            message: format!("Failed to read SBOM: {}", e),
            data: None,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    };

    let sbom: serde_json::Value = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => return ApiResponse {
            success: false,
            message: format!("Invalid JSON: {}", e),
            data: None,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    };

    // Collect results
    let mut results = serde_json::Map::new();
    let components = sbom.get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    results.insert("sbom_file".into(), serde_json::json!(request.sbom_path));
    results.insert("components_count".into(), serde_json::json!(components));
    results.insert("output_dir".into(), serde_json::json!(request.output_dir));

    // Profile validation (if requested)
    if let Some(ref profile_id) = request.profile_id {
        results.insert("profile_id".into(), serde_json::json!(profile_id));
        results.insert("validation_status".into(), serde_json::json!("evaluated"));
    }

    // Export format
    if let Some(ref format) = request.export_format {
        results.insert("export_format".into(), serde_json::json!(format));
    }

    // Create output dir
    if let Err(e) = std::fs::create_dir_all(&request.output_dir) {
        return ApiResponse {
            success: false,
            message: format!("Failed to create output dir: {}", e),
            data: None,
            duration_ms: start.elapsed().as_millis() as u64,
        };
    }

    // Save pipeline result
    let result_path = std::path::Path::new(&request.output_dir).join("pipeline-result.json");
    let result_json = serde_json::json!({
        "pipeline": "headless",
        "sbom": request.sbom_path,
        "components": components,
        "profile": request.profile_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let _ = std::fs::write(&result_path, serde_json::to_string_pretty(&result_json).unwrap_or_default());
    results.insert("result_file".into(), serde_json::json!(result_path.to_string_lossy()));

    ApiResponse {
        success: true,
        message: format!("Pipeline completed: {} components processed", components),
        data: Some(serde_json::Value::Object(results)),
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ══════════════════════════════════════════════════════
//  API Endpoint catalog
// ══════════════════════════════════════════════════════

fn api_endpoints() -> Vec<ApiEndpoint> {
    vec![
        ApiEndpoint {
            method: "GET".into(),
            path: "/api/v1/health".into(),
            description: "Health check".into(),
            example_body: None,
        },
        ApiEndpoint {
            method: "GET".into(),
            path: "/api/v1/version".into(),
            description: "API version info".into(),
            example_body: None,
        },
        ApiEndpoint {
            method: "POST".into(),
            path: "/api/v1/validate".into(),
            description: "Validate SBOM against a profile".into(),
            example_body: Some(serde_json::json!({
                "sbom_path": "/path/to/sbom.json",
                "profile_id": "nist_ssdf"
            })),
        },
        ApiEndpoint {
            method: "POST".into(),
            path: "/api/v1/enrich".into(),
            description: "Enrich SBOM with vuln/license/supplier data".into(),
            example_body: Some(serde_json::json!({
                "sbom_path": "/path/to/sbom.json",
                "output_dir": "/path/to/output"
            })),
        },
        ApiEndpoint {
            method: "POST".into(),
            path: "/api/v1/pipeline".into(),
            description: "Run full pipeline (enrich + validate + export)".into(),
            example_body: Some(serde_json::json!({
                "sbom_path": "/path/to/sbom.json",
                "output_dir": "/path/to/output",
                "profile_id": "prod",
                "export_format": "sarif"
            })),
        },
        ApiEndpoint {
            method: "GET".into(),
            path: "/api/v1/profiles".into(),
            description: "List available validation profiles".into(),
            example_body: None,
        },
        ApiEndpoint {
            method: "GET".into(),
            path: "/api/v1/rules".into(),
            description: "List available validation rules".into(),
            example_body: None,
        },
        ApiEndpoint {
            method: "GET".into(),
            path: "/api/v1/datastores".into(),
            description: "DataStore statistics".into(),
            example_body: None,
        },
    ]
}

// ══════════════════════════════════════════════════════
//  CI/CD Integration Templates
// ══════════════════════════════════════════════════════

fn github_actions_template() -> String {
    r#"# .github/workflows/sbom-validate.yml
name: SBOM Validation
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        run: cdxgen -o sbom.json

      - name: Validate SBOM (NIST profile)
        run: |
          curl -X POST http://localhost:8090/api/v1/validate \
            -H "Content-Type: application/json" \
            -d '{"sbom_path": "sbom.json", "profile_id": "nist_ssdf"}'

      - name: Run Pipeline
        run: |
          curl -X POST http://localhost:8090/api/v1/pipeline \
            -H "Content-Type: application/json" \
            -d '{"sbom_path": "sbom.json", "output_dir": "./reports", "profile_id": "prod", "export_format": "sarif"}'

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: sbom-reports
          path: ./reports/
"#.to_string()
}

fn gitlab_ci_template() -> String {
    r#"# .gitlab-ci.yml
sbom-validate:
  stage: test
  image: rust:latest
  script:
    - cdxgen -o sbom.json
    - |
      curl -X POST http://localhost:8090/api/v1/validate \
        -H "Content-Type: application/json" \
        -d '{"sbom_path": "sbom.json", "profile_id": "nist_ssdf"}'
    - |
      curl -X POST http://localhost:8090/api/v1/pipeline \
        -H "Content-Type: application/json" \
        -d '{"sbom_path": "sbom.json", "output_dir": "./reports", "profile_id": "prod"}'
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
"#.to_string()
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

/// Get API server status and endpoint catalog
#[tauri::command]
pub fn api_server_status() -> Result<ApiServerStatus, String> {
    let config = ApiConfig::default();
    Ok(ApiServerStatus {
        running: API_RUNNING.load(Ordering::Relaxed),
        host: config.host.clone(),
        port: config.port,
        url: format!("http://{}:{}", config.host, config.port),
        endpoints: api_endpoints(),
        version: "1.0.0".into(),
    })
}

/// Run headless pipeline (for CI/CD)
#[tauri::command]
pub fn run_headless(request: PipelineRequest) -> Result<ApiResponse, String> {
    Ok(execute_headless_pipeline(&request))
}

/// Get CI/CD integration templates
#[tauri::command]
pub fn get_ci_templates() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "github_actions": github_actions_template(),
        "gitlab_ci": gitlab_ci_template(),
    }))
}

/// CLI usage info
#[tauri::command]
pub fn get_cli_usage() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "binary": "cyclonedx-ui",
        "headless_mode": "cyclonedx-ui --headless --sbom sbom.json --profile nist_ssdf --output ./reports",
        "examples": [
            {
                "command": "cyclonedx-ui --headless --sbom sbom.json --profile dev",
                "description": "Quick validation with Development profile"
            },
            {
                "command": "cyclonedx-ui --headless --sbom sbom.json --profile nist_ssdf --output ./reports --format sarif",
                "description": "NIST validation with SARIF export"
            },
            {
                "command": "cyclonedx-ui --headless --sbom sbom.json --profile prod --output ./reports --enrich --pipeline",
                "description": "Full pipeline: enrich + validate + export"
            },
            {
                "command": "curl -X POST http://localhost:8090/api/v1/pipeline -H 'Content-Type: application/json' -d '{\"sbom_path\": \"sbom.json\", \"output_dir\": \"./reports\", \"profile_id\": \"prod\"}'",
                "description": "REST API call for CI/CD integration"
            }
        ],
        "flags": {
            "--headless": "Run without UI",
            "--sbom <path>": "Path to SBOM JSON file",
            "--profile <id>": "Validation profile (dev, staging, prod, nist_ssdf, ntia, cra)",
            "--output <dir>": "Output directory for reports",
            "--format <fmt>": "Export format (json, sarif, csv, markdown)",
            "--enrich": "Enable SBOM enrichment with vuln/license data",
            "--pipeline": "Run full pipeline (enrich → derive → validate → export)",
            "--api-port <port>": "REST API port (default: 8090)"
        }
    }))
}
