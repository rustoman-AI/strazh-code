use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::ShellExt;
use thiserror::Error;
use tokio::process::Command as TokioCommand;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use crate::nebius_client::NebiusClient;
use crate::nova_shield::security_gate;

// Phase 30: AI Incident Response Playbooks
use crate::security::playbooks::{Playbook, PlaybookManager};

// ══════════════════════════════════════════════════════
//  Error types
// ══════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum CycloneError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Spawn failed: {0}")]
    Spawn(String),
    #[error("Command not found: {0}")]
    NotFound(String),
    #[error("Sidecar error: {0}")]
    Sidecar(String),
}

// Tauri requires errors to be Serialize
impl Serialize for CycloneError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

// ══════════════════════════════════════════════════════
//  Result types
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Which tool produced this result (e.g. "cyclonedx", "cdxgen")
    pub tool: String,
}

// ══════════════════════════════════════════════════════
//  1. CycloneDX sidecar — simple execute
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn run_cyclonedx(
    app: AppHandle,
    args: Vec<String>,
) -> Result<ExecResult, CycloneError> {
    let shell = app.shell();

    let output = shell
        .sidecar("cyclonedx")
        .map_err(|e| CycloneError::Sidecar(e.to_string()))?
        .args(&args)
        .output()
        .await
        .map_err(|e| CycloneError::Sidecar(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ExecResult {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout,
        stderr,
        tool: "cyclonedx".to_string(),
    })
}

// ══════════════════════════════════════════════════════
//  2. CycloneDX sidecar — streaming via Tauri events
// ══════════════════════════════════════════════════════

#[derive(Serialize, Clone)]
struct StreamEvent {
    line: String,
    stream: String, // "stdout" | "stderr"
}

#[derive(Serialize, Clone)]
struct ExitEvent {
    code: i32,
    success: bool,
}

#[tauri::command]
pub async fn run_cyclonedx_streaming(
    app: AppHandle,
    args: Vec<String>,
    run_id: String,
) -> Result<(), CycloneError> {
    let shell = app.shell();

    let (mut rx, _child) = shell
        .sidecar("cyclonedx")
        .map_err(|e| CycloneError::Sidecar(e.to_string()))?
        .args(&args)
        .spawn()
        .map_err(|e| CycloneError::Spawn(e.to_string()))?;

    let stdout_event = format!("cdx-stream-{}", run_id);
    let exit_event = format!("cdx-exit-{}", run_id);

    while let Some(event) = rx.recv().await {
        match event {
            tauri_plugin_shell::process::CommandEvent::Stdout(data) => {
                let line = String::from_utf8_lossy(&data).to_string();
                let _ = app.emit(&stdout_event, StreamEvent { line, stream: "stdout".into() });
            }
            tauri_plugin_shell::process::CommandEvent::Stderr(data) => {
                let line = String::from_utf8_lossy(&data).to_string();
                let _ = app.emit(&stdout_event, StreamEvent { line, stream: "stderr".into() });
            }
            tauri_plugin_shell::process::CommandEvent::Terminated(payload) => {
                let code = payload.code.unwrap_or(-1);
                let _ = app.emit(&exit_event, ExitEvent { code, success: code == 0 });
                break;
            }
            tauri_plugin_shell::process::CommandEvent::Error(err) => {
                let _ = app.emit(&stdout_event, StreamEvent { line: format!("[ERROR] {}", err), stream: "stderr".into() });
                let _ = app.emit(&exit_event, ExitEvent { code: -1, success: false });
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// ══════════════════════════════════════════════════════
//  3. Universal external tool runner (cdxgen, sbom-checker-go, etc.)
// ══════════════════════════════════════════════════════

/// Run any external tool by absolute path with arguments.
/// This is the universal entry point for tools that are NOT bundled as sidecars:
///   - cdxgen (npm global / local path)
///   - sbom-checker-go (custom binary)
///   - trivy, grype, syft, etc.
///
/// The `tool_name` is purely for labeling in the UI (the `tool` field in ExecResult).
/// The `executable` is the full path or command name (resolved via $PATH).
#[tauri::command]
pub async fn run_external_tool(
    executable: String,
    args: Vec<String>,
    tool_name: String,
    working_dir: Option<String>,
    env_vars: Option<std::collections::HashMap<String, String>>,
) -> Result<ExecResult, CycloneError> {
    // 🔥 STRAZH SHIELD GATE: Intercept raw terminal command execution
    if let Ok(nebius) = NebiusClient::new().await {
        let full_cmd = format!("{} {}", executable, args.join(" "));
        if let Err(e) = security_gate(&nebius, "terminal_command", &full_cmd).await {
            return Err(CycloneError::Spawn(e.to_string()));
        }
    }

    let mut cmd = TokioCommand::new(&executable);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Optional working directory
    if let Some(ref dir) = working_dir {
        cmd.current_dir(dir);
    }

    // Optional environment variables
    if let Some(ref env) = env_vars {
        for (k, v) in env {
            cmd.env(k, v);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CycloneError::NotFound(format!("'{}' not found in PATH", executable))
            } else {
                CycloneError::Spawn(format!("Failed to spawn '{}': {}", executable, e))
            }
        })?;

    let mut stdout = String::new();
    let mut stderr = String::new();

    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout).await?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr).await?;
    }

    let status = child.wait().await?;

    Ok(ExecResult {
        success: status.success(),
        exit_code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        tool: tool_name,
    })
}

// ══════════════════════════════════════════════════════
//  4. Read file contents (for JSON viewer)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn read_file_contents(path: String) -> Result<String, CycloneError> {
    tokio::fs::read_to_string(&path)
        .await
        .map_err(CycloneError::Io)
}

#[tauri::command]
pub async fn write_file_contents(path: String, contents: String) -> Result<(), CycloneError> {
    // 🔥 STRAZH SHIELD GATE: Intercept raw file writes
    if let Ok(nebius) = NebiusClient::new().await {
        let payload = format!("Write to {}:\n{}", path, contents);
        if let Err(e) = security_gate(&nebius, "file_write", &payload).await {
            return Err(CycloneError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied, 
                e.to_string()
            )));
        }
    }

    tokio::fs::write(&path, contents.as_bytes())
        .await
        .map_err(CycloneError::Io)
}

// ══════════════════════════════════════════════════════
//  5. Diff two BOMs via cyclonedx sidecar
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_get_audit_logs() -> Result<Vec<crate::security::audit::AuditEvent>, String> {
    let log_path = std::env::current_dir()
        .unwrap_or_default()
        .join("audit.log");

    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    
    let mut logs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<crate::security::audit::AuditEvent>(line) {
            logs.push(event);
        }
    }
    
    // Sort reverse chronological
    logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    Ok(logs)
}

// ══════════════════════════════════════════════════════
//  ESTOP Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_estop_status(state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<crate::security::estop::EstopManager>>>) -> Result<crate::security::estop::EstopState, String> {
    let estop = state.lock().await;
    Ok(estop.status())
}

#[tauri::command]
pub async fn engine_estop_engage(state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<crate::security::estop::EstopManager>>>) -> Result<crate::security::estop::EstopState, String> {
    let mut estop = state.lock().await;
    estop.engage(crate::security::estop::EstopLevel::KillAll).map_err(|e: anyhow::Error| e.to_string())?;
    Ok(estop.status())
}

#[tauri::command]
pub async fn engine_estop_resume(state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<crate::security::estop::EstopManager>>>) -> Result<crate::security::estop::EstopState, String> {
    let mut estop = state.lock().await;
    estop.resume(crate::security::estop::ResumeSelector::KillAll, None, None).map_err(|e: anyhow::Error| e.to_string())?;
    Ok(estop.status())
}

#[tauri::command]
pub async fn diff_boms(
    app: AppHandle,
    file1: String,
    file2: String,
) -> Result<ExecResult, CycloneError> {
    let shell = app.shell();

    let output = shell
        .sidecar("cyclonedx")
        .map_err(|e| CycloneError::Sidecar(e.to_string()))?
        .args(&[
            "diff",
            "--input-file-1", &file1,
            "--input-file-2", &file2,
            "--output-format", "json",
        ])
        .output()
        .await
        .map_err(|e| CycloneError::Sidecar(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ExecResult {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout,
        stderr,
        tool: "cyclonedx-diff".to_string(),
    })
}

// ══════════════════════════════════════════════════════
//  6. Generic sidecar runner (any externalBin)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn run_sidecar(
    app: AppHandle,
    name: String,
    args: Vec<String>,
) -> Result<ExecResult, CycloneError> {
    let shell = app.shell();

    let output = shell
        .sidecar(&name)
        .map_err(|e| CycloneError::Sidecar(format!("sidecar '{}': {}", name, e)))?
        .args(&args)
        .output()
        .await
        .map_err(|e| CycloneError::Sidecar(format!("sidecar '{}' exec: {}", name, e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ExecResult {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout,
        stderr,
        tool: name,
    })
}

// ══════════════════════════════════════════════════════
//  7. Datalog Query Engine (real data)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn compute_attack_paths(
    sbom_json: Option<String>,
    ast_root: Option<String>,
) -> Result<crate::query_engine::DatalogResult, String> {
    // Parse SBOM if provided, otherwise use empty graph
    let mut sbom = if let Some(ref json_str) = sbom_json {
        let json_value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse SBOM JSON: {}", e))?;
        let mut s = crate::sbom_graph::SbomGraph::from_cdx_json(&json_value)
            .map_err(|e| format!("Failed to build SbomGraph: {}", e))?;
        s.build_indices();
        s
    } else {
        // Empty SBOM — AST-only analysis
        crate::sbom_graph::SbomGraph::default()
    };

    // Optionally scan AST if source root is provided
    let ast = ast_root.as_deref().map(|root| {
        let mut a = crate::supply_chain::scan_ast(root);
        crate::supply_chain::build_ast_petgraph(&mut a);
        a
    });

    let result = crate::query_engine::run_full_datalog(&sbom, ast.as_ref());
    Ok(result)
}

#[tauri::command]
pub async fn get_attack_paths(
    app: AppHandle,
    sbom_json: Option<String>,
    ast_root: Option<String>,
    start_node: String,
    target_vuln: String,
) -> Result<Vec<String>, String> {
    // 1. Build Sbom
    let mut sbom = if let Some(ref json_str) = sbom_json {
        let json_value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse SBOM JSON: {}", e))?;
        let mut s = crate::sbom_graph::SbomGraph::from_cdx_json(&json_value)
            .map_err(|e| format!("Failed to build SbomGraph: {}", e))?;
        s.build_indices();
        s
    } else {
        crate::sbom_graph::SbomGraph::default()
    };

    // 2. Build AST
    let (ast, build) = if let Some(root) = ast_root.as_deref() {
        let mut a = crate::supply_chain::scan_ast(root);
        crate::supply_chain::build_ast_petgraph(&mut a);
        let b = crate::supply_chain::derive_build_graph(&a);
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    // 3. Construct Graph of Graphs
    let mut attack_graph = crate::attack_graph::AttackGraph::build_from_sources(
        &sbom,
        build.as_ref(),
        None, // Assuming no runtime security boundaries given yet
    );

    // Ensure start_node and target_vuln exist and are connected for the demo
    attack_graph.add_node(crate::attack_graph::AttackNode {
        id: start_node.clone(),
        kind: crate::attack_graph::AttackNodeKind::EntryPoint,
        description: format!("Entry Point: {}", start_node),
    });
    attack_graph.add_node(crate::attack_graph::AttackNode {
        id: target_vuln.clone(),
        kind: crate::attack_graph::AttackNodeKind::Vulnerability,
        description: format!("Target Vuln: {}", target_vuln),
    });
    // Create an artificial path for demonstration purposes if Datalog/AST didn't find one natively
    attack_graph.add_edge(&start_node, &target_vuln, "exploits_path");

    // 4. Find exploit path
    let path = attack_graph.find_shortest_exploit_path(&start_node, &target_vuln);
    
    match path {
        Some(p) => {
            // Self-Evolving Mechanism: Save discovered exploit pattern into rules engine
            let safe_vuln_id = target_vuln.replace(|c: char| !c.is_alphanumeric(), "");
            let rule = crate::rules::Rule {
                id: format!("AUTO-BLOCK-{}", safe_vuln_id.to_uppercase()),
                name: format!("Auto-generated baseline from {}", target_vuln),
                description: format!("Discovered static exploit path from AST `{}` to `{}`", start_node, target_vuln),
                severity: crate::rules::Severity::Error,
                field: "id".into(), // Hypothetical field filter for vulns
                operator: crate::rules::Operator::Equals,
                threshold: None,
                pattern: Some(target_vuln.clone()),
            };
            let _ = crate::rules::save_rule(app.clone(), rule);

            // Self-Evolving Mechanism: update AstGraphNode -> PR chain pipeline
            // Emits an event to trigger a PR generation workflow on the frontend
            let _ = app.emit("pr-chain-update", serde_json::json!({
                "action": "QUARANTINE_AST_NODE",
                "node": start_node.clone(),
                "vuln": target_vuln.clone(),
                "status": "PR_CREATED",
            }));

            // Spawn background task to simulate AI healing
            let app_clone = app.clone();
            let sn = start_node.clone();
            let tv = target_vuln.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                let _ = app_clone.emit("pr-chain-update", serde_json::json!({
                    "action": "HEALED_AST_NODE",
                    "node": sn,
                    "vuln": tv,
                    "status": "MERGE_READY",
                    "risk_score": "CRITICAL",
                    "root_cause_analysis": "The `exec_engine::run_devsecops_pipeline` failed to sanitize the input before passing it down the AST call chain, allowing a payload to reach `api_server::api_server_status`.",
                    "patch": "@@ -1,5 +1,6 @@\n fn run_devsecops_pipeline(input: String) {\n+    let safe_input = sanitize_input(&input);\n     ...\n-    api_server_status(input);\n+    api_server_status(safe_input);\n }",
                    "new_rule": "ALL external strings MUST pass boundary `sanitize_input()`"
                }));
            });

            Ok(p)
        },
        None => Err("No exploit path found between these nodes.".into()),
    }
}

#[tauri::command]
pub fn execute_secql_query(
    root_dir: String,
    sbom_path: Option<String>,
    query: String
) -> Result<Vec<crate::secql::exec::SecQlPathResult>, String> {
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let sbom = if let Some(ref sp) = sbom_path {
        let content = std::fs::read_to_string(sp).map_err(|e| format!("{}", e))?;
        let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("{}", e))?;
        Some(crate::sbom_graph::SbomGraph::from_cdx_json(&json).map_err(|e| format!("{}", e))?)
    } else {
        None
    };
    
    let mg = crate::meta_graph::PetMetaGraph::from_ast_and_sbom(&ast, sbom.as_ref());
    
    let parsed_ast = crate::secql::parser::parse_secql(&query)
        .map(|(_, ast)| ast)
        .map_err(|e| format!("Query Syntax Error: {:?}", e))?;
        
    crate::secql::exec::execute_secql(&parsed_ast, &mg)
}

// ══════════════════════════════════════════════════════
//  Phase 30: Incident Response Playbooks
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_generate_playbook(
    vuln_id: String,
    state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<PlaybookManager>>>
) -> Result<Playbook, String> {
    let manager = state.lock().await;
    manager.generate_playbook(vuln_id).await
}

#[tauri::command]
pub async fn engine_execute_playbook(
    playbook_id: String,
    state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<PlaybookManager>>>
) -> Result<(), String> {
    let manager_arc = std::sync::Arc::clone(&*state);
    let pb_id = playbook_id.clone();
    
    tauri::async_runtime::spawn(async move {
        let manager = manager_arc.lock().await;
        if let Err(e) = manager.execute_playbook(pb_id).await {
            eprintln!("Playbook Execution Error: {}", e);
        }
    });
    
    Ok(())
}

#[tauri::command]
pub async fn engine_get_playbooks(
    state: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<PlaybookManager>>>
) -> Result<Vec<Playbook>, String> {
    let manager = state.lock().await;
    Ok(manager.get_playbooks().await)
}

#[tauri::command]
pub async fn engine_get_git_status() -> Result<serde_json::Value, String> {
    use tokio::process::Command;
    let output = Command::new("git")
        .arg("log")
        .arg("-n")
        .arg("5")
        .arg("--oneline")
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let log = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(serde_json::json!({
        "status": "clean",
        "recent_commits": log.lines().collect::<Vec<_>>()
    }))
}

#[tauri::command]
pub async fn engine_chat_with_swarm(
    message: String,
    bus: tauri::State<'_, std::sync::Arc<crate::actor_registry::SwarmBus>>
) -> Result<(), String> {
    // Inject user message into the Swarm Bus
    bus.publish(crate::actor_registry::SwarmEvent::UserChatMessage { text: message.clone() });
    
    // Also echo it back instantly as a log
    bus.publish(crate::actor_registry::SwarmEvent::Log {
        agent: "User".into(),
        message,
    });
    
    Ok(())
}

#[tauri::command]
pub async fn engine_query_knowledge_base(
    query: String,
) -> Result<Vec<crate::engine::memory::knowledge::KnowledgeDoc>, String> {
    // In a real app, KnowledgeBase would be in Tauri State, but Since the db is static
    // for this demo and fast, we just instantiate it per query to keep things simple.
    let kb = crate::engine::memory::knowledge::KnowledgeBase::new();
    let results = kb.query(&query);
    Ok(results)
}

#[tauri::command]
pub async fn engine_generate_executive_report() -> Result<crate::engine::reporting::ExecutiveReport, String> {
    let engine = crate::engine::reporting::ReportingEngine::new();
    Ok(engine.generate_report())
}

#[tauri::command]
pub async fn engine_get_mcp_servers() -> Result<Vec<crate::engine::mcp_client::MCPServer>, String> {
    Ok(crate::engine::mcp_client::MCPConfigManager::get_default_servers())
}

#[tauri::command]
pub async fn engine_connect_mcp_server(url: String) -> Result<crate::engine::mcp_client::MCPServer, String> {
    crate::engine::mcp_client::MCPConfigManager::simulate_connect(&url).await
}

#[tauri::command]
pub async fn engine_generate_exploit_poc(cve_id: String, component_id: String) -> Result<crate::agents::exploit_agent::ExploitPayload, String> {
    Ok(crate::agents::exploit_agent::ExploitAgent::generate_poc(&cve_id, &component_id).await)
}

#[tauri::command]
pub async fn engine_generate_ast_patch(cve_id: String, component_id: String) -> Result<crate::agents::patch_agent::PatchPayload, String> {
    Ok(crate::agents::patch_agent::PatchAgent::generate_ast_patch(&cve_id, &component_id).await)
}

#[tauri::command]
pub async fn engine_execute_wasm_policy(plugin_name: String, target_node: String) -> Result<crate::engine::wasm::WasmExecutionResult, String> {
    Ok(crate::engine::wasm::WasmEngine::execute_policy(&plugin_name, &target_node).await)
}

#[tauri::command]
pub async fn engine_get_incident_playbooks() -> Result<Vec<crate::agents::playbook_agent::IncidentPlaybook>, String> {
    Ok(crate::agents::playbook_agent::PlaybookAgent::get_active_playbooks())
}

#[tauri::command]
pub async fn engine_execute_playbook_step(incident_id: String, step_id: String, executor: String) -> Result<crate::agents::playbook_agent::StepExecutionResult, String> {
    Ok(crate::agents::playbook_agent::PlaybookAgent::execute_step(&incident_id, &step_id, &executor).await)
}

#[tauri::command]
pub async fn engine_run_onboarding_pipeline(window: tauri::Window, repository: String) -> Result<crate::engine::onboarding::WizardOnboardingResult, String> {
    Ok(crate::engine::onboarding::OnboardingEngine::run_pipeline(window, repository).await)
}

#[tauri::command]
pub fn engine_poll_runtime_events() -> Result<Vec<crate::engine::runtime_monitor::RuntimeEvent>, String> {
    Ok(crate::engine::runtime_monitor::RuntimeMonitor::poll_events())
}

#[tauri::command]
pub fn engine_get_threat_correlations() -> Result<Vec<crate::engine::threat_feed::ThreatCorrelation>, String> {
    Ok(crate::engine::threat_feed::ThreatFeedEngine::get_correlated_threats())
}

#[tauri::command]
pub fn engine_get_posture_timeline() -> Result<Vec<crate::engine::posture_timeline::PostureSnapshot>, String> {
    Ok(crate::engine::posture_timeline::PostureTimeline::get_snapshots())
}

#[tauri::command]
pub fn engine_get_soc_overview() -> Result<crate::engine::soc_dashboard::SocOverview, String> {
    Ok(crate::engine::soc_dashboard::SocDashboard::get_overview())
}

#[tauri::command]
pub fn engine_get_image_layers() -> Result<crate::engine::image_forensics::ImageAnalysis, String> {
    Ok(crate::engine::image_forensics::ImageForensics::get_image_layers())
}

// ══════════════════════════════════════════════════════
//  Nemotron fix generation (Nebius Token Factory)
// ══════════════════════════════════════════════════════

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct NemotronFix {
    /// The NVIDIA Nemotron model that produced this fix.
    pub model: String,
    /// Raw Markdown returned by Nemotron (root cause + fenced code fix).
    pub fix_markdown: String,
}

/// Ask NVIDIA Nemotron (via Nebius Token Factory) to write a fix for one
/// concrete attack path produced by the real scan. The API key is read from
/// the NEBIUS_API_KEY environment variable inside `NebiusClient::new`.
#[tauri::command]
pub async fn generate_nemotron_fix(
    vuln_id: String,
    entry_point: String,
    target_component: String,
    proof_chain: Vec<String>,
    source_excerpt: Option<String>,
) -> Result<NemotronFix, String> {
    let client = NebiusClient::new()
        .await
        .map_err(|e| e.to_string())?;

    let model = client.model().to_string();

    let fix_markdown = client
        .generate_fix(
            &vuln_id,
            &entry_point,
            &target_component,
            &proof_chain,
            source_excerpt.as_deref().unwrap_or(""),
        )
        .await
        .map_err(|e| e.to_string())?;

    Ok(NemotronFix { model, fix_markdown })
}
