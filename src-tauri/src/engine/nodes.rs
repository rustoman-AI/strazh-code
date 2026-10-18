use crate::engine::artifact::{ArtifactKind, ArtifactRef};
use crate::engine::context::{EngineEvent, ExecutionContext};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use thiserror::Error;

// ══════════════════════════════════════════════════════
//  ExecutionError
// ══════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Cycle detected in execution graph")]
    CycleDetected,
    #[error("Missing artifact: {0}")]
    MissingArtifact(String),
    #[error("Command failed with exit code {0}: {1}")]
    CommandFailed(i32, String),
    #[error("Command not found: {0}")]
    CommandNotFound(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Graph validation failed: {0}")]
    ValidationFailed(String),
    #[error("Multiple validation errors:\n{0}")]
    MultipleErrors(String),
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),
}

impl ExecutionError {
    /// Returns true if the error is transient and the operation should be retried.
    /// CommandFailed and Io are retryable (external process issues).
    /// MissingArtifact, TypeMismatch, CommandNotFound etc. are stable errors.
    pub fn is_retryable(&self) -> bool {
        matches!(self, ExecutionError::CommandFailed(_, _) | ExecutionError::Io(_))
    }
}

impl Serialize for ExecutionError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

// ══════════════════════════════════════════════════════
//  ExecutableNode trait
// ══════════════════════════════════════════════════════

pub trait ExecutableNode: Send + Sync {
    /// Unique node identifier
    fn id(&self) -> &str;

    /// Human-readable label
    fn label(&self) -> &str;

    /// Node type name
    fn node_type(&self) -> &str;

    /// Required input artifacts
    fn inputs(&self) -> Vec<ArtifactRef>;

    /// Produced output artifacts
    fn outputs(&self) -> Vec<ArtifactRef>;

    /// Phase 20: Whether this node requires manual human approval to execute
    fn requires_approval(&self) -> bool { false }

    /// Execute the node
    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>>;
}

// ══════════════════════════════════════════════════════
//  Node descriptor for frontend
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeDescriptor {
    pub node_type: String,
    pub label: String,
    pub icon: String,
    pub input_kinds: Vec<String>,
    pub output_kinds: Vec<String>,
    pub description: String,
}

pub fn available_node_types() -> Vec<NodeDescriptor> {
    vec![
        NodeDescriptor {
            node_type: "cdxgen_scan".into(), label: "CdxGen Scan".into(), icon: "🔬".into(),
            input_kinds: vec!["source-dir".into()], output_kinds: vec!["sbom".into()],
            description: "Scan source directory with cdxgen to generate SBOM".into(),
        },
        NodeDescriptor {
            node_type: "validate".into(), label: "Validate BOM".into(), icon: "✅".into(),
            input_kinds: vec!["sbom".into()], output_kinds: vec!["validated-sbom".into()],
            description: "Validate CycloneDX BOM against schema".into(),
        },
        NodeDescriptor {
            node_type: "merge".into(), label: "Merge BOMs".into(), icon: "🌳".into(),
            input_kinds: vec!["sbom".into(), "sbom".into()], output_kinds: vec!["merged-sbom".into()],
            description: "Merge multiple BOMs into a single BOM".into(),
        },
        NodeDescriptor {
            node_type: "nist_ssdf".into(), label: "NIST Check".into(), icon: "🏛️".into(),
            input_kinds: vec!["sbom".into()], output_kinds: vec!["compliance-report".into()],
            description: "Check BOM against NIST compliance rules".into(),
        },
        NodeDescriptor {
            node_type: "diff".into(), label: "Diff BOMs".into(), icon: "⇄".into(),
            input_kinds: vec!["sbom".into(), "sbom".into()], output_kinds: vec!["diff-report".into()],
            description: "Compare two BOMs and generate diff report".into(),
        },
        NodeDescriptor {
            node_type: "sign".into(), label: "Sign BOM".into(), icon: "🔏".into(),
            input_kinds: vec!["validated-sbom".into()], output_kinds: vec!["signed-sbom".into()],
            description: "Sign a validated BOM (placeholder)".into(),
        },
        NodeDescriptor {
            node_type: "sarif_export".into(), label: "SARIF Export".into(), icon: "📊".into(),
            input_kinds: vec!["compliance-report".into()], output_kinds: vec!["sarif-report".into()],
            description: "Convert compliance report to SARIF 2.1.0 for CI/CD integration".into(),
        },
    ]
}

// ══════════════════════════════════════════════════════
//  Concrete Node: CycloneDxValidateNode
// ══════════════════════════════════════════════════════

pub struct CycloneDxValidateNode {
    pub id: String,
    pub input: ArtifactRef,
    pub output: ArtifactRef,
    pub expects_approval: bool,
}

impl ExecutableNode for CycloneDxValidateNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "Validate BOM" }
    fn node_type(&self) -> &str { "validate" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let input_path = ctx.artifact_store.get(&self.input)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input.id.clone()))?;

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("Validating: {}", input_path.display()),
            });

            let output = tokio::process::Command::new("cyclonedx")
                .args(["validate", "--input-file"])
                .arg(&input_path)
                .output()
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ExecutionError::CommandNotFound("cyclonedx".into())
                    } else {
                        ExecutionError::Io(e)
                    }
                })?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("stdout: {}", stdout.trim()),
            });

            if !output.status.success() {
                return Err(ExecutionError::CommandFailed(
                    output.status.code().unwrap_or(-1),
                    stderr.to_string(),
                ));
            }

            // Validated SBOM = same file, promoted type
            let stored = ctx.artifact_store.put(&self.output, &input_path)?;
            let hash = ctx.artifact_store.hash(&self.output);
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash,
            });

            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════
//  Concrete Node: CycloneDxMergeNode
// ══════════════════════════════════════════════════════

pub struct CycloneDxMergeNode {
    pub id: String,
    pub inputs: Vec<ArtifactRef>,
    pub output: ArtifactRef,
    pub expects_approval: bool,
}

impl ExecutableNode for CycloneDxMergeNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "Merge BOMs" }
    fn node_type(&self) -> &str { "merge" }
    fn inputs(&self) -> Vec<ArtifactRef> { self.inputs.clone() }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let mut args = vec!["merge".to_string(), "--output-file".to_string()];
            let output_path = ctx.workspace.join(format!("{}.json", self.output.id));
            args.push(output_path.display().to_string());

            for input in &self.inputs {
                let path = ctx.artifact_store.get(input)
                    .ok_or_else(|| ExecutionError::MissingArtifact(input.id.clone()))?;
                args.push("--input-file".to_string());
                args.push(path.display().to_string());
            }

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("Merging {} BOMs", self.inputs.len()),
            });

            let output = tokio::process::Command::new("cyclonedx")
                .args(&args)
                .output()
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ExecutionError::CommandNotFound("cyclonedx".into())
                    } else {
                        ExecutionError::Io(e)
                    }
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ExecutionError::CommandFailed(
                    output.status.code().unwrap_or(-1), stderr.to_string(),
                ));
            }

            let stored = ctx.artifact_store.put(&self.output, &output_path)?;
            let hash = ctx.artifact_store.hash(&self.output);
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash,
            });

            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════
//  Concrete Node: CdxgenScanNode
// ══════════════════════════════════════════════════════

pub struct CdxgenScanNode {
    pub id: String,
    pub input: ArtifactRef,
    pub output: ArtifactRef,
    pub cdxgen_path: String,
    pub expects_approval: bool,
}

impl ExecutableNode for CdxgenScanNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "CdxGen Scan" }
    fn node_type(&self) -> &str { "cdxgen_scan" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let src_dir = ctx.artifact_store.get(&self.input)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input.id.clone()))?;

            let output_path = ctx.workspace.join(format!("{}.json", self.output.id));

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("Scanning: {}", src_dir.display()),
            });

            let output = tokio::process::Command::new(&self.cdxgen_path)
                .args(["-o"])
                .arg(&output_path)
                .arg(&src_dir)
                .output()
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ExecutionError::CommandNotFound(self.cdxgen_path.clone())
                    } else {
                        ExecutionError::Io(e)
                    }
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ExecutionError::CommandFailed(
                    output.status.code().unwrap_or(-1), stderr.to_string(),
                ));
            }

            let stored = ctx.artifact_store.put(&self.output, &output_path)?;
            let hash = ctx.artifact_store.hash(&self.output);
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash,
            });

            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════
//  Concrete Node: FstecComplianceNode
// ══════════════════════════════════════════════════════

pub struct FstecComplianceNode {
    pub id: String,
    pub input: ArtifactRef,
    pub output: ArtifactRef,
    /// If true, return Err when compliance checks fail; if false, just warn
    pub fail_on_violation: bool,
    pub expects_approval: bool,
}

impl ExecutableNode for FstecComplianceNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "NIST Compliance" }
    fn node_type(&self) -> &str { "nist_ssdf" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let input_path = ctx.artifact_store.get(&self.input)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input.id.clone()))?;

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: "Running NIST compliance checks...".into(),
            });

            // Read BOM and perform compliance checks
            let content = tokio::fs::read_to_string(&input_path).await?;
            let bom: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| ExecutionError::CommandFailed(-1, format!("Invalid JSON: {}", e)))?;

            let mut checks: Vec<serde_json::Value> = vec![];
            let mut pass_count = 0;
            let mut fail_count = 0;

            // Check 1: BOM has metadata
            let has_metadata = bom.get("metadata").is_some();
            if has_metadata { pass_count += 1; } else { fail_count += 1; }
            checks.push(serde_json::json!({
                "check": "Metadata присутствует", "status": if has_metadata { "PASS" } else { "FAIL" },
                "requirement": "NIST п.4.1"
            }));

            // Check 2: All components have licenses
            let components = bom.get("components").and_then(|c| c.as_array());
            let total = components.map(|c| c.len()).unwrap_or(0);
            let with_license = components.map(|cs| cs.iter().filter(|c| {
                c.get("licenses").and_then(|l| l.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
            }).count()).unwrap_or(0);
            let lic_pct = if total > 0 { (with_license as f64 / total as f64 * 100.0) as u32 } else { 0 };
            let lic_pass = lic_pct >= 80;
            if lic_pass { pass_count += 1; } else { fail_count += 1; }
            checks.push(serde_json::json!({
                "check": "Лицензии компонентов", "status": if lic_pass { "PASS" } else { "FAIL" },
                "detail": format!("{}/{} ({}%)", with_license, total, lic_pct),
                "requirement": "NIST п.5.2"
            }));

            // Check 3: BOM serial number
            let has_serial = bom.get("serialNumber").is_some();
            if has_serial { pass_count += 1; } else { fail_count += 1; }
            checks.push(serde_json::json!({
                "check": "Серийный номер BOM", "status": if has_serial { "PASS" } else { "FAIL" },
                "requirement": "NIST п.3.1"
            }));

            // Check 4: Component supplier info
            let with_supplier = components.map(|cs| cs.iter().filter(|c| {
                c.get("supplier").is_some() || c.get("publisher").is_some()
            }).count()).unwrap_or(0);
            let sup_pct = if total > 0 { (with_supplier as f64 / total as f64 * 100.0) as u32 } else { 0 };
            let sup_pass = sup_pct >= 50;
            if sup_pass { pass_count += 1; } else { fail_count += 1; }
            checks.push(serde_json::json!({
                "check": "Поставщик/издатель", "status": if sup_pass { "PASS" } else { "FAIL" },
                "detail": format!("{}/{} ({}%)", with_supplier, total, sup_pct),
                "requirement": "NIST п.5.4"
            }));

            let report = serde_json::json!({
                "type": "nist_ssdf-compliance-report",
                "timestamp": chrono_now(),
                "input": input_path.display().to_string(),
                "summary": {
                    "pass": pass_count, "fail": fail_count,
                    "total": pass_count + fail_count,
                    "score": format!("{:.0}%", pass_count as f64 / (pass_count + fail_count) as f64 * 100.0),
                },
                "checks": checks,
            });

            let output_path = ctx.workspace.join(format!("{}.json", self.output.id));
            tokio::fs::write(&output_path, serde_json::to_string_pretty(&report).unwrap()).await?;

            let stored = ctx.artifact_store.put(&self.output, &output_path)?;
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash: ctx.artifact_store.hash(&self.output),
            });

            if fail_count > 0 {
                ctx.event_bus.emit(EngineEvent::NodeLog {
                    node_id: self.id.clone(),
                    line: format!("⚠️ {} checks failed", fail_count),
                });

                if self.fail_on_violation {
                    return Err(ExecutionError::ComplianceViolation(
                        format!("{} of {} NIST checks failed (score: {})",
                            fail_count, pass_count + fail_count,
                            format!("{:.0}%", pass_count as f64 / (pass_count + fail_count) as f64 * 100.0))
                    ));
                }
            }

            Ok(())
        })
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

// ══════════════════════════════════════════════════════
//  Concrete Node: DiffNode
// ══════════════════════════════════════════════════════

pub struct DiffNode {
    pub id: String,
    pub input_a: ArtifactRef,
    pub input_b: ArtifactRef,
    pub output: ArtifactRef,
    pub expects_approval: bool,
}

impl ExecutableNode for DiffNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "Diff BOMs" }
    fn node_type(&self) -> &str { "diff" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input_a.clone(), self.input_b.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let path_a = ctx.artifact_store.get(&self.input_a)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input_a.id.clone()))?;
            let path_b = ctx.artifact_store.get(&self.input_b)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input_b.id.clone()))?;

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("Diffing: {} vs {}", path_a.display(), path_b.display()),
            });

            let output_path = ctx.workspace.join(format!("{}.json", self.output.id));

            let output = tokio::process::Command::new("cyclonedx")
                .args(["diff", "--input-file"])
                .arg(&path_a)
                .arg("--input-file")
                .arg(&path_b)
                .arg("--output-file")
                .arg(&output_path)
                .output()
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ExecutionError::CommandNotFound("cyclonedx".into())
                    } else {
                        ExecutionError::Io(e)
                    }
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ExecutionError::CommandFailed(
                    output.status.code().unwrap_or(-1), stderr.to_string(),
                ));
            }

            let stored = ctx.artifact_store.put(&self.output, &output_path)?;
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash: ctx.artifact_store.hash(&self.output),
            });

            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════
//  Concrete Node: SignNode (placeholder)
// ══════════════════════════════════════════════════════

pub struct SignNode {
    pub id: String,
    pub input: ArtifactRef,
    pub output: ArtifactRef,
    pub expects_approval: bool,
}

impl ExecutableNode for SignNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "Sign BOM" }
    fn node_type(&self) -> &str { "sign" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let input_path = ctx.artifact_store.get(&self.input)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input.id.clone()))?;

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: "Signing BOM (placeholder — copying as-is)".into(),
            });

            // Placeholder: just copy the file
            let stored = ctx.artifact_store.put(&self.output, &input_path)?;
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash: ctx.artifact_store.hash(&self.output),
            });

            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════
//  Concrete Node: SarifExportNode
// ══════════════════════════════════════════════════════

pub struct SarifExportNode {
    pub id: String,
    pub input: ArtifactRef,
    pub output: ArtifactRef,
    pub expects_approval: bool,
}

impl ExecutableNode for SarifExportNode {
    fn id(&self) -> &str { &self.id }
    fn label(&self) -> &str { "SARIF Export" }
    fn node_type(&self) -> &str { "sarif_export" }
    fn inputs(&self) -> Vec<ArtifactRef> { vec![self.input.clone()] }
    fn outputs(&self) -> Vec<ArtifactRef> { vec![self.output.clone()] }
    fn requires_approval(&self) -> bool { self.expects_approval }

    fn execute<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            let input_path = ctx.artifact_store.get(&self.input)
                .ok_or_else(|| ExecutionError::MissingArtifact(self.input.id.clone()))?;

            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("Converting to SARIF 2.1.0: {}", input_path.display()),
            });

            // Read compliance report
            let content = tokio::fs::read_to_string(&input_path).await?;
            let report: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| ExecutionError::CommandFailed(-1, format!("Invalid JSON: {}", e)))?;

            // Convert to SARIF 2.1.0
            let sarif = compliance_to_sarif(&report);

            let output_path = ctx.workspace.join(format!("{}.sarif.json", self.output.id));
            tokio::fs::write(&output_path, serde_json::to_string_pretty(&sarif).unwrap()).await?;

            let stored = ctx.artifact_store.put(&self.output, &output_path)?;
            ctx.event_bus.emit(EngineEvent::ArtifactStored {
                artifact_id: self.output.id.clone(),
                path: stored.display().to_string(),
                hash: ctx.artifact_store.hash(&self.output),
            });

            // Log summary
            let results = sarif["runs"][0]["results"].as_array();
            let total = results.map(|r| r.len()).unwrap_or(0);
            let errors = results.map(|r| r.iter().filter(|v| v["level"] == "error").count()).unwrap_or(0);
            
            ctx.event_bus.emit(EngineEvent::NodeLog {
                node_id: self.id.clone(),
                line: format!("✅ SARIF generated: {} results ({} errors)", total, errors),
            });

            Ok(())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    Idle,
    Running,
    Done,
    Passed,
    Failed,
    Skipped,
}

/// Convert a NIST compliance-report JSON to SARIF 2.1.0 format
pub fn compliance_to_sarif(report: &serde_json::Value) -> serde_json::Value {
    let checks = report["checks"].as_array();

    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut results: Vec<serde_json::Value> = Vec::new();

    if let Some(checks) = checks {
        for (i, check) in checks.iter().enumerate() {
            let check_name = check["check"].as_str().unwrap_or("Unknown check");
            let status = check["status"].as_str().unwrap_or("UNKNOWN");
            let requirement = check["requirement"].as_str().unwrap_or("");
            let detail = check["detail"].as_str().unwrap_or("");

            let rule_id = if requirement.is_empty() {
                format!("FSTEC-{:03}", i + 1)
            } else {
                requirement.replace(' ', "-")
            };

            let level = match status {
                "FAIL" => "error",
                "WARN" | "WARNING" => "warning",
                "PASS" => "note",
                _ => "none",
            };

            // Rule descriptor
            rules.push(serde_json::json!({
                "id": rule_id,
                "name": check_name,
                "shortDescription": { "text": check_name },
                "fullDescription": {
                    "text": format!("{} ({})", check_name, requirement)
                },
                "defaultConfiguration": {
                    "level": if status == "FAIL" { "error" } else { "note" }
                }
            }));

            // Result
            let mut message = format!("{}: {}", check_name, status);
            if !detail.is_empty() {
                message = format!("{} — {}", message, detail);
            }

            results.push(serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report["input"].as_str().unwrap_or("unknown"),
                            "uriBaseId": "SRCROOT"
                        }
                    }
                }]
            }));
        }
    }

    // Summary from report
    let summary = &report["summary"];

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CycloneDX-FSTEC-Checker",
                    "version": "1.0.0",
                    "informationUri": "https://cyclonedx.org",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": summary["fail"].as_u64().unwrap_or(0) == 0,
                "toolExecutionNotifications": []
            }],
            "properties": {
                "summary": {
                    "pass": summary["pass"],
                    "fail": summary["fail"],
                    "total": summary["total"],
                    "score": summary["score"]
                }
            }
        }]
    })
}
