use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::Manager;

// ══════════════════════════════════════════════════════
//  Validation Profiles — inspired by Tracee pkg/policy/
//  Profiles: dev, staging, prod, NIST, NTIA, CRA
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidationProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ProfileCategory,
    pub rules: Vec<ProfileRule>,
    pub fail_on_violation: bool,
    pub builtin: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ProfileCategory {
    Development,
    Staging,
    Production,
    Compliance,
    Custom,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileRule {
    pub id: String,
    pub field: String,
    pub operator: String,       // exists, not_empty, min_percent, min_count, equals, regex
    pub threshold: Option<f64>,
    pub pattern: Option<String>,
    pub severity: String,       // error, warning, info
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileRuleResult {
    pub rule_id: String,
    pub passed: bool,
    pub severity: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileEvaluation {
    pub profile_id: String,
    pub profile_name: String,
    pub category: ProfileCategory,
    pub total_rules: usize,
    pub passed: usize,
    pub failed: usize,
    pub score: f64,
    pub verdict: String,    // PASS, FAIL, WARNING
    pub results: Vec<ProfileRuleResult>,
}

// ══════════════════════════════════════════════════════
//  Built-in Profile Templates
// ══════════════════════════════════════════════════════

fn profile_dev() -> ValidationProfile {
    ValidationProfile {
        id: "dev".into(),
        name: "Development".into(),
        description: "Minimal checks for development builds".into(),
        category: ProfileCategory::Development,
        fail_on_violation: false,
        builtin: true,
        rules: vec![
            ProfileRule { id: "DEV-001".into(), field: "bomFormat".into(), operator: "exists".into(), threshold: None, pattern: None, severity: "warning".into(), enabled: true },
            ProfileRule { id: "DEV-002".into(), field: "components".into(), operator: "min_count".into(), threshold: Some(1.0), pattern: None, severity: "warning".into(), enabled: true },
        ],
    }
}

fn profile_staging() -> ValidationProfile {
    ValidationProfile {
        id: "staging".into(),
        name: "Staging".into(),
        description: "Moderate checks for staging/QA builds".into(),
        category: ProfileCategory::Staging,
        fail_on_violation: false,
        builtin: true,
        rules: vec![
            ProfileRule { id: "STG-001".into(), field: "bomFormat".into(), operator: "equals".into(), threshold: None, pattern: Some("CycloneDX".into()), severity: "error".into(), enabled: true },
            ProfileRule { id: "STG-002".into(), field: "metadata".into(), operator: "exists".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "STG-003".into(), field: "components".into(), operator: "min_count".into(), threshold: Some(1.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "STG-004".into(), field: "components[*].licenses".into(), operator: "min_percent".into(), threshold: Some(50.0), pattern: None, severity: "warning".into(), enabled: true },
        ],
    }
}

fn profile_prod() -> ValidationProfile {
    ValidationProfile {
        id: "prod".into(),
        name: "Production".into(),
        description: "Strict checks for production releases".into(),
        category: ProfileCategory::Production,
        fail_on_violation: true,
        builtin: true,
        rules: vec![
            ProfileRule { id: "PROD-001".into(), field: "bomFormat".into(), operator: "equals".into(), threshold: None, pattern: Some("CycloneDX".into()), severity: "error".into(), enabled: true },
            ProfileRule { id: "PROD-002".into(), field: "serialNumber".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "PROD-003".into(), field: "metadata".into(), operator: "exists".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "PROD-004".into(), field: "components".into(), operator: "min_count".into(), threshold: Some(1.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "PROD-005".into(), field: "components[*].licenses".into(), operator: "min_percent".into(), threshold: Some(80.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "PROD-006".into(), field: "components[*].supplier".into(), operator: "min_percent".into(), threshold: Some(50.0), pattern: None, severity: "warning".into(), enabled: true },
        ],
    }
}

fn profile_nist_ssdf() -> ValidationProfile {
    ValidationProfile {
        id: "nist_ssdf".into(),
        name: "NIST".into(),
        description: "NIST compliance — все обязательные поля для сертификации".into(),
        category: ProfileCategory::Compliance,
        fail_on_violation: true,
        builtin: true,
        rules: vec![
            ProfileRule { id: "FSTEC-001".into(), field: "metadata".into(), operator: "exists".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-002".into(), field: "metadata.component.name".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-003".into(), field: "serialNumber".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-004".into(), field: "components[*].licenses".into(), operator: "min_percent".into(), threshold: Some(80.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-005".into(), field: "components[*].supplier".into(), operator: "min_percent".into(), threshold: Some(50.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-006".into(), field: "components[*].version".into(), operator: "min_percent".into(), threshold: Some(90.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "FSTEC-007".into(), field: "components[*].purl".into(), operator: "min_percent".into(), threshold: Some(70.0), pattern: None, severity: "warning".into(), enabled: true },
        ],
    }
}

fn profile_ntia() -> ValidationProfile {
    ValidationProfile {
        id: "ntia".into(),
        name: "NTIA Minimum Elements".into(),
        description: "NTIA minimum elements for SBOM (US Executive Order 14028)".into(),
        category: ProfileCategory::Compliance,
        fail_on_violation: true,
        builtin: true,
        rules: vec![
            ProfileRule { id: "NTIA-001".into(), field: "metadata.component.name".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "NTIA-002".into(), field: "metadata.component.version".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "NTIA-003".into(), field: "components[*].name".into(), operator: "min_percent".into(), threshold: Some(100.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "NTIA-004".into(), field: "components[*].version".into(), operator: "min_percent".into(), threshold: Some(95.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "NTIA-005".into(), field: "metadata.timestamp".into(), operator: "not_empty".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
        ],
    }
}

fn profile_cra() -> ValidationProfile {
    ValidationProfile {
        id: "cra".into(),
        name: "EU CRA".into(),
        description: "EU Cyber Resilience Act — vulnerability handling requirements".into(),
        category: ProfileCategory::Compliance,
        fail_on_violation: true,
        builtin: true,
        rules: vec![
            ProfileRule { id: "CRA-001".into(), field: "metadata".into(), operator: "exists".into(), threshold: None, pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "CRA-002".into(), field: "components[*].licenses".into(), operator: "min_percent".into(), threshold: Some(90.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "CRA-003".into(), field: "components[*].supplier".into(), operator: "min_percent".into(), threshold: Some(80.0), pattern: None, severity: "error".into(), enabled: true },
            ProfileRule { id: "CRA-004".into(), field: "components[*].purl".into(), operator: "min_percent".into(), threshold: Some(90.0), pattern: None, severity: "error".into(), enabled: true },
        ],
    }
}

fn all_builtin_profiles() -> Vec<ValidationProfile> {
    vec![profile_dev(), profile_staging(), profile_prod(), profile_nist_ssdf(), profile_ntia(), profile_cra()]
}

/// Public accessor for cross_pipeline
pub fn all_builtin_profiles_pub() -> Vec<ValidationProfile> {
    all_builtin_profiles()
}

/// Evaluate rules against SBOM, returns (passed, failed)
pub fn evaluate_rules_against(rules: &[ProfileRule], sbom: &serde_json::Value) -> (usize, usize) {
    let results: Vec<ProfileRuleResult> = rules.iter().map(|r| evaluate_profile_rule(r, sbom)).collect();
    let passed = results.iter().filter(|r| r.passed).count();
    (passed, results.len() - passed)
}

// ══════════════════════════════════════════════════════
//  Rule Evaluation (reuses logic from rules.rs)
// ══════════════════════════════════════════════════════

fn resolve_field(json: &serde_json::Value, path: &str) -> serde_json::Value {
    let clean = path.replace("[*]", "");
    let parts: Vec<&str> = clean.split('.').collect();
    let mut current = json.clone();
    for part in parts {
        if part.is_empty() { continue; }
        current = match current.get(part) {
            Some(v) => v.clone(),
            None => return serde_json::Value::Null,
        };
    }
    current
}

fn count_array_field(json: &serde_json::Value, path: &str) -> (usize, usize) {
    if let Some(idx) = path.find("[*].") {
        let array_path = &path[..idx];
        let field_name = &path[idx + 4..];
        let array = resolve_field(json, array_path);
        if let serde_json::Value::Array(items) = array {
            let total = items.len();
            let with_field = items.iter().filter(|item| {
                let v = resolve_field(item, field_name);
                match &v {
                    serde_json::Value::Null => false,
                    serde_json::Value::Array(a) => !a.is_empty(),
                    serde_json::Value::String(s) => !s.is_empty(),
                    _ => true,
                }
            }).count();
            return (total, with_field);
        }
    }
    (0, 0)
}

fn evaluate_profile_rule(rule: &ProfileRule, sbom: &serde_json::Value) -> ProfileRuleResult {
    if !rule.enabled {
        return ProfileRuleResult {
            rule_id: rule.id.clone(), passed: true, severity: rule.severity.clone(),
            message: "⏭️ Skipped (disabled)".into(),
        };
    }

    let value = resolve_field(sbom, &rule.field);

    let (passed, message) = match rule.operator.as_str() {
        "exists" => {
            let ok = !value.is_null();
            (ok, if ok { format!("✅ '{}' exists", rule.field) } else { format!("❌ '{}' missing", rule.field) })
        }
        "not_empty" => {
            let ok = match &value {
                serde_json::Value::Null => false,
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Array(a) => !a.is_empty(),
                serde_json::Value::Object(o) => !o.is_empty(),
                _ => true,
            };
            (ok, if ok { format!("✅ '{}' not empty", rule.field) } else { format!("❌ '{}' empty", rule.field) })
        }
        "min_percent" => {
            let thr = rule.threshold.unwrap_or(80.0);
            let (total, with) = count_array_field(sbom, &rule.field);
            let pct = if total > 0 { (with as f64 / total as f64) * 100.0 } else { 0.0 };
            let ok = pct >= thr;
            (ok, format!("{} {:.0}% ({}/{}) vs {:.0}%", if ok { "✅" } else { "❌" }, pct, with, total, thr))
        }
        "min_count" => {
            let thr = rule.threshold.unwrap_or(1.0) as usize;
            let count = match &value { serde_json::Value::Array(a) => a.len(), _ => 0 };
            let ok = count >= thr;
            (ok, format!("{} count {} vs ≥{}", if ok { "✅" } else { "❌" }, count, thr))
        }
        "equals" => {
            let pat = rule.pattern.as_deref().unwrap_or("");
            let actual = value.as_str().unwrap_or("");
            let ok = actual == pat;
            (ok, format!("{} '{}' {} '{}'", if ok { "✅" } else { "❌" }, actual, if ok { "==" } else { "!=" }, pat))
        }
        _ => (false, format!("❓ Unknown operator '{}'", rule.operator)),
    };

    ProfileRuleResult { rule_id: rule.id.clone(), passed, severity: rule.severity.clone(), message }
}

// ══════════════════════════════════════════════════════
//  Profiles directory helper
// ══════════════════════════════════════════════════════

fn profiles_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path().app_data_dir().expect("app data dir").join("profiles")
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn list_profiles(app: tauri::AppHandle) -> Result<Vec<ValidationProfile>, String> {
    let mut profiles = all_builtin_profiles();

    // Load custom profiles from YAML
    let dir = profiles_dir(&app);
    if dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(profile) = serde_yaml::from_str::<ValidationProfile>(&content) {
                            profiles.push(profile);
                        }
                    }
                }
            }
        }
    }

    Ok(profiles)
}

#[tauri::command]
pub async fn evaluate_profile(
    app: tauri::AppHandle,
    profile_id: String,
    sbom_path: String,
) -> Result<ProfileEvaluation, String> {
    let profiles = list_profiles(app)?;
    let profile = profiles.iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Profile '{}' not found", profile_id))?;

    let content = tokio::fs::read_to_string(&sbom_path)
        .await
        .map_err(|e| format!("Failed to read SBOM: {}", e))?;
    let sbom: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let results: Vec<ProfileRuleResult> = profile.rules.iter()
        .map(|r| evaluate_profile_rule(r, &sbom))
        .collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let score = if results.is_empty() { 100.0 } else { (passed as f64 / results.len() as f64) * 100.0 };

    let verdict = if failed == 0 {
        "PASS".into()
    } else if profile.fail_on_violation {
        "FAIL".into()
    } else {
        "WARNING".into()
    };

    Ok(ProfileEvaluation {
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        category: profile.category.clone(),
        total_rules: results.len(),
        passed,
        failed,
        score,
        verdict,
        results,
    })
}

#[tauri::command]
pub fn save_profile(app: tauri::AppHandle, profile: ValidationProfile) -> Result<String, String> {
    let dir = profiles_dir(&app);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create dir: {}", e))?;

    let path = dir.join(format!("{}.yaml", profile.id));
    let content = serde_yaml::to_string(&profile).map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, &content).map_err(|e| format!("Write error: {}", e))?;

    Ok(format!("Saved profile '{}' to {}", profile.id, path.display()))
}
