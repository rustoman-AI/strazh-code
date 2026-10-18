use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tauri::Manager;

// ══════════════════════════════════════════════════════
//  Rule — declarative SBOM validation rule (YAML)
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub field: String,        // JSONPath-like: "components[*].licenses", "metadata.component.name"
    pub operator: Operator,
    pub threshold: Option<f64>,
    pub pattern: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    NotEmpty,      // field must not be empty/null
    MinPercent,    // at least threshold% of array items must have field
    Exists,        // field must exist in JSON
    Regex,         // field value must match pattern
    MinCount,      // array must have at least threshold items
    Equals,        // field must equal pattern
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuleResult {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub passed: bool,
    pub message: String,
    pub actual_value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvaluationReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<RuleResult>,
}

// ══════════════════════════════════════════════════════
//  Rule Evaluation Engine
// ══════════════════════════════════════════════════════

fn evaluate_rule(rule: &Rule, sbom: &serde_json::Value) -> RuleResult {
    let base = RuleResult {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity.clone(),
        passed: false,
        message: String::new(),
        actual_value: String::new(),
    };

    // Parse field path: "components[*].licenses" → navigate JSON
    let value = resolve_field(sbom, &rule.field);

    match &rule.operator {
        Operator::Exists => {
            let exists = !value.is_null();
            RuleResult {
                passed: exists,
                message: if exists {
                    format!("✅ Field '{}' exists", rule.field)
                } else {
                    format!("❌ Field '{}' does not exist", rule.field)
                },
                actual_value: format!("{}", exists),
                ..base
            }
        }
        Operator::NotEmpty => {
            let not_empty = match &value {
                serde_json::Value::Null => false,
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Array(a) => !a.is_empty(),
                serde_json::Value::Object(o) => !o.is_empty(),
                _ => true,
            };
            RuleResult {
                passed: not_empty,
                message: if not_empty {
                    format!("✅ Field '{}' is not empty", rule.field)
                } else {
                    format!("❌ Field '{}' is empty or missing", rule.field)
                },
                actual_value: format!("{}", not_empty),
                ..base
            }
        }
        Operator::MinPercent => {
            let threshold = rule.threshold.unwrap_or(80.0);
            // Field like "components[*].licenses" → check % of components with licenses
            let (total, with_field) = count_array_field(sbom, &rule.field);
            let percent = if total > 0 { (with_field as f64 / total as f64) * 100.0 } else { 0.0 };
            let passed = percent >= threshold;
            RuleResult {
                passed,
                message: if passed {
                    format!("✅ {:.0}% ({}/{}) — above {:.0}% threshold", percent, with_field, total, threshold)
                } else {
                    format!("❌ {:.0}% ({}/{}) — below {:.0}% threshold", percent, with_field, total, threshold)
                },
                actual_value: format!("{:.1}%", percent),
                ..base
            }
        }
        Operator::MinCount => {
            let threshold = rule.threshold.unwrap_or(1.0) as usize;
            let count = match &value {
                serde_json::Value::Array(a) => a.len(),
                _ => 0,
            };
            let passed = count >= threshold;
            RuleResult {
                passed,
                message: if passed {
                    format!("✅ Count {} ≥ {}", count, threshold)
                } else {
                    format!("❌ Count {} < {}", count, threshold)
                },
                actual_value: format!("{}", count),
                ..base
            }
        }
        Operator::Equals => {
            let pattern = rule.pattern.as_deref().unwrap_or("");
            let actual = value.as_str().unwrap_or("");
            let passed = actual == pattern;
            RuleResult {
                passed,
                message: if passed {
                    format!("✅ '{}' equals '{}'", rule.field, pattern)
                } else {
                    format!("❌ '{}' = '{}', expected '{}'", rule.field, actual, pattern)
                },
                actual_value: actual.to_string(),
                ..base
            }
        }
        Operator::Regex => {
            let pattern = rule.pattern.as_deref().unwrap_or(".*");
            let actual = value.as_str().unwrap_or("");
            let passed = regex::Regex::new(pattern)
                .map(|re| re.is_match(actual))
                .unwrap_or(false);
            RuleResult {
                passed,
                message: if passed {
                    format!("✅ '{}' matches /{}/", rule.field, pattern)
                } else {
                    format!("❌ '{}' = '{}' does not match /{}/", rule.field, actual, pattern)
                },
                actual_value: actual.to_string(),
                ..base
            }
        }
    }
}

/// Resolve a simple JSON field path like "metadata.component.name" or "components"
fn resolve_field<'a>(json: &'a serde_json::Value, path: &str) -> serde_json::Value {
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

/// Count array items that have a nested field (for MinPercent).
/// Path like "components[*].licenses" → count components with non-null licenses.
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

// ══════════════════════════════════════════════════════
//  Default Rules — built-in NIST rules
// ══════════════════════════════════════════════════════

fn default_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "FSTEC-001".into(),
            name: "SBOM Metadata".into(),
            description: "SBOM must have metadata section".into(),
            severity: Severity::Error,
            field: "metadata".into(),
            operator: Operator::Exists,
            threshold: None,
            pattern: None,
        },
        Rule {
            id: "FSTEC-002".into(),
            name: "Component licenses".into(),
            description: "At least 80% of components must have licenses".into(),
            severity: Severity::Error,
            field: "components[*].licenses".into(),
            operator: Operator::MinPercent,
            threshold: Some(80.0),
            pattern: None,
        },
        Rule {
            id: "FSTEC-003".into(),
            name: "Serial number".into(),
            description: "SBOM must have a serial number".into(),
            severity: Severity::Error,
            field: "serialNumber".into(),
            operator: Operator::NotEmpty,
            threshold: None,
            pattern: None,
        },
        Rule {
            id: "FSTEC-004".into(),
            name: "Component suppliers".into(),
            description: "At least 50% of components must have supplier info".into(),
            severity: Severity::Warning,
            field: "components[*].supplier".into(),
            operator: Operator::MinPercent,
            threshold: Some(50.0),
            pattern: None,
        },
        Rule {
            id: "FSTEC-005".into(),
            name: "Components exist".into(),
            description: "SBOM must contain at least 1 component".into(),
            severity: Severity::Error,
            field: "components".into(),
            operator: Operator::MinCount,
            threshold: Some(1.0),
            pattern: None,
        },
        Rule {
            id: "NTIA-001".into(),
            name: "SBOM version".into(),
            description: "SBOM must specify bomFormat".into(),
            severity: Severity::Info,
            field: "bomFormat".into(),
            operator: Operator::Equals,
            threshold: None,
            pattern: Some("CycloneDX".into()),
        },
    ]
}

// ══════════════════════════════════════════════════════
//  Rules directory helper
// ══════════════════════════════════════════════════════

fn rules_dir(app: &tauri::AppHandle) -> PathBuf {
    let dir = app.path().app_data_dir().expect("app data dir");
    dir.join("rules")
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn load_rules(app: tauri::AppHandle) -> Result<Vec<Rule>, String> {
    let dir = rules_dir(&app);
    let mut rules: Vec<Rule> = default_rules();

    // Load custom YAML rules from rules/ directory
    if dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            match serde_yaml::from_str::<Rule>(&content) {
                                Ok(rule) => rules.push(rule),
                                Err(e) => eprintln!("Failed to parse {}: {}", path.display(), e),
                            }
                        }
                        Err(e) => eprintln!("Failed to read {}: {}", path.display(), e),
                    }
                }
            }
        }
    }

    Ok(rules)
}

#[tauri::command]
pub async fn evaluate_rules(
    app: tauri::AppHandle,
    sbom_path: String,
) -> Result<EvaluationReport, String> {
    let content = tokio::fs::read_to_string(&sbom_path)
        .await
        .map_err(|e| format!("Failed to read SBOM: {}", e))?;

    let sbom: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let rules = load_rules(app)?;

    let results: Vec<RuleResult> = rules.iter()
        .map(|rule| evaluate_rule(rule, &sbom))
        .collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();

    Ok(EvaluationReport {
        total,
        passed,
        failed: total - passed,
        results,
    })
}

#[tauri::command]
pub fn save_rule(app: tauri::AppHandle, rule: Rule) -> Result<String, String> {
    let dir = rules_dir(&app);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create rules dir: {}", e))?;

    let path = dir.join(format!("{}.yaml", rule.id.to_lowercase()));
    let content = serde_yaml::to_string(&rule)
        .map_err(|e| format!("Failed to serialize rule: {}", e))?;

    std::fs::write(&path, &content)
        .map_err(|e| format!("Failed to write rule: {}", e))?;

    Ok(format!("Saved rule '{}' to {}", rule.id, path.display()))
}
