use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::Manager;

// ══════════════════════════════════════════════════════
//  DataStore Registry — inspired by Tracee pkg/datastores/
// ══════════════════════════════════════════════════════

/// Known vulnerability entry (offline cache for NVD/OSV)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VulnEntry {
    pub id: String,           // CVE-2024-1234
    pub severity: String,     // CRITICAL, HIGH, MEDIUM, LOW
    pub score: f64,           // CVSS score
    pub summary: String,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_version: String,
    pub references: Vec<String>,
}

/// SPDX license info
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LicenseEntry {
    pub id: String,           // MIT, Apache-2.0, GPL-3.0-only
    pub name: String,
    pub osi_approved: bool,
    pub fsf_free: bool,
    pub category: String,     // permissive, copyleft, weak-copyleft, proprietary
    pub spdx_url: String,
}

/// Supplier/vendor info for NIST compliance
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SupplierEntry {
    pub name: String,
    pub website: String,
    pub country: String,
    pub trusted: bool,        // in trusted supplier list
    pub contact: String,
}

/// Enrichment result for a single component
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrichmentResult {
    pub component_name: String,
    pub component_version: String,
    pub vulns_found: Vec<VulnEntry>,
    pub license_info: Option<LicenseEntry>,
    pub supplier_info: Option<SupplierEntry>,
}

/// Full enrichment report for an SBOM
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrichmentReport {
    pub total_components: usize,
    pub enriched_components: usize,
    pub total_vulns: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
    pub components: Vec<EnrichmentResult>,
}

// ══════════════════════════════════════════════════════
//  Built-in data (sample — in real system from JSON files)
// ══════════════════════════════════════════════════════

fn builtin_vulndb() -> HashMap<String, Vec<VulnEntry>> {
    let mut db: HashMap<String, Vec<VulnEntry>> = HashMap::new();
    // Sample entries for common packages
    db.insert("log4j-core".into(), vec![
        VulnEntry {
            id: "CVE-2021-44228".into(),
            severity: "CRITICAL".into(),
            score: 10.0,
            summary: "Apache Log4j2 JNDI RCE (Log4Shell)".into(),
            affected_package: "log4j-core".into(),
            affected_versions: "< 2.17.0".into(),
            fixed_version: "2.17.1".into(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".into()],
        },
    ]);
    db.insert("lodash".into(), vec![
        VulnEntry {
            id: "CVE-2021-23337".into(),
            severity: "HIGH".into(),
            score: 7.2,
            summary: "Lodash Command Injection via template".into(),
            affected_package: "lodash".into(),
            affected_versions: "< 4.17.21".into(),
            fixed_version: "4.17.21".into(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".into()],
        },
    ]);
    db.insert("openssl".into(), vec![
        VulnEntry {
            id: "CVE-2022-3602".into(),
            severity: "HIGH".into(),
            score: 7.5,
            summary: "OpenSSL X.509 buffer overread".into(),
            affected_package: "openssl".into(),
            affected_versions: "3.0.0 - 3.0.6".into(),
            fixed_version: "3.0.7".into(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-3602".into()],
        },
    ]);
    db
}

fn builtin_licensedb() -> HashMap<String, LicenseEntry> {
    let mut db = HashMap::new();
    let licenses = vec![
        ("MIT", "MIT License", true, true, "permissive"),
        ("Apache-2.0", "Apache License 2.0", true, true, "permissive"),
        ("GPL-3.0-only", "GNU General Public License v3.0 only", true, true, "copyleft"),
        ("GPL-2.0-only", "GNU General Public License v2.0 only", true, true, "copyleft"),
        ("LGPL-2.1-only", "GNU Lesser General Public License v2.1 only", true, true, "weak-copyleft"),
        ("BSD-2-Clause", "BSD 2-Clause \"Simplified\" License", true, true, "permissive"),
        ("BSD-3-Clause", "BSD 3-Clause \"New\" License", true, true, "permissive"),
        ("ISC", "ISC License", true, true, "permissive"),
        ("MPL-2.0", "Mozilla Public License 2.0", true, true, "weak-copyleft"),
        ("AGPL-3.0-only", "GNU Affero General Public License v3.0", true, true, "copyleft"),
        ("Unlicense", "The Unlicense", true, false, "permissive"),
        ("SSPL-1.0", "Server Side Public License v1", false, false, "proprietary"),
        ("BSL-1.1", "Business Source License 1.1", false, false, "proprietary"),
    ];
    for (id, name, osi, fsf, cat) in licenses {
        db.insert(id.to_string(), LicenseEntry {
            id: id.into(),
            name: name.into(),
            osi_approved: osi,
            fsf_free: fsf,
            category: cat.into(),
            spdx_url: format!("https://spdx.org/licenses/{}.html", id),
        });
    }
    db
}

fn builtin_supplierdb() -> HashMap<String, SupplierEntry> {
    let mut db = HashMap::new();
    let suppliers = vec![
        ("Apache Software Foundation", "https://apache.org", "US", true),
        ("Google LLC", "https://google.com", "US", true),
        ("Microsoft", "https://microsoft.com", "US", true),
        ("Red Hat", "https://redhat.com", "US", true),
        ("Canonical", "https://canonical.com", "UK", true),
        ("SUSE", "https://suse.com", "DE", true),
        ("JetBrains", "https://jetbrains.com", "CZ", true),
        ("Aqua Security", "https://aquasec.com", "IL", true),
    ];
    for (name, web, country, trusted) in suppliers {
        db.insert(name.to_lowercase(), SupplierEntry {
            name: name.into(),
            website: web.into(),
            country: country.into(),
            trusted,
            contact: format!("security@{}", web.replace("https://", "")),
        });
    }
    db
}

// ══════════════════════════════════════════════════════
//  Enrichment Logic
// ══════════════════════════════════════════════════════

fn enrich_component(
    name: &str,
    version: &str,
    license_id: Option<&str>,
    supplier_name: Option<&str>,
    vulndb: &HashMap<String, Vec<VulnEntry>>,
    licensedb: &HashMap<String, LicenseEntry>,
    supplierdb: &HashMap<String, SupplierEntry>,
) -> EnrichmentResult {
    let name_lower = name.to_lowercase();

    // Lookup vulns by package name
    let vulns = vulndb.get(&name_lower)
        .cloned()
        .unwrap_or_default();

    // Lookup license info
    let license_info = license_id
        .and_then(|id| licensedb.get(id).cloned());

    // Lookup supplier info
    let supplier_info = supplier_name
        .and_then(|s| supplierdb.get(&s.to_lowercase()).cloned());

    EnrichmentResult {
        component_name: name.into(),
        component_version: version.into(),
        vulns_found: vulns,
        license_info,
        supplier_info,
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

/// Query vulnerability database for a specific package
#[tauri::command]
pub fn query_vuln(package_name: String) -> Result<Vec<VulnEntry>, String> {
    let db = builtin_vulndb();
    Ok(db.get(&package_name.to_lowercase())
        .cloned()
        .unwrap_or_default())
}

/// Query license database for a specific SPDX ID
#[tauri::command]
pub fn query_license(license_id: String) -> Result<Option<LicenseEntry>, String> {
    let db = builtin_licensedb();
    Ok(db.get(&license_id).cloned())
}

/// Enrich an entire SBOM with vulnerability, license, and supplier data
#[tauri::command]
pub async fn enrich_sbom(sbom_path: String) -> Result<EnrichmentReport, String> {
    let content = tokio::fs::read_to_string(&sbom_path)
        .await
        .map_err(|e| format!("Failed to read SBOM: {}", e))?;

    let sbom: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let vulndb = builtin_vulndb();
    let licensedb = builtin_licensedb();
    let supplierdb = builtin_supplierdb();

    let components = sbom.get("components")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let mut results = Vec::new();
    let mut total_vulns = 0usize;
    let mut critical_vulns = 0usize;
    let mut high_vulns = 0usize;

    for comp in &components {
        let name = comp.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let version = comp.get("version").and_then(|v| v.as_str()).unwrap_or("");

        // Extract license ID from CycloneDX structure
        let license_id = comp.get("licenses")
            .and_then(|l| l.as_array())
            .and_then(|arr| arr.first())
            .and_then(|lic| {
                lic.get("license")
                    .and_then(|l| l.get("id"))
                    .and_then(|id| id.as_str())
                    .or_else(|| lic.get("expression").and_then(|e| e.as_str()))
            });

        // Extract supplier name
        let supplier_name = comp.get("supplier")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str());

        let result = enrich_component(
            name, version, license_id, supplier_name,
            &vulndb, &licensedb, &supplierdb,
        );

        for v in &result.vulns_found {
            total_vulns += 1;
            match v.severity.as_str() {
                "CRITICAL" => critical_vulns += 1,
                "HIGH" => high_vulns += 1,
                _ => {}
            }
        }
        results.push(result);
    }

    let enriched = results.iter()
        .filter(|r| !r.vulns_found.is_empty() || r.license_info.is_some() || r.supplier_info.is_some())
        .count();

    Ok(EnrichmentReport {
        total_components: components.len(),
        enriched_components: enriched,
        total_vulns,
        critical_vulns,
        high_vulns,
        components: results,
    })
}

/// Get DataStore statistics
#[tauri::command]
pub fn datastore_stats() -> Result<serde_json::Value, String> {
    let vulndb = builtin_vulndb();
    let licensedb = builtin_licensedb();
    let supplierdb = builtin_supplierdb();

    let total_vulns: usize = vulndb.values().map(|v| v.len()).sum();

    Ok(serde_json::json!({
        "vulndb": {
            "packages": vulndb.len(),
            "total_vulns": total_vulns,
        },
        "licensedb": {
            "licenses": licensedb.len(),
        },
        "supplierdb": {
            "suppliers": supplierdb.len(),
        }
    }))
}
