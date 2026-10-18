use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

// ══════════════════════════════════════════════════════
//  SBOM Graph — typed model replacing serde_json::Value
//  CycloneDX 1.6 compliant graph structure
// ══════════════════════════════════════════════════════

pub type NodeId = String;

// ─────────────────── Core Entities ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SbomGraph {
    pub bom_ref: Option<String>,
    pub serial_number: Option<String>,
    pub version: u32,
    pub metadata: Option<SbomMetadata>,
    pub components: Vec<Component>,
    pub dependencies: Vec<DependencyEdge>,
    pub vulnerabilities: Vec<Vulnerability>,
    /// Adjacency index: component bom-ref → Vec<dependency bom-ref>
    #[serde(skip)]
    pub adjacency: HashMap<String, Vec<String>>,
    /// Reverse index: component bom-ref → Vec<dependent bom-ref>
    #[serde(skip)]
    pub reverse_adj: HashMap<String, Vec<String>>,
    /// petgraph in-memory DiGraph for accelerated BFS/DFS
    #[serde(skip)]
    pub pet_graph: DiGraph<String, f64>,
    #[serde(skip)]
    pub pet_index: HashMap<String, NodeIndex>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SbomMetadata {
    pub timestamp: Option<String>,
    pub component: Option<MetadataComponent>,
    pub tools: Vec<String>,
    pub authors: Vec<String>,
    pub supplier: Option<Supplier>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetadataComponent {
    pub name: String,
    pub version: Option<String>,
    pub bom_ref: Option<String>,
    pub component_type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Component {
    pub bom_ref: Option<String>,
    pub component_type: String,       // library, framework, application, device, firmware
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub description: Option<String>,
    pub licenses: Vec<LicenseEntry>,
    pub supplier: Option<Supplier>,
    pub hashes: Vec<HashEntry>,
    pub external_references: Vec<ExternalRef>,
    pub scope: Option<String>,        // required, optional, excluded
    pub properties: HashMap<String, String>,
    // Computed fields (populated by build_indices)
    #[serde(skip)]
    pub vuln_count: usize,
    #[serde(skip)]
    pub dep_count: usize,
    #[serde(skip)]
    pub dependents_count: usize,
    #[serde(skip)]
    pub trust_score: f64,             // 0.0-1.0, computed from supplier/license/hash presence
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LicenseEntry {
    pub id: Option<String>,          // SPDX ID
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Supplier {
    pub name: Option<String>,
    pub url: Option<String>,
    pub contact: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HashEntry {
    pub alg: String,                 // SHA-256, SHA-512, MD5
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExternalRef {
    pub ref_type: String,            // vcs, website, issue-tracker, distribution
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DependencyEdge {
    pub from_ref: String,
    pub to_refs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vulnerability {
    pub id: String,                  // CVE-2024-...
    pub source: Option<String>,      // NVD, OSV, GHSA
    pub severity: Option<String>,    // critical, high, medium, low
    pub cvss_score: Option<f64>,
    pub description: Option<String>,
    pub affects: Vec<String>,        // component bom-refs
    pub fixed_version: Option<String>,
    pub published: Option<String>,
    pub url: Option<String>,
}

// ─────────────────── Builder from JSON ───────────────────

impl SbomGraph {
    /// Parse from CycloneDX JSON (serde_json::Value)
    pub fn from_cdx_json(json: &serde_json::Value) -> Result<Self, String> {
        let mut graph = SbomGraph {
            bom_ref: json.get("serialNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
            serial_number: json.get("serialNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
            version: json.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            metadata: parse_metadata(json.get("metadata")),
            components: parse_components(json.get("components")),
            dependencies: parse_dependencies(json.get("dependencies")),
            vulnerabilities: parse_vulnerabilities(json.get("vulnerabilities")),
            adjacency: HashMap::new(),
            reverse_adj: HashMap::new(),
            pet_graph: DiGraph::new(),
            pet_index: HashMap::new(),
        };
        graph.build_indices();
        Ok(graph)
    }

    /// Build adjacency indices, petgraph, and compute stats
    pub fn build_indices(&mut self) {
        self.adjacency.clear();
        self.reverse_adj.clear();
        self.pet_graph = DiGraph::with_capacity(self.components.len() + 128, self.dependencies.len() * 4);
        self.pet_index.clear();

        // Ensure all component nodes exist in petgraph
        for comp in &self.components {
            let bref = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
            if !self.pet_index.contains_key(&bref) {
                let nx = self.pet_graph.add_node(bref.clone());
                self.pet_index.insert(bref, nx);
            }
        }

        // Build adjacency + petgraph edges
        for dep in &self.dependencies {
            self.adjacency.entry(dep.from_ref.clone()).or_default().extend(dep.to_refs.clone());
            // Ensure from_ref node exists
            if !self.pet_index.contains_key(&dep.from_ref) {
                let nx = self.pet_graph.add_node(dep.from_ref.clone());
                self.pet_index.insert(dep.from_ref.clone(), nx);
            }
            for to in &dep.to_refs {
                self.reverse_adj.entry(to.clone()).or_default().push(dep.from_ref.clone());
                // Ensure to node exists
                if !self.pet_index.contains_key(to) {
                    let nx = self.pet_graph.add_node(to.clone());
                    self.pet_index.insert(to.clone(), nx);
                }
                // Add edge in petgraph
                let from_nx = self.pet_index[&dep.from_ref];
                let to_nx = self.pet_index[to];
                self.pet_graph.add_edge(from_nx, to_nx, 1.0);
            }
        }

        // Compute per-component stats
        let vuln_map: HashMap<String, usize> = {
            let mut m = HashMap::new();
            for v in &self.vulnerabilities {
                for a in &v.affects {
                    *m.entry(a.clone()).or_insert(0) += 1;
                }
            }
            m
        };

        for comp in &mut self.components {
            let bref = comp.bom_ref.as_deref().unwrap_or("");
            comp.vuln_count = vuln_map.get(bref).copied().unwrap_or(0);
            comp.dep_count = self.adjacency.get(bref).map(|v| v.len()).unwrap_or(0);
            comp.dependents_count = self.reverse_adj.get(bref).map(|v| v.len()).unwrap_or(0);
            comp.trust_score = compute_trust_score(comp);
        }
    }

    // ─────────────────── Graph Queries ───────────────────

    /// Components without any license
    pub fn unlicensed(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.licenses.is_empty()).collect()
    }

    /// Components without supplier
    pub fn no_supplier(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.supplier.is_none()).collect()
    }

    /// Components with vulnerabilities
    pub fn vulnerable(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.vuln_count > 0).collect()
    }

    /// Components with critical/high vulns
    pub fn critical_vulnerable(&self) -> Vec<(&Component, Vec<&Vulnerability>)> {
        self.components.iter().filter_map(|c| {
            let bref = c.bom_ref.as_deref()?;
            let vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                .filter(|v| v.affects.iter().any(|a| a == bref))
                .filter(|v| matches!(v.severity.as_deref(), Some("critical") | Some("high") | Some("CRITICAL") | Some("HIGH")))
                .collect();
            if vulns.is_empty() { None } else { Some((c, vulns)) }
        }).collect()
    }

    /// Dependency path from component to root (petgraph BFS reverse)
    pub fn path_to_root(&self, bom_ref: &str) -> Vec<String> {
        let Some(&start) = self.pet_index.get(bom_ref) else {
            return vec![bom_ref.to_string()];
        };
        let mut path = vec![bom_ref.to_string()];
        let mut visited = vec![false; self.pet_graph.node_count()];
        visited[start.index()] = true;
        let mut current = start;
        loop {
            // Walk first incoming edge (towards root)
            let parent = self.pet_graph.edges_directed(current, Direction::Incoming)
                .find(|e| !visited[e.source().index()])
                .map(|e| e.source());
            if let Some(p) = parent {
                visited[p.index()] = true;
                path.push(self.pet_graph[p].clone());
                current = p;
            } else {
                break;
            }
        }
        path.reverse();
        path
    }

    /// Transitive dependencies (petgraph BFS forward)
    pub fn transitive_deps(&self, bom_ref: &str) -> Vec<String> {
        let Some(&start) = self.pet_index.get(bom_ref) else {
            return vec![];
        };
        let mut result = Vec::new();
        let mut visited = vec![false; self.pet_graph.node_count()];
        visited[start.index()] = true;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start);
        while let Some(cur) = queue.pop_front() {
            for edge in self.pet_graph.edges_directed(cur, Direction::Outgoing) {
                let tgt = edge.target();
                if !visited[tgt.index()] {
                    visited[tgt.index()] = true;
                    result.push(self.pet_graph[tgt].clone());
                    queue.push_back(tgt);
                }
            }
        }
        result
    }

    /// License propagation: find GPL-like licenses that propagate up
    pub fn copyleft_propagation(&self) -> Vec<(String, String, String)> {
        let copyleft = ["GPL", "LGPL", "AGPL", "MPL", "EUPL", "CDDL", "EPL"];
        let mut propagations = Vec::new();
        for comp in &self.components {
            for lic in &comp.licenses {
                let lid = lic.id.as_deref().or(lic.name.as_deref()).unwrap_or("");
                if copyleft.iter().any(|c| lid.to_uppercase().contains(c)) {
                    let bref = comp.bom_ref.as_deref().unwrap_or(&comp.name);
                    if let Some(parents) = self.reverse_adj.get(bref) {
                        for parent in parents {
                            propagations.push((lid.to_string(), bref.to_string(), parent.clone()));
                        }
                    }
                }
            }
        }
        propagations
    }

    /// Summary statistics
    pub fn stats(&self) -> SbomStats {
        let with_license = self.components.iter().filter(|c| !c.licenses.is_empty()).count();
        let with_supplier = self.components.iter().filter(|c| c.supplier.is_some()).count();
        let with_purl = self.components.iter().filter(|c| c.purl.is_some()).count();
        let with_hash = self.components.iter().filter(|c| !c.hashes.is_empty()).count();
        let with_version = self.components.iter().filter(|c| c.version.is_some()).count();
        let avg_trust = if self.components.is_empty() { 0.0 } else {
            self.components.iter().map(|c| c.trust_score).sum::<f64>() / self.components.len() as f64
        };
        SbomStats {
            total_components: self.components.len(),
            total_dependencies: self.dependencies.iter().map(|d| d.to_refs.len()).sum(),
            total_vulnerabilities: self.vulnerabilities.len(),
            with_license, with_supplier, with_purl, with_hash, with_version,
            license_coverage: pct(with_license, self.components.len()),
            supplier_coverage: pct(with_supplier, self.components.len()),
            purl_coverage: pct(with_purl, self.components.len()),
            hash_coverage: pct(with_hash, self.components.len()),
            avg_trust_score: avg_trust,
            critical_vulns: self.vulnerabilities.iter().filter(|v| matches!(v.severity.as_deref(), Some("critical") | Some("CRITICAL"))).count(),
            high_vulns: self.vulnerabilities.iter().filter(|v| matches!(v.severity.as_deref(), Some("high") | Some("HIGH"))).count(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SbomStats {
    pub total_components: usize,
    pub total_dependencies: usize,
    pub total_vulnerabilities: usize,
    pub with_license: usize,
    pub with_supplier: usize,
    pub with_purl: usize,
    pub with_hash: usize,
    pub with_version: usize,
    pub license_coverage: f64,
    pub supplier_coverage: f64,
    pub purl_coverage: f64,
    pub hash_coverage: f64,
    pub avg_trust_score: f64,
    pub critical_vulns: usize,
    pub high_vulns: usize,
}

fn pct(n: usize, total: usize) -> f64 {
    if total == 0 { 0.0 } else { (n as f64 / total as f64) * 100.0 }
}

fn compute_trust_score(comp: &Component) -> f64 {
    let mut score = 0.0;
    let mut factors = 0.0;
    // License present: +0.2
    factors += 0.2;
    if !comp.licenses.is_empty() { score += 0.2; }
    // Supplier present: +0.2
    factors += 0.2;
    if comp.supplier.is_some() { score += 0.2; }
    // Hash present: +0.2
    factors += 0.2;
    if !comp.hashes.is_empty() { score += 0.2; }
    // PURL present: +0.2
    factors += 0.2;
    if comp.purl.is_some() { score += 0.2; }
    // Version present: +0.1
    factors += 0.1;
    if comp.version.is_some() { score += 0.1; }
    // No vulns: +0.1
    factors += 0.1;
    if comp.vuln_count == 0 { score += 0.1; }
    score / factors
}

// ─────────────────── JSON Parsers ───────────────────

fn parse_metadata(json: Option<&serde_json::Value>) -> Option<SbomMetadata> {
    let j = json?;
    Some(SbomMetadata {
        timestamp: j.get("timestamp").and_then(|v| v.as_str()).map(|s| s.into()),
        component: j.get("component").map(|c| MetadataComponent {
            name: c.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
            version: c.get("version").and_then(|v| v.as_str()).map(|s| s.into()),
            bom_ref: c.get("bom-ref").and_then(|v| v.as_str()).map(|s| s.into()),
            component_type: c.get("type").and_then(|v| v.as_str()).unwrap_or("application").into(),
        }),
        tools: j.get("tools").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(|s| s.into())).collect()
        }).unwrap_or_default(),
        authors: j.get("authors").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(|s| s.into())).collect()
        }).unwrap_or_default(),
        supplier: j.get("supplier").map(|s| Supplier {
            name: s.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
            url: s.get("url").and_then(|v| v.as_str()).map(|s| s.into()),
            contact: Vec::new(),
        }),
    })
}

fn parse_components(json: Option<&serde_json::Value>) -> Vec<Component> {
    json.and_then(|v| v.as_array()).map(|arr| {
        arr.iter().map(|c| Component {
            bom_ref: c.get("bom-ref").and_then(|v| v.as_str()).map(|s| s.into()),
            component_type: c.get("type").and_then(|v| v.as_str()).unwrap_or("library").into(),
            name: c.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
            version: c.get("version").and_then(|v| v.as_str()).map(|s| s.into()),
            group: c.get("group").and_then(|v| v.as_str()).map(|s| s.into()),
            purl: c.get("purl").and_then(|v| v.as_str()).map(|s| s.into()),
            cpe: c.get("cpe").and_then(|v| v.as_str()).map(|s| s.into()),
            description: c.get("description").and_then(|v| v.as_str()).map(|s| s.into()),
            licenses: c.get("licenses").and_then(|v| v.as_array()).map(|a| {
                a.iter().map(|l| {
                    let lic = l.get("license").unwrap_or(l);
                    LicenseEntry {
                        id: lic.get("id").and_then(|v| v.as_str()).map(|s| s.into()),
                        name: lic.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
                        url: lic.get("url").and_then(|v| v.as_str()).map(|s| s.into()),
                    }
                }).collect()
            }).unwrap_or_default(),
            supplier: c.get("supplier").map(|s| Supplier {
                name: s.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
                url: s.get("url").and_then(|v| v.as_str()).map(|s| s.into()),
                contact: Vec::new(),
            }),
            hashes: c.get("hashes").and_then(|v| v.as_array()).map(|a| {
                a.iter().map(|h| HashEntry {
                    alg: h.get("alg").and_then(|v| v.as_str()).unwrap_or("").into(),
                    content: h.get("content").and_then(|v| v.as_str()).unwrap_or("").into(),
                }).collect()
            }).unwrap_or_default(),
            external_references: c.get("externalReferences").and_then(|v| v.as_array()).map(|a| {
                a.iter().map(|r| ExternalRef {
                    ref_type: r.get("type").and_then(|v| v.as_str()).unwrap_or("").into(),
                    url: r.get("url").and_then(|v| v.as_str()).unwrap_or("").into(),
                }).collect()
            }).unwrap_or_default(),
            scope: c.get("scope").and_then(|v| v.as_str()).map(|s| s.into()),
            properties: c.get("properties").and_then(|v| v.as_array()).map(|a| {
                a.iter().filter_map(|p| {
                    let k = p.get("name").and_then(|v| v.as_str())?;
                    let v = p.get("value").and_then(|v| v.as_str())?;
                    Some((k.to_string(), v.to_string()))
                }).collect()
            }).unwrap_or_default(),
            vuln_count: 0,
            dep_count: 0,
            dependents_count: 0,
            trust_score: 0.0,
        }).collect()
    }).unwrap_or_default()
}

fn parse_dependencies(json: Option<&serde_json::Value>) -> Vec<DependencyEdge> {
    json.and_then(|v| v.as_array()).map(|arr| {
        arr.iter().map(|d| DependencyEdge {
            from_ref: d.get("ref").and_then(|v| v.as_str()).unwrap_or("").into(),
            to_refs: d.get("dependsOn").and_then(|v| v.as_array()).map(|a| {
                a.iter().filter_map(|r| r.as_str().map(|s| s.into())).collect()
            }).unwrap_or_default(),
        }).collect()
    }).unwrap_or_default()
}

fn parse_vulnerabilities(json: Option<&serde_json::Value>) -> Vec<Vulnerability> {
    json.and_then(|v| v.as_array()).map(|arr| {
        arr.iter().map(|v| {
            let affects = v.get("affects").and_then(|a| a.as_array()).map(|arr| {
                arr.iter().filter_map(|a| a.get("ref").and_then(|r| r.as_str()).map(|s| s.into())).collect()
            }).unwrap_or_default();
            Vulnerability {
                id: v.get("id").and_then(|id| id.as_str()).unwrap_or("").into(),
                source: v.get("source").and_then(|s| s.get("name")).and_then(|n| n.as_str()).map(|s| s.into()),
                severity: v.get("ratings").and_then(|r| r.as_array()).and_then(|a| a.first()).and_then(|r| r.get("severity")).and_then(|s| s.as_str()).map(|s| s.into()),
                cvss_score: v.get("ratings").and_then(|r| r.as_array()).and_then(|a| a.first()).and_then(|r| r.get("score")).and_then(|s| s.as_f64()),
                description: v.get("description").and_then(|d| d.as_str()).map(|s| s.into()),
                affects,
                fixed_version: None,
                published: v.get("published").and_then(|p| p.as_str()).map(|s| s.into()),
                url: v.get("source").and_then(|s| s.get("url")).and_then(|u| u.as_str()).map(|s| s.into()),
            }
        }).collect()
    }).unwrap_or_default()
}
