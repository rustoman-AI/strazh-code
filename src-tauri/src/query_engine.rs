use crepe::crepe;
use serde::{Deserialize, Serialize};
use crate::sbom_graph::SbomGraph;
use crate::supply_chain::AstGraph;

// ══════════════════════════════════════════════════════
//  Output Payloads
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExploitationPathPayload {
    pub entry_point: String,
    pub target_component: String,
    pub vulnerability_id: String,
    pub proof_chain: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CopyleftRiskPayload {
    pub source_component: String,
    pub license: String,
    pub affected_component: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustDecayPayload {
    pub component: String,
    pub reason: String,         // "no_supplier", "no_hash", "no_license"
    pub downstream_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlastRadiusPayload {
    pub vulnerability_id: String,
    pub vulnerable_component: String,
    pub affected_components: Vec<String>,
    pub total_affected: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatalogResult {
    pub exploitation_paths: Vec<ExploitationPathPayload>,
    pub copyleft_risks: Vec<CopyleftRiskPayload>,
    pub trust_decay: Vec<TrustDecayPayload>,
    pub blast_radius: Vec<BlastRadiusPayload>,
    pub stats: DatalogStats,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatalogStats {
    pub total_facts: usize,
    pub total_derived: usize,
    pub components_analyzed: usize,
    pub vulnerabilities_analyzed: usize,
    pub entry_points_analyzed: usize,
}

// ══════════════════════════════════════════════════════
//  DATALOG (crepe macro) Logic
// ══════════════════════════════════════════════════════

crepe! {
    // ── Input relations ──

    @input
    struct TakesNetworkInput<'a>(&'a str, &'a str);  // (label, func_path)

    @input
    struct Calls<'a>(&'a str, &'a str);  // (caller, callee)

    @input
    struct UsesComponent<'a>(&'a str, &'a str);  // (func_path, component_ref)

    @input
    struct DependsOn<'a>(&'a str, &'a str);  // (from_ref, to_ref)

    @input
    struct HasVuln<'a>(&'a str, &'a str, &'a str);  // (component_ref, vuln_id, severity)

    @input
    struct HasLicense<'a>(&'a str, &'a str);  // (component_ref, license_id)

    @input
    struct IsCopyleft<'a>(&'a str);  // (license_id)

    @input
    struct LowTrust<'a>(&'a str, &'a str);  // (component_ref, reason)

    // ── Output relations ──

    @output
    struct ReachableFunc<'a>(&'a str, &'a str);

    @output
    struct ReachableComponent<'a>(&'a str, &'a str);

    @output
    struct TransitiveDependsOn<'a>(&'a str, &'a str);

    @output
    pub struct ExploitationPath<'a>(&'a str, &'a str, &'a str, &'a str); // (entry, intermediate, target, vuln)

    @output
    struct CopyleftPropagation<'a>(&'a str, &'a str, &'a str);  // (source, license, affected)

    @output
    struct TrustDecayChain<'a>(&'a str, &'a str, &'a str);  // (untrusted_comp, reason, downstream)

    @output
    struct VulnBlast<'a>(&'a str, &'a str, &'a str);  // (vuln_id, vuln_comp, affected_comp)

    // ═══════════════════════════════════════════
    //  Rules
    // ═══════════════════════════════════════════

    // Rule 1: Reachable functions from network entry points
    ReachableFunc(entry, target) <-
        TakesNetworkInput(_, entry),
        Calls(entry, target);

    ReachableFunc(entry, target) <-
        ReachableFunc(entry, intermediate),
        Calls(intermediate, target);

    // Rule 2: Reachable components through function calls
    ReachableComponent(entry, component) <-
        TakesNetworkInput(_, entry),
        UsesComponent(entry, component);

    ReachableComponent(entry, component) <-
        ReachableFunc(entry, func),
        UsesComponent(func, component);

    // Rule 3: Transitive dependencies
    TransitiveDependsOn(from, to) <- DependsOn(from, to);
    TransitiveDependsOn(from, to) <- TransitiveDependsOn(from, mid), DependsOn(mid, to);

    // Rule 4: Exploitation Paths (entry → vuln component via intermediate)
    ExploitationPath(entry, intermediate_comp, target_comp, vuln_id) <-
        ReachableComponent(entry, intermediate_comp),
        TransitiveDependsOn(intermediate_comp, target_comp),
        HasVuln(target_comp, vuln_id, "critical");

    ExploitationPath(entry, intermediate_comp, target_comp, vuln_id) <-
        ReachableComponent(entry, intermediate_comp),
        TransitiveDependsOn(intermediate_comp, target_comp),
        HasVuln(target_comp, vuln_id, "high");

    ExploitationPath(entry, target_comp, target_comp, vuln_id) <-
        ReachableComponent(entry, target_comp),
        HasVuln(target_comp, vuln_id, "critical");

    ExploitationPath(entry, target_comp, target_comp, vuln_id) <-
        ReachableComponent(entry, target_comp),
        HasVuln(target_comp, vuln_id, "high");

    // Rule 5: Copyleft license propagation through dependencies
    CopyleftPropagation(source, license, source) <-
        HasLicense(source, license),
        IsCopyleft(license);

    CopyleftPropagation(source, license, affected) <-
        CopyleftPropagation(source, license, mid),
        DependsOn(affected, mid);

    // Rule 6: Trust decay — low-trust component contaminates downstream
    TrustDecayChain(comp, reason, comp) <-
        LowTrust(comp, reason);

    TrustDecayChain(comp, reason, downstream) <-
        TrustDecayChain(comp, reason, mid),
        DependsOn(downstream, mid);

    // Rule 7: Blast radius — vuln propagates to all transitive dependents
    VulnBlast(vuln_id, vuln_comp, vuln_comp) <-
        HasVuln(vuln_comp, vuln_id, "critical");

    VulnBlast(vuln_id, vuln_comp, vuln_comp) <-
        HasVuln(vuln_comp, vuln_id, "high");

    VulnBlast(vuln_id, vuln_comp, affected) <-
        VulnBlast(vuln_id, vuln_comp, mid),
        DependsOn(affected, mid);
}

// ══════════════════════════════════════════════════════
//  Runner: populate facts from real data
// ══════════════════════════════════════════════════════

/// Known copyleft licenses
const COPYLEFT_LICENSES: &[&str] = &[
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-2.0", "EUPL-1.2", "CECILL-2.1",
];

pub fn run_full_datalog(sbom: &SbomGraph, ast: Option<&AstGraph>) -> DatalogResult {
    let mut runtime = Crepe::new();

    let mut total_facts: usize = 0;

    // ── 1. Populate dependency facts from SBOM ──
    let dep_facts: Vec<DependsOn> = sbom.dependencies.iter()
        .flat_map(|edge| {
            edge.to_refs.iter().map(move |to| DependsOn(edge.from_ref.as_str(), to.as_str()))
        })
        .collect();
    total_facts += dep_facts.len();
    runtime.extend(&dep_facts);

    // ── 2. Populate vulnerability facts from SBOM ──
    let vuln_facts: Vec<HasVuln> = sbom.vulnerabilities.iter()
        .flat_map(|vuln| {
            let severity = vuln.severity.as_deref().unwrap_or("unknown");
            vuln.affects.iter().map(move |comp_ref| {
                HasVuln(comp_ref.as_str(), vuln.id.as_str(), severity)
            })
        })
        .collect();
    total_facts += vuln_facts.len();
    runtime.extend(&vuln_facts);

    // ── 3. Populate license facts from SBOM components ──
    // Store owned strings for licenses so we can reference them
    let license_strings: Vec<(String, String)> = sbom.components.iter()
        .filter_map(|c| {
            let bom_ref = c.bom_ref.as_deref()?;
            if c.licenses.is_empty() { return None; }
            Some(c.licenses.iter().map(move |l| {
                let lic_id = l.id.as_deref()
                    .or(l.name.as_deref())
                    .unwrap_or("unknown");
                (bom_ref.to_string(), lic_id.to_uppercase())
            }).collect::<Vec<_>>())
        })
        .flatten()
        .collect();

    let license_facts: Vec<HasLicense> = license_strings.iter()
        .map(|(br, lic)| HasLicense(br.as_str(), lic.as_str()))
        .collect();
    total_facts += license_facts.len();
    runtime.extend(&license_facts);

    // ── 4. Populate copyleft markers ──
    let copyleft_owned: Vec<String> = COPYLEFT_LICENSES.iter()
        .map(|s| s.to_uppercase())
        .collect();
    let copyleft_facts: Vec<IsCopyleft> = copyleft_owned.iter()
        .map(|lic| IsCopyleft(lic.as_str()))
        .collect();
    total_facts += copyleft_facts.len();
    runtime.extend(&copyleft_facts);

    // ── 5. Populate low-trust facts ──
    let trust_owned: Vec<(String, String)> = sbom.components.iter()
        .filter_map(|c| {
            let bom_ref = c.bom_ref.as_ref()?;
            if c.supplier.is_none() {
                Some((bom_ref.clone(), "no_supplier".to_string()))
            } else if c.hashes.is_empty() {
                Some((bom_ref.clone(), "no_hash".to_string()))
            } else if c.licenses.is_empty() {
                Some((bom_ref.clone(), "no_license".to_string()))
            } else {
                None
            }
        })
        .collect();

    let trust_facts: Vec<LowTrust> = trust_owned.iter()
        .map(|(comp, reason)| LowTrust(comp.as_str(), reason.as_str()))
        .collect();
    total_facts += trust_facts.len();
    runtime.extend(&trust_facts);

    // ── 6. Populate AST facts (entry points, calls, component usage) ──
    let mut entry_owned: Vec<(String, String)> = Vec::new();
    let mut call_owned: Vec<(String, String)> = Vec::new();
    let mut uses_owned: Vec<(String, String)> = Vec::new();

    if let Some(ast) = ast {
        for node in &ast.source_nodes {
            if node.is_entry {
                entry_owned.push(("App".to_string(), node.path.clone()));
            }
        }

        for edge in &ast.import_edges {
            match edge.import_type.as_str() {
                "internal" => {
                    call_owned.push((edge.from_file.clone(), edge.to_module.clone()));
                }
                "external" => {
                    let module_lower = edge.to_module.to_lowercase();
                    if let Some(comp) = sbom.components.iter().find(|c| {
                        c.name.to_lowercase() == module_lower ||
                        c.purl.as_deref().map(|p| p.to_lowercase().contains(&module_lower)).unwrap_or(false)
                    }) {
                        if let Some(ref bom_ref) = comp.bom_ref {
                            uses_owned.push((edge.from_file.clone(), bom_ref.clone()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let entry_facts: Vec<TakesNetworkInput> = entry_owned.iter()
        .map(|(label, func)| TakesNetworkInput(label.as_str(), func.as_str()))
        .collect();
    total_facts += entry_facts.len();
    runtime.extend(&entry_facts);

    let call_facts: Vec<Calls> = call_owned.iter()
        .map(|(caller, callee)| Calls(caller.as_str(), callee.as_str()))
        .collect();
    total_facts += call_facts.len();
    runtime.extend(&call_facts);

    let uses_facts: Vec<UsesComponent> = uses_owned.iter()
        .map(|(func, comp)| UsesComponent(func.as_str(), comp.as_str()))
        .collect();
    total_facts += uses_facts.len();
    runtime.extend(&uses_facts);

    // ── Execute Crepe inference ──
    let (
        _reachable_func,
        _reachable_comp,
        _transitive_deps,
        exploitation_paths,
        copyleft_propagation,
        trust_decay_chain,
        vuln_blast,
    ) = runtime.run();

    let total_derived = exploitation_paths.len()
        + copyleft_propagation.len()
        + trust_decay_chain.len()
        + vuln_blast.len()
        + _reachable_func.len()
        + _reachable_comp.len()
        + _transitive_deps.len();

    // ── Build exploitation paths (Proof Chains) ──
    let exploitation_results: Vec<ExploitationPathPayload> = exploitation_paths.into_iter()
        .map(|p| {
            let entry = p.0.to_string();
            let intermediate = p.1.to_string();
            let target = p.2.to_string();
            let vuln = p.3.to_string();

            let mut proof_chain = vec!["API / Entry".to_string(), entry.clone()];

            if intermediate != target {
                // Find shortest path in SBOM graph from intermediate to target
                if let (Some(&start_nx), Some(&end_nx)) = (sbom.pet_index.get(&intermediate), sbom.pet_index.get(&target)) {
                    let path = petgraph::algo::astar(
                        &sbom.pet_graph,
                        start_nx,
                        |finish| finish == end_nx,
                        |_| 1.0,
                        |_| 0.0,
                    );
                    if let Some((_, nodes)) = path {
                        for nx in nodes {
                            proof_chain.push(sbom.pet_graph[nx].clone());
                        }
                    } else {
                        proof_chain.push(intermediate);
                        proof_chain.push("...".to_string());
                        proof_chain.push(target.clone());
                    }
                } else {
                    proof_chain.push(intermediate);
                    proof_chain.push("...".to_string());
                    proof_chain.push(target.clone());
                }
            } else {
                proof_chain.push(target.clone());
            }
            proof_chain.push(vuln.clone());

            ExploitationPathPayload {
                entry_point: entry,
                target_component: target,
                vulnerability_id: vuln,
                proof_chain,
            }
        })
        .collect();

    // ── Build copyleft risks ──
    let copyleft_results: Vec<CopyleftRiskPayload> = copyleft_propagation.into_iter()
        .filter(|p| p.0 != p.2) // Exclude self-propagation
        .map(|p| CopyleftRiskPayload {
            source_component: p.0.to_string(),
            license: p.1.to_string(),
            affected_component: p.2.to_string(),
        })
        .collect();

    // ── Build trust decay ──
    // Group by untrusted component to count downstream impact
    let mut trust_map: std::collections::HashMap<(String, String), Vec<String>> = std::collections::HashMap::new();
    for t in &trust_decay_chain {
        let key = (t.0.to_string(), t.1.to_string());
        if t.0 != t.2 { // exclude self
            trust_map.entry(key).or_default().push(t.2.to_string());
        }
    }
    let trust_results: Vec<TrustDecayPayload> = trust_map.into_iter()
        .map(|((comp, reason), downstream)| TrustDecayPayload {
            component: comp,
            reason,
            downstream_count: downstream.len(),
        })
        .collect();

    // ── Build blast radius ──
    let mut blast_map: std::collections::HashMap<(String, String), Vec<String>> = std::collections::HashMap::new();
    for b in &vuln_blast {
        let key = (b.0.to_string(), b.1.to_string());
        if b.1 != b.2 { // exclude the vulnerable component itself
            blast_map.entry(key).or_default().push(b.2.to_string());
        }
    }
    let blast_results: Vec<BlastRadiusPayload> = blast_map.into_iter()
        .map(|((vuln_id, vuln_comp), affected)| BlastRadiusPayload {
            vulnerability_id: vuln_id,
            total_affected: affected.len(),
            vulnerable_component: vuln_comp,
            affected_components: affected,
        })
        .collect();

    DatalogResult {
        stats: DatalogStats {
            total_facts,
            total_derived,
            components_analyzed: sbom.components.len(),
            vulnerabilities_analyzed: sbom.vulnerabilities.len(),
            entry_points_analyzed: entry_facts.len(),
        },
        exploitation_paths: exploitation_results,
        copyleft_risks: copyleft_results,
        trust_decay: trust_results,
        blast_radius: blast_results,
    }
}

// Legacy compat wrapper
pub fn run_datalog_query(sbom: &SbomGraph) -> Vec<ExploitationPathPayload> {
    run_full_datalog(sbom, None).exploitation_paths
}
