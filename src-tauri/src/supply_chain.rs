use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use petgraph::graph::{DiGraph, NodeIndex};

// ══════════════════════════════════════════════════════
//  Supply Chain Graph — end-to-end pipeline
//  ASTGraph → BuildGraph → ExecutionGraph →
//  ArtifactGraph → SBOMGraph → TrustGraph
// ══════════════════════════════════════════════════════

// ─────────────────── ASTGraph ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AstGraph {
    pub root_dir: String,
    pub source_nodes: Vec<SourceNode>,
    pub import_edges: Vec<ImportEdge>,
    pub build_files: Vec<BuildFile>,
    pub stats: AstStats,
    /// petgraph in-memory DiGraph: file nodes + import edges
    #[serde(skip)]
    pub pet_graph: DiGraph<String, String>,
    #[serde(skip)]
    pub pet_index: HashMap<String, NodeIndex>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SourceNode {
    pub path: String,
    pub language: String,
    pub size_bytes: u64,
    pub lines: usize,
    pub imports: usize,
    pub exports: usize,
    pub is_entry: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImportEdge {
    pub from_file: String,
    pub to_module: String,
    pub import_type: String, // internal, external, stdlib
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildFile {
    pub path: String,
    pub build_system: String, // cargo, npm, gradle, maven, go
    pub declared_deps: Vec<DeclaredDep>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeclaredDep {
    pub name: String,
    pub version: String,
    pub dep_type: String, // runtime, dev, build, optional
    pub source: String,   // registry, git, local
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AstStats {
    pub total_files: usize,
    pub total_lines: usize,
    pub total_imports: usize,
    pub languages: HashMap<String, usize>,
    pub build_systems: Vec<String>,
    pub declared_deps: usize,
    pub internal_imports: usize,
    pub external_imports: usize,
}

fn detect_language(path: &str) -> Option<&'static str> {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("rs") => Some("rust"),
        Some("ts") | Some("tsx") => Some("typescript"),
        Some("js") | Some("jsx") => Some("javascript"),
        Some("java") => Some("java"),
        Some("go") => Some("go"),
        Some("py") => Some("python"),
        Some("cs") => Some("csharp"),
        Some("kt") => Some("kotlin"),
        Some("c") | Some("h") => Some("c"),
        Some("cpp") | Some("cc") | Some("hpp") => Some("cpp"),
        Some("rb") => Some("ruby"),
        _ => None,
    }
}

fn detect_build_system(path: &str) -> Option<&'static str> {
    let name = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "Cargo.toml" => Some("cargo"),
        "package.json" => Some("npm"),
        "go.mod" => Some("go"),
        "build.gradle" | "build.gradle.kts" => Some("gradle"),
        "pom.xml" => Some("maven"),
        "Makefile" | "makefile" => Some("make"),
        "CMakeLists.txt" => Some("cmake"),
        "requirements.txt" | "setup.py" | "pyproject.toml" => Some("python"),
        "Gemfile" => Some("ruby"),
        _ => None,
    }
}

fn parse_imports(content: &str, lang: &str) -> Vec<(String, String)> {
    let mut imports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        match lang {
            "rust" => {
                if trimmed.starts_with("use ") || trimmed.starts_with("extern crate ") {
                    let module = trimmed.trim_start_matches("use ").trim_start_matches("extern crate ")
                        .split("::").next().unwrap_or("").trim_end_matches(';').to_string();
                    let itype = if ["std", "core", "alloc"].contains(&module.as_str()) { "stdlib" }
                        else if module.starts_with("crate") || module.starts_with("super") || module.starts_with("self") { "internal" }
                        else { "external" };
                    imports.push((module, itype.to_string()));
                }
            }
            "typescript" | "javascript" => {
                if (trimmed.starts_with("import ") || trimmed.starts_with("import{")) && trimmed.contains("from") {
                    if let Some(idx) = trimmed.rfind("from") {
                        let module = trimmed[idx+4..].trim().trim_matches(|c| c == '\'' || c == '"' || c == ';').to_string();
                        let itype = if module.starts_with('.') { "internal" } else { "external" };
                        imports.push((module, itype.to_string()));
                    }
                }
            }
            "java" | "kotlin" => {
                if trimmed.starts_with("import ") {
                    let module = trimmed.trim_start_matches("import ").trim_start_matches("static ")
                        .trim_end_matches(';').split('.').take(3).collect::<Vec<_>>().join(".");
                    let itype = if module.starts_with("java.") || module.starts_with("javax.") { "stdlib" }
                        else { "external" };
                    imports.push((module, itype.to_string()));
                }
            }
            "go" => {
                if trimmed.starts_with('"') && trimmed.ends_with('"') {
                    let module = trimmed.trim_matches('"').to_string();
                    let itype = if !module.contains('.') { "stdlib" } else { "external" };
                    imports.push((module, itype.to_string()));
                }
            }
            "python" => {
                if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                    let module = trimmed.trim_start_matches("from ").trim_start_matches("import ")
                        .split_whitespace().next().unwrap_or("").split('.').next().unwrap_or("").to_string();
                    let itype = if module.starts_with('.') { "internal" } else { "external" };
                    imports.push((module, itype.to_string()));
                }
            }
            _ => {}
        }
    }
    imports
}

fn parse_cargo_deps(content: &str) -> Vec<DeclaredDep> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    let mut in_dev = false;
    let mut in_build = false;
    for line in content.lines() {
        let t = line.trim();
        if t == "[dependencies]" { in_deps = true; in_dev = false; in_build = false; continue; }
        if t == "[dev-dependencies]" { in_dev = true; in_deps = false; in_build = false; continue; }
        if t == "[build-dependencies]" { in_build = true; in_deps = false; in_dev = false; continue; }
        if t.starts_with('[') { in_deps = false; in_dev = false; in_build = false; continue; }
        if (in_deps || in_dev || in_build) && t.contains('=') {
            let parts: Vec<&str> = t.splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().trim_matches('"').to_string();
                let ver = parts[1].trim().trim_matches('"').trim_matches('{').split(',').next().unwrap_or("*").trim().to_string();
                let dtype = if in_dev { "dev" } else if in_build { "build" } else { "runtime" };
                deps.push(DeclaredDep { name, version: ver, dep_type: dtype.into(), source: "registry".into() });
            }
        }
    }
    deps
}

fn parse_package_json_deps(content: &str) -> Vec<DeclaredDep> {
    let mut deps = Vec::new();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        for (section, dtype) in [("dependencies", "runtime"), ("devDependencies", "dev"), ("peerDependencies", "optional")] {
            if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
                for (name, ver) in obj {
                    deps.push(DeclaredDep { name: name.clone(), version: ver.as_str().unwrap_or("*").to_string(), dep_type: dtype.into(), source: "registry".into() });
                }
            }
        }
    }
    deps
}

pub fn scan_ast(root_dir: &str) -> AstGraph {
    let root = Path::new(root_dir);
    let mut source_nodes = Vec::new();
    let mut import_edges = Vec::new();
    let mut build_files = Vec::new();
    let mut languages: HashMap<String, usize> = HashMap::new();

    let entries = walkdir(root, 5);

    for entry in &entries {
        let rel = entry.strip_prefix(root).unwrap_or(Path::new(entry)).to_string_lossy().to_string();

        // Build files
        if let Some(bs) = detect_build_system(&rel) {
            if let Ok(content) = std::fs::read_to_string(entry) {
                let declared_deps = match bs {
                    "cargo" => parse_cargo_deps(&content),
                    "npm" => parse_package_json_deps(&content),
                    _ => Vec::new(),
                };
                build_files.push(BuildFile { path: rel.clone(), build_system: bs.into(), declared_deps });
            }
        }

        // Source files
        if let Some(lang) = detect_language(&rel) {
            if let Ok(content) = std::fs::read_to_string(entry) {
                let lines = content.lines().count();
                let size = content.len() as u64;
                let parsed = parse_imports(&content, lang);
                let imports_count = parsed.len();
                let is_entry = rel.contains("main.") || rel.contains("lib.") || rel.contains("index.") || rel.contains("mod.");

                for (module, itype) in &parsed {
                    import_edges.push(ImportEdge { from_file: rel.clone(), to_module: module.clone(), import_type: itype.clone() });
                }

                *languages.entry(lang.to_string()).or_insert(0) += 1;
                source_nodes.push(SourceNode { path: rel, language: lang.into(), size_bytes: size, lines, imports: imports_count, exports: 0, is_entry });
            }
        }
    }

    let total_imports = import_edges.len();
    let internal = import_edges.iter().filter(|e| e.import_type == "internal").count();
    let external = import_edges.iter().filter(|e| e.import_type == "external").count();
    let declared_deps: usize = build_files.iter().map(|b| b.declared_deps.len()).sum();

    let stats = AstStats {
        total_files: source_nodes.len(),
        total_lines: source_nodes.iter().map(|n| n.lines).sum(),
        total_imports,
        languages,
        build_systems: build_files.iter().map(|b| b.build_system.clone()).collect::<std::collections::HashSet<_>>().into_iter().collect(),
        declared_deps,
        internal_imports: internal,
        external_imports: external,
    };

    AstGraph { root_dir: root_dir.into(), source_nodes, import_edges, build_files, stats, pet_graph: DiGraph::new(), pet_index: HashMap::new() }
}

/// Build petgraph DiGraph from AstGraph
pub fn build_ast_petgraph(ast: &mut AstGraph) {
    let mut pg: DiGraph<String, String> = DiGraph::with_capacity(ast.source_nodes.len(), ast.import_edges.len());
    let mut idx: HashMap<String, NodeIndex> = HashMap::new();
    for src in &ast.source_nodes {
        let nx = pg.add_node(src.path.clone());
        idx.insert(src.path.clone(), nx);
    }
    for imp in &ast.import_edges {
        if !idx.contains_key(&imp.from_file) {
            let nx = pg.add_node(imp.from_file.clone());
            idx.insert(imp.from_file.clone(), nx);
        }
        let target_key = if imp.import_type == "internal" {
            let mod_path = imp.to_module.replace("::", "/").replace('.', "/");
            ast.source_nodes.iter().find(|n| n.path != imp.from_file && (n.path.contains(&mod_path) || n.path.replace(&['.'][..], "").ends_with(&mod_path)))
                .map(|n| n.path.clone())
        } else {
            Some(format!("ext:{}", imp.to_module.split("::").next().unwrap_or(&imp.to_module)))
        };
        if let Some(tgt) = target_key {
            if !idx.contains_key(&tgt) {
                let nx = pg.add_node(tgt.clone());
                idx.insert(tgt.clone(), nx);
            }
            let from_nx = idx[&imp.from_file];
            let to_nx = idx[&tgt];
            pg.add_edge(from_nx, to_nx, imp.import_type.clone());
        }
    }
    ast.pet_graph = pg;
    ast.pet_index = idx;
}

fn walkdir(root: &Path, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    walk_recursive(root, 0, max_depth, &mut result);
    result
}

fn walk_recursive(dir: &Path, depth: usize, max_depth: usize, result: &mut Vec<std::path::PathBuf>) {
    if depth > max_depth { return; }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name == "node_modules" || name == "target" || name == "dist" || name == "build" || name == "__pycache__" { continue; }
        if path.is_dir() { walk_recursive(&path, depth + 1, max_depth, result); }
        else { result.push(path); }
    }
}

// ─────────────────── BuildGraph ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildGraph {
    pub targets: Vec<BuildTarget>,
    pub dep_resolution: Vec<ResolvedDep>,
    pub build_steps: Vec<BuildStep>,
    pub outputs: Vec<BuildOutput>,
    /// petgraph DAG: build steps → outputs
    #[serde(skip)]
    pub pet_dag: DiGraph<String, ()>,
    #[serde(skip)]
    pub pet_index: HashMap<String, NodeIndex>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildTarget {
    pub name: String,
    pub target_type: String, // binary, library, test, bench
    pub source_files: usize,
    pub build_system: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResolvedDep {
    pub name: String,
    pub declared_version: String,
    pub dep_type: String,
    pub source: String,
    pub in_sbom: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildStep {
    pub id: String,
    pub name: String,
    pub command: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildOutput {
    pub name: String,
    pub output_type: String, // binary, library, container, archive
    pub path: String,
}

pub fn derive_build_graph(ast: &AstGraph) -> BuildGraph {
    let mut targets = Vec::new();
    let mut dep_resolution = Vec::new();
    let mut build_steps = Vec::new();
    let mut outputs = Vec::new();

    // Derive targets from build files
    for bf in &ast.build_files {
        let lang_files = ast.source_nodes.iter().filter(|n| match bf.build_system.as_str() {
            "cargo" => n.language == "rust",
            "npm" => n.language == "typescript" || n.language == "javascript",
            "gradle" | "maven" => n.language == "java" || n.language == "kotlin",
            "go" => n.language == "go",
            "python" => n.language == "python",
            _ => false,
        }).count();

        targets.push(BuildTarget { name: bf.path.clone(), target_type: "binary".into(), source_files: lang_files, build_system: bf.build_system.clone() });

        // Resolve deps
        for dep in &bf.declared_deps {
            dep_resolution.push(ResolvedDep { name: dep.name.clone(), declared_version: dep.version.clone(), dep_type: dep.dep_type.clone(), source: dep.source.clone(), in_sbom: false });
        }
    }

    // Generate canonical build steps
    for (i, bs) in ast.build_files.iter().enumerate() {
        let cmd = match bs.build_system.as_str() {
            "cargo" => "cargo build --release",
            "npm" => "npm run build",
            "gradle" => "./gradlew build",
            "maven" => "mvn package",
            "go" => "go build ./...",
            "python" => "pip install -e .",
            "make" => "make all",
            _ => "build",
        };

        build_steps.push(BuildStep {
            id: format!("build-{}", i),
            name: format!("{} build", bs.build_system),
            command: cmd.into(),
            inputs: vec![bs.path.clone()],
            outputs: vec![format!("build-output-{}", i)],
        });
    }

    // Generate outputs
    for bs in &ast.build_files {
        let (out_type, out_path) = match bs.build_system.as_str() {
            "cargo" => ("binary", "target/release/"),
            "npm" => ("archive", "dist/"),
            "gradle" | "maven" => ("library", "build/libs/"),
            "go" => ("binary", "./"),
            _ => ("archive", "build/"),
        };
        outputs.push(BuildOutput { name: format!("{} output", bs.build_system), output_type: out_type.into(), path: out_path.into() });
    }

    // petgraph DAG built lazily on demand (not during parse)
    BuildGraph { targets, dep_resolution, build_steps, outputs, pet_dag: DiGraph::new(), pet_index: HashMap::new() }
}

// ─────────────────── Full Supply Chain ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SupplyChain {
    pub ast: AstGraphSummary,
    pub build: BuildGraphSummary,
    pub chain_nodes: Vec<ChainNode>,
    pub chain_edges: Vec<ChainEdge>,
    pub chain_stats: ChainStats,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AstGraphSummary {
    pub total_files: usize,
    pub total_lines: usize,
    pub languages: HashMap<String, usize>,
    pub build_systems: Vec<String>,
    pub declared_deps: usize,
    pub internal_imports: usize,
    pub external_imports: usize,
    pub entry_points: Vec<String>,
    pub top_importers: Vec<(String, usize)>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildGraphSummary {
    pub targets: usize,
    pub resolved_deps: usize,
    pub build_steps: usize,
    pub outputs: usize,
    pub build_commands: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainNode {
    pub id: String,
    pub label: String,
    pub kind: String,      // ast, build, execution, artifact, sbom, trust
    pub icon: String,
    pub color: String,
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainStats {
    pub total_chain_nodes: usize,
    pub total_chain_edges: usize,
    pub graphs_connected: usize,
    pub source_to_trust_depth: usize,
}

pub fn build_supply_chain(root_dir: &str, sbom: Option<&crate::sbom_graph::SbomGraph>) -> SupplyChain {
    let ast = scan_ast(root_dir);
    let build = derive_build_graph(&ast);

    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // AST layer nodes
    for (lang, count) in &ast.stats.languages {
        let mut det = HashMap::new();
        det.insert("files".into(), format!("{}", count));
        nodes.push(ChainNode { id: format!("ast:{}", lang), label: format!("{} source", lang), kind: "ast".into(), icon: "📝".into(), color: "#eb2f96".into(), details: det });
    }
    let entries: Vec<String> = ast.source_nodes.iter().filter(|n| n.is_entry).map(|n| n.path.clone()).collect();
    for ep in &entries {
        let mut det = HashMap::new();
        det.insert("type".into(), "entry point".into());
        nodes.push(ChainNode { id: format!("ast:entry:{}", ep), label: ep.split('/').last().unwrap_or(ep).into(), kind: "ast".into(), icon: "🚪".into(), color: "#eb2f96".into(), details: det });
    }

    // Build layer nodes
    for (i, step) in build.build_steps.iter().enumerate() {
        let mut det = HashMap::new();
        det.insert("command".into(), step.command.clone());
        nodes.push(ChainNode { id: format!("build:{}", i), label: step.name.clone(), kind: "build".into(), icon: "🔨".into(), color: "#fa8c16".into(), details: det });
    }
    for out in &build.outputs {
        let mut det = HashMap::new();
        det.insert("type".into(), out.output_type.clone());
        det.insert("path".into(), out.path.clone());
        nodes.push(ChainNode { id: format!("build:out:{}", out.name), label: out.name.clone(), kind: "build".into(), icon: "📦".into(), color: "#fa8c16".into(), details: det });
    }

    // Execution layer nodes
    let exec_steps = ["① Scan SBOM", "② Validate", "③ Rules", "④ Vuln Scan", "⑤ Export"];
    for (i, step) in exec_steps.iter().enumerate() {
        nodes.push(ChainNode { id: format!("exec:{}", i), label: step.to_string(), kind: "execution".into(), icon: "⚙️".into(), color: "#1890ff".into(), details: HashMap::new() });
    }

    // Artifact layer nodes
    let artifacts = [("sbom.json", "📄"), ("report.sarif", "📋"), ("vex.json", "🛡️")];
    for (name, icon) in &artifacts {
        nodes.push(ChainNode { id: format!("art:{}", name), label: name.to_string(), kind: "artifact".into(), icon: icon.to_string(), color: "#13c2c2".into(), details: HashMap::new() });
    }

    // SBOM layer nodes
    if let Some(sbom) = sbom {
        let stats = sbom.stats();
        let mut det = HashMap::new();
        det.insert("components".into(), format!("{}", stats.total_components));
        det.insert("deps".into(), format!("{}", stats.total_dependencies));
        det.insert("vulns".into(), format!("{}", stats.total_vulnerabilities));
        nodes.push(ChainNode { id: "sbom:graph".into(), label: format!("{} components", stats.total_components), kind: "sbom".into(), icon: "📦".into(), color: "#52c41a".into(), details: det });

        if stats.total_vulnerabilities > 0 {
            let mut vdet = HashMap::new();
            vdet.insert("critical".into(), format!("{}", stats.critical_vulns));
            vdet.insert("high".into(), format!("{}", stats.high_vulns));
            nodes.push(ChainNode { id: "sbom:vulns".into(), label: format!("{} vulnerabilities", stats.total_vulnerabilities), kind: "sbom".into(), icon: "🔴".into(), color: "#ff4d4f".into(), details: vdet });
        }
    } else {
        nodes.push(ChainNode { id: "sbom:graph".into(), label: "SBOM (load to enrich)".into(), kind: "sbom".into(), icon: "📦".into(), color: "#52c41a".into(), details: HashMap::new() });
    }

    // Trust layer nodes
    nodes.push(ChainNode { id: "trust:score".into(), label: "Trust Score".into(), kind: "trust".into(), icon: "🛡️".into(), color: "#722ed1".into(), details: HashMap::new() });
    nodes.push(ChainNode { id: "trust:compliance".into(), label: "Compliance".into(), kind: "trust".into(), icon: "🏛️".into(), color: "#722ed1".into(), details: HashMap::new() });

    // Chain edges: AST → Build
    for (lang, _) in &ast.stats.languages {
        for (i, _) in build.build_steps.iter().enumerate() {
            edges.push(ChainEdge { from: format!("ast:{}", lang), to: format!("build:{}", i), label: "compiled_by".into() });
        }
    }
    // Build → Execution
    for (i, _) in build.build_steps.iter().enumerate() {
        edges.push(ChainEdge { from: format!("build:{}", i), to: "exec:0".into(), label: "triggers".into() });
    }
    // Execution chain
    for i in 0..exec_steps.len()-1 {
        edges.push(ChainEdge { from: format!("exec:{}", i), to: format!("exec:{}", i+1), label: "→".into() });
    }
    // Execution → Artifacts
    edges.push(ChainEdge { from: "exec:0".into(), to: "art:sbom.json".into(), label: "produces".into() });
    edges.push(ChainEdge { from: "exec:3".into(), to: "art:vex.json".into(), label: "produces".into() });
    edges.push(ChainEdge { from: "exec:4".into(), to: "art:report.sarif".into(), label: "produces".into() });
    // Artifacts → SBOM
    edges.push(ChainEdge { from: "art:sbom.json".into(), to: "sbom:graph".into(), label: "contains".into() });
    // SBOM → Trust
    edges.push(ChainEdge { from: "sbom:graph".into(), to: "trust:score".into(), label: "evaluated_by".into() });
    edges.push(ChainEdge { from: "trust:score".into(), to: "trust:compliance".into(), label: "verified_by".into() });

    let ast_summary = AstGraphSummary {
        total_files: ast.stats.total_files,
        total_lines: ast.stats.total_lines,
        languages: ast.stats.languages.clone(),
        build_systems: ast.stats.build_systems.clone(),
        declared_deps: ast.stats.declared_deps,
        internal_imports: ast.stats.internal_imports,
        external_imports: ast.stats.external_imports,
        entry_points: entries,
        top_importers: {
            let mut map: HashMap<String, usize> = HashMap::new();
            for edge in &ast.import_edges {
                *map.entry(edge.from_file.clone()).or_default() += 1;
            }
            let mut sorted: Vec<_> = map.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            sorted.truncate(10);
            sorted
        },
    };

    let build_summary = BuildGraphSummary {
        targets: build.targets.len(),
        resolved_deps: build.dep_resolution.len(),
        build_steps: build.build_steps.len(),
        outputs: build.outputs.len(),
        build_commands: build.build_steps.iter().map(|s| s.command.clone()).collect(),
    };

    let chain_stats = ChainStats {
        total_chain_nodes: nodes.len(),
        total_chain_edges: edges.len(),
        graphs_connected: 6,
        source_to_trust_depth: 6,
    };

    SupplyChain { ast: ast_summary, build: build_summary, chain_nodes: nodes, chain_edges: edges, chain_stats }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn scan_supply_chain(root_dir: String, sbom_path: Option<String>) -> Result<SupplyChain, String> {
    let sbom = if let Some(ref sp) = sbom_path {
        let content = std::fs::read_to_string(sp).map_err(|e| format!("Cannot read SBOM: {}", e))?;
        let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
        Some(crate::sbom_graph::SbomGraph::from_cdx_json(&json)?)
    } else { None };

    Ok(build_supply_chain(&root_dir, sbom.as_ref()))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeGraphResult {
    pub source_nodes: Vec<SourceNode>,
    pub import_edges: Vec<ImportEdge>,
    pub build_files: Vec<BuildFile>,
    pub stats: AstStats,
}

#[tauri::command]
pub fn scan_code_graph(root_dir: String) -> Result<CodeGraphResult, String> {
    let ast = scan_ast(&root_dir);
    Ok(CodeGraphResult {
        source_nodes: ast.source_nodes,
        import_edges: ast.import_edges,
        build_files: ast.build_files,
        stats: ast.stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_project_ast() {
        // Scan our own project
        let root = env!("CARGO_MANIFEST_DIR");
        let parent = std::path::Path::new(root).parent().unwrap().to_string_lossy().to_string();
        println!("\n=== AST Scanner Test ===");
        println!("Scanning: {}", parent);

        let ast = scan_ast(&parent);

        println!("\n📊 Stats:");
        println!("  Files: {}", ast.stats.total_files);
        println!("  Lines: {}", ast.stats.total_lines);
        println!("  Imports: {}", ast.stats.total_imports);
        println!("  Internal: {}", ast.stats.internal_imports);
        println!("  External: {}", ast.stats.external_imports);
        println!("  Declared deps: {}", ast.stats.declared_deps);

        println!("\n🌐 Languages:");
        for (lang, count) in &ast.stats.languages {
            println!("  {} → {} files", lang, count);
        }

        println!("\n📦 Build systems: {:?}", ast.stats.build_systems);

        println!("\n📄 Build files:");
        for bf in &ast.build_files {
            println!("  {} ({}) → {} deps", bf.path, bf.build_system, bf.declared_deps.len());
            for dep in bf.declared_deps.iter().take(5) {
                println!("    {} = {} ({})", dep.name, dep.version, dep.dep_type);
            }
            if bf.declared_deps.len() > 5 {
                println!("    ... and {} more", bf.declared_deps.len() - 5);
            }
        }

        println!("\n🚪 Entry points:");
        for n in ast.source_nodes.iter().filter(|n| n.is_entry) {
            println!("  {} ({}, {} lines)", n.path, n.language, n.lines);
        }

        println!("\n📈 Top importers:");
        let mut import_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for edge in &ast.import_edges {
            *import_counts.entry(edge.from_file.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = import_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (file, count) in sorted.iter().take(10) {
            println!("  {} → {} imports", file, count);
        }

        println!("\n🔨 Build Graph:");
        let build = derive_build_graph(&ast);
        println!("  Targets: {}", build.targets.len());
        println!("  Resolved deps: {}", build.dep_resolution.len());
        println!("  Build steps: {}", build.build_steps.len());
        for step in &build.build_steps {
            println!("    {} → {}", step.name, step.command);
        }
        println!("  Outputs: {}", build.outputs.len());
        for out in &build.outputs {
            println!("    {} ({}) → {}", out.name, out.output_type, out.path);
        }

        // Assertions
        assert!(ast.stats.total_files > 0, "Should find source files");
        assert!(ast.stats.total_lines > 0, "Should count lines");
        assert!(!ast.stats.languages.is_empty(), "Should detect languages");
        assert!(!ast.build_files.is_empty(), "Should find build files");
        assert!(ast.stats.total_imports > 0, "Should parse imports");

        println!("\n✅ All assertions passed!");
    }
}

