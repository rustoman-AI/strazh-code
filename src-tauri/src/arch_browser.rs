use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ══════════════════════════════════════════════════════
//  Architecture Browser — scan /docs/Arch/ from all projects
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArchProject {
    pub id: String,
    pub name: String,
    pub version: String,
    pub path: String,
    pub arch_dir: String,
    pub files: Vec<ArchFile>,
    pub has_arch: bool,
    pub icon: String,
    pub tech: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArchFile {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub content: String,
    pub mermaid_blocks: Vec<MermaidBlock>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MermaidBlock {
    pub index: usize,
    pub code: String,
    pub title: String,       // heading above the mermaid block
    pub explanation: String,  // paragraph below the block
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectLink {
    pub from: String,
    pub to: String,
    pub relation: String,   // uses, invokes, inspires
    pub label: String,
}

/// Extract mermaid blocks from markdown content
fn extract_mermaid_blocks(content: &str) -> Vec<MermaidBlock> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    let mut block_idx = 0;

    while i < lines.len() {
        if lines[i].trim() == "```mermaid" {
            // Find title (look backwards for heading)
            let mut title = String::new();
            for j in (0..i).rev() {
                let line = lines[j].trim();
                if line.starts_with('#') {
                    title = line.trim_start_matches('#').trim().to_string();
                    break;
                }
                if !line.is_empty() && !line.starts_with('>') && !line.starts_with("---") {
                    break;
                }
            }

            // Collect mermaid code
            let mut code = String::new();
            i += 1;
            while i < lines.len() && lines[i].trim() != "```" {
                code.push_str(lines[i]);
                code.push('\n');
                i += 1;
            }

            // Find explanation (look forward for **Пояснение:** paragraph)
            let mut explanation = String::new();
            let mut j = i + 1;
            while j < lines.len() {
                let line = lines[j].trim();
                if line.is_empty() { j += 1; continue; }
                if line.starts_with("**Пояснение") || line.starts_with("**Explanation") {
                    // Collect until next empty line or heading
                    while j < lines.len() {
                        let l = lines[j].trim();
                        if l.starts_with('#') || l.starts_with("```") || l.starts_with("---") || l.starts_with("|") {
                            break;
                        }
                        if !explanation.is_empty() { explanation.push(' '); }
                        explanation.push_str(l);
                        j += 1;
                    }
                }
                break;
            }

            blocks.push(MermaidBlock {
                index: block_idx,
                code: code.trim().to_string(),
                title,
                explanation: explanation.trim().to_string(),
            });
            block_idx += 1;
        }
        i += 1;
    }

    blocks
}

/// Known projects in workspace
fn known_projects(workspace: &Path) -> Vec<(&str, &str, &str, &str)> {
    // (dir_name, display_name, version, icon, tech)
    vec![
        ("black-duck-security-scan-2.8.0", "Black Duck Security Scan", "2.8.0", "🔒"),
        ("clonedx-core-java-12.1.0", "CycloneDX Core Java", "12.1.0", "☕"),
        ("cyclonedx-cli-0.30.0", "CycloneDX CLI", "0.30.0", "⌨️"),
        ("cyclonedx-gradle-plugin-3.2.0", "CycloneDX Gradle Plugin", "3.2.0", "🐘"),
        ("cyclonedx-tauri-ui", "CycloneDX Tauri UI", "0.3.0", "🖥️"),
        ("tracee-33.33.34", "Tracee (Aqua Security)", "33.33.34", "🔬"),
        ("trivy-0.69.3", "Trivy (Aqua Security)", "0.69.3", "🔍"),
    ]
}

fn tech_for(dir: &str) -> &str {
    match dir {
        d if d.contains("java") => "Java / Maven",
        d if d.contains("cli") => ".NET / C#",
        d if d.contains("gradle") => "Java / Gradle",
        d if d.contains("tauri") => "Rust / React / Tauri",
        d if d.contains("tracee") => "Go / eBPF",
        d if d.contains("trivy") => "Go",
        d if d.contains("black-duck") => "Node.js / TypeScript",
        _ => "Unknown",
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn scan_architectures(workspace_path: String) -> Result<Vec<ArchProject>, String> {
    let workspace = Path::new(&workspace_path);
    if !workspace.exists() {
        return Err(format!("Workspace not found: {}", workspace_path));
    }

    let projects_info = known_projects(workspace);
    let mut projects = Vec::new();

    for (dir_name, display_name, version, icon) in &projects_info {
        let project_path = workspace.join(dir_name);
        let arch_dir = project_path.join("docs").join("Arch");
        let has_arch = arch_dir.exists();

        let mut files = Vec::new();
        if has_arch {
            if let Ok(entries) = std::fs::read_dir(&arch_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e == "md") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let mermaid_blocks = extract_mermaid_blocks(&content);
                            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                            files.push(ArchFile {
                                name: path.file_name().unwrap().to_string_lossy().to_string(),
                                path: path.to_string_lossy().to_string(),
                                size_bytes: size,
                                content,
                                mermaid_blocks,
                            });
                        }
                    }
                }
            }
        }

        // Sort files: ARCHITECTURE.md first
        files.sort_by(|a, b| {
            if a.name == "ARCHITECTURE.md" { std::cmp::Ordering::Less }
            else if b.name == "ARCHITECTURE.md" { std::cmp::Ordering::Greater }
            else { a.name.cmp(&b.name) }
        });

        projects.push(ArchProject {
            id: dir_name.to_string(),
            name: display_name.to_string(),
            version: version.to_string(),
            path: project_path.to_string_lossy().to_string(),
            arch_dir: arch_dir.to_string_lossy().to_string(),
            files,
            has_arch,
            icon: icon.to_string(),
            tech: tech_for(dir_name).to_string(),
        });
    }

    Ok(projects)
}

#[tauri::command]
pub fn get_project_links() -> Result<Vec<ProjectLink>, String> {
    Ok(vec![
        ProjectLink { from: "cyclonedx-gradle-plugin-3.2.0".into(), to: "clonedx-core-java-12.1.0".into(), relation: "uses".into(), label: "BomGeneratorFactory, Model classes".into() },
        ProjectLink { from: "cyclonedx-cli-0.30.0".into(), to: "clonedx-core-java-12.1.0".into(), relation: "uses".into(), label: "Shared CycloneDX specification".into() },
        ProjectLink { from: "cyclonedx-tauri-ui".into(), to: "cyclonedx-cli-0.30.0".into(), relation: "invokes".into(), label: "validate, convert, merge via CLI".into() },
        ProjectLink { from: "cyclonedx-tauri-ui".into(), to: "trivy-0.69.3".into(), relation: "invokes".into(), label: "trivy scan via subprocess".into() },
        ProjectLink { from: "tracee-33.33.34".into(), to: "cyclonedx-tauri-ui".into(), relation: "inspires".into(), label: "Registry, Pipeline, Policy (Phases 5-9)".into() },
        ProjectLink { from: "black-duck-security-scan-2.8.0".into(), to: "cyclonedx-tauri-ui".into(), relation: "inspires".into(), label: "DAG, SARIF, Export (Phases 1-4)".into() },
        ProjectLink { from: "cyclonedx-tauri-ui".into(), to: "clonedx-core-java-12.1.0".into(), relation: "uses".into(), label: "Schema resources, license DB".into() },
    ])
}
