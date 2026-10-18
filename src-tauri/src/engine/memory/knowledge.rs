use std::collections::HashMap;

/// A simple struct representing a static knowledge base document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KnowledgeDoc {
    pub id: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
}

pub struct KnowledgeBase {
    docs: HashMap<String, KnowledgeDoc>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        let mut docs = HashMap::new();
        
        // Seed some basic knowledge for the RAG demo
        docs.insert("pci-6-5-1".to_string(), KnowledgeDoc {
            id: "pci-6-5-1".to_string(),
            title: "PCI DSS Requirement 6.5.1".to_string(),
            content: "Injection flaws, particularly SQL injection (SQLi), are addressed in PCI DSS Requirement 6.5.1. Applications must prevent user-supplied data from modifying backend queries. Mitigation strategies include utilizing parameterized queries, prepared statements, and strict input validation/sanitization. AI Agents must prioritize these fixes over string-escape mechanisms.".to_string(),
            tags: vec!["pci".to_string(), "compliance".to_string(), "sqli".to_string(), "sql-injection".to_string(), "security".to_string()],
        });

        docs.insert("buffer-overflow".to_string(), KnowledgeDoc {
            id: "buffer-overflow".to_string(),
            title: "CWE-119: Memory Buffer Overflow".to_string(),
            content: "A buffer overflow occurs when a program attempts to put more data in a memory buffer than it can hold, leading to memory corruption. In unsafe Rust, this occurs during unchecked pointer arithmetic or FFI boundaries. Mitigation requires exclusively using Rust's safe abstractions, checking slice bounds, or utilizing standard library collections dynamically, entirely removing `unsafe` blocks where possible.".to_string(),
            tags: vec!["cwe".to_string(), "memory-safety".to_string(), "unsafe-rust".to_string(), "buffer-overflow".to_string()],
        });

        docs.insert("supply-chain-cra".to_string(), KnowledgeDoc {
            id: "supply-chain-cra".to_string(),
            title: "EU CRA: Software Supply Chain".to_string(),
            content: "Under the upcoming European Cyber Resilience Act (CRA), manufacturers must guarantee products with digital elements have no known exploitable vulnerabilities upon release. The Build and AST graphs are required to map provenance up the supply chain. If an upstream crate is compromised (e.g., via Typosquatting), the blast radius graph node flags the entire artifact as a CRA Compliance Violation until the dependency is pinned to a known good version or quarantined.".to_string(),
            tags: vec!["cra".to_string(), "europe".to_string(), "supply-chain".to_string(), "dependencies".to_string(), "governance".to_string()],
        });

        Self { docs }
    }

    /// Basic TF-IDF / Tag-based retrieval mockup mimicking Vector Search
    pub fn query(&self, prompt: &str) -> Vec<KnowledgeDoc> {
        let lower = prompt.to_lowercase();
        let tokens: Vec<&str> = lower.split_whitespace().collect();

        let mut scored_docs: Vec<(f64, &KnowledgeDoc)> = self.docs.values().map(|doc| {
            let mut score = 0.0;
            // Tag matching (high weight)
            for tag in &doc.tags {
                if tokens.contains(&tag.as_str()) || lower.contains(tag) {
                    score += 5.0;
                }
            }
            // Title matching
            if lower.contains(&doc.title.to_lowercase()) {
                score += 3.0;
            }
            // Full-text hit
            for token in &tokens {
                if token.len() > 3 && doc.content.to_lowercase().contains(token) {
                    score += 1.0;
                }
            }
            (score, doc)
        }).collect();

        // Sort descending by score
        scored_docs.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Return top results (filter 0s)
        scored_docs.into_iter()
            .filter(|(score, _)| *score > 0.0)
            .map(|(_, doc)| doc.clone())
            .take(3)
            .collect()
    }
}
