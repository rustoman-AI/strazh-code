use serde::{Deserialize, Serialize};
use std::fmt;

// ══════════════════════════════════════════════════════
//  ArtifactKind — typed categories for pipeline artifacts
// ══════════════════════════════════════════════════════

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Source code directory or project root
    SourceDir,
    /// Raw CycloneDX SBOM (JSON or XML)
    SBOM,
    /// SBOM that passed validation
    ValidatedSBOM,
    /// Multiple SBOMs merged into one
    MergedSBOM,
    /// Signed BOM (with signature envelope)
    SignedSBOM,
    /// Compliance report (NIST, NTIA, etc.)
    ComplianceReport,
    /// Diff report between two BOMs
    DiffReport,
    /// SARIF 2.1.0 report for CI/CD integration
    SarifReport,
    /// Generic file artifact
    Generic,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactKind::SourceDir => write!(f, "source-dir"),
            ArtifactKind::SBOM => write!(f, "sbom"),
            ArtifactKind::ValidatedSBOM => write!(f, "validated-sbom"),
            ArtifactKind::MergedSBOM => write!(f, "merged-sbom"),
            ArtifactKind::SignedSBOM => write!(f, "signed-sbom"),
            ArtifactKind::ComplianceReport => write!(f, "compliance-report"),
            ArtifactKind::DiffReport => write!(f, "diff-report"),
            ArtifactKind::SarifReport => write!(f, "sarif-report"),
            ArtifactKind::Generic => write!(f, "generic"),
        }
    }
}

// ══════════════════════════════════════════════════════
//  ArtifactRef — typed reference to a pipeline artifact
// ══════════════════════════════════════════════════════

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Unique identifier within the pipeline
    pub id: String,
    /// Typed category
    pub kind: ArtifactKind,
}

impl ArtifactRef {
    pub fn new(id: impl Into<String>, kind: ArtifactKind) -> Self {
        Self { id: id.into(), kind }
    }

    pub fn sbom(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::SBOM)
    }

    pub fn validated(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::ValidatedSBOM)
    }

    pub fn source_dir(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::SourceDir)
    }

    pub fn merged(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::MergedSBOM)
    }

    pub fn compliance(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::ComplianceReport)
    }

    pub fn diff(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::DiffReport)
    }

    pub fn sarif(id: impl Into<String>) -> Self {
        Self::new(id, ArtifactKind::SarifReport)
    }
}

// ══════════════════════════════════════════════════════
//  Type compatibility rules
// ══════════════════════════════════════════════════════

impl ArtifactKind {
    /// Returns true if `self` (output kind) can be consumed as `input_kind`
    pub fn is_compatible_with(&self, input_kind: &ArtifactKind) -> bool {
        match (self, input_kind) {
            // Exact match is always fine
            (a, b) if a == b => true,
            // ValidatedSBOM can be used wherever SBOM is expected
            (ArtifactKind::ValidatedSBOM, ArtifactKind::SBOM) => true,
            // MergedSBOM can be used wherever SBOM is expected
            (ArtifactKind::MergedSBOM, ArtifactKind::SBOM) => true,
            // SignedSBOM can be used wherever SBOM is expected
            (ArtifactKind::SignedSBOM, ArtifactKind::SBOM) => true,
            // ComplianceReport can feed into SarifReport export
            (ArtifactKind::ComplianceReport, ArtifactKind::SarifReport) => true,
            _ => false,
        }
    }
}
