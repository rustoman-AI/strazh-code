use crate::engine::artifact::ArtifactRef;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ══════════════════════════════════════════════════════
//  ArtifactStore trait
// ══════════════════════════════════════════════════════

pub trait ArtifactStore: Send + Sync {
    /// Store an artifact at the given path
    fn put(&self, artifact: &ArtifactRef, path: &Path) -> io::Result<PathBuf>;

    /// Retrieve the path for an artifact
    fn get(&self, artifact: &ArtifactRef) -> Option<PathBuf>;

    /// Check if an artifact exists
    fn exists(&self, artifact: &ArtifactRef) -> bool;

    /// Compute SHA-256 hash of an artifact's content
    fn hash(&self, artifact: &ArtifactRef) -> Option<String>;

    /// List all stored artifacts
    fn list(&self) -> Vec<ArtifactRef>;
}

// ══════════════════════════════════════════════════════
//  LocalFsStore — simple workspace/{id} layout
// ══════════════════════════════════════════════════════

pub struct LocalFsStore {
    root: PathBuf,
    index: Mutex<HashMap<String, PathBuf>>,
}

impl LocalFsStore {
    pub fn new(workspace: &Path) -> io::Result<Self> {
        let root = workspace.join("artifacts");
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            index: Mutex::new(HashMap::new()),
        })
    }
}

impl ArtifactStore for LocalFsStore {
    fn put(&self, artifact: &ArtifactRef, path: &Path) -> io::Result<PathBuf> {
        let dest = self.root.join(&artifact.id);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // If source != dest, copy (or link) the file
        if path != dest {
            if path.is_dir() {
                // For directories, just store the reference
                self.index.lock().unwrap().insert(artifact.id.clone(), path.to_path_buf());
                return Ok(path.to_path_buf());
            }
            fs::copy(path, &dest)?;
        }
        self.index.lock().unwrap().insert(artifact.id.clone(), dest.clone());
        Ok(dest)
    }

    fn get(&self, artifact: &ArtifactRef) -> Option<PathBuf> {
        let idx = self.index.lock().unwrap();
        idx.get(&artifact.id).cloned().filter(|p| p.exists())
    }

    fn exists(&self, artifact: &ArtifactRef) -> bool {
        self.get(artifact).is_some()
    }

    fn hash(&self, artifact: &ArtifactRef) -> Option<String> {
        let path = self.get(artifact)?;
        if path.is_dir() {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        let digest = Sha256::digest(&bytes);
        Some(hex::encode(digest))
    }

    fn list(&self) -> Vec<ArtifactRef> {
        // Not easily reconstructable from fs alone, return empty
        vec![]
    }
}

// ══════════════════════════════════════════════════════
//  ContentHashStore — SHA-256 content-addressable
// ══════════════════════════════════════════════════════

pub struct ContentHashStore {
    root: PathBuf,
    /// Maps artifact id → (content hash, stored path)
    index: Mutex<HashMap<String, (String, PathBuf)>>,
}

impl ContentHashStore {
    pub fn new(workspace: &Path) -> io::Result<Self> {
        let root = workspace.join("cas");
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            index: Mutex::new(HashMap::new()),
        })
    }

    fn content_path(&self, hash: &str, ext: &str) -> PathBuf {
        let prefix = &hash[..2.min(hash.len())];
        self.root.join(prefix).join(format!("{}.{}", hash, ext))
    }
}

impl ArtifactStore for ContentHashStore {
    fn put(&self, artifact: &ArtifactRef, path: &Path) -> io::Result<PathBuf> {
        if path.is_dir() {
            // CAS doesn't store directories — fallback to reference
            self.index.lock().unwrap().insert(
                artifact.id.clone(),
                ("dir".to_string(), path.to_path_buf()),
            );
            return Ok(path.to_path_buf());
        }

        let bytes = fs::read(path)?;
        let digest = Sha256::digest(&bytes);
        let hash = hex::encode(digest);

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");

        let dest = self.content_path(&hash, ext);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        if !dest.exists() {
            fs::write(&dest, &bytes)?;
        }

        self.index.lock().unwrap().insert(
            artifact.id.clone(),
            (hash, dest.clone()),
        );

        Ok(dest)
    }

    fn get(&self, artifact: &ArtifactRef) -> Option<PathBuf> {
        let idx = self.index.lock().unwrap();
        idx.get(&artifact.id).map(|(_, p)| p.clone()).filter(|p| p.exists())
    }

    fn exists(&self, artifact: &ArtifactRef) -> bool {
        self.get(artifact).is_some()
    }

    fn hash(&self, artifact: &ArtifactRef) -> Option<String> {
        let idx = self.index.lock().unwrap();
        idx.get(&artifact.id).map(|(h, _)| h.clone())
    }

    fn list(&self) -> Vec<ArtifactRef> {
        vec![]
    }
}
