use git2::{Repository, Signature, Oid, Commit};
use std::path::Path;
use anyhow::{Context, Result};

use crate::actor_registry::{SwarmBus, SwarmEvent};
use std::sync::Arc;

pub struct GitAgent {
    pub bus: Arc<SwarmBus>,
}

impl GitAgent {
    pub fn new(bus: Arc<SwarmBus>) -> Self {
        Self { bus }
    }

    pub async fn run(&self) {
        let mut rx = self.bus.subscribe();

        self.bus.publish(SwarmEvent::Log {
            agent: "GitAgent".into(),
            message: "GitAgent started. Monitoring for patched files...".into(),
        });

        // Use spawn_blocking for git2 sync operations when events arrive
        while let Ok(event) = rx.recv().await {
            if let SwarmEvent::FilePatched { node_id: _, vuln_id, file_path } = event {
                self.bus.publish(SwarmEvent::Log {
                    agent: "GitAgent".into(),
                    message: format!("Received FilePatched for {}. Committing changes...", vuln_id),
                });

                let vuln_id_cloned = vuln_id.clone();
                let file_path_cloned = file_path.clone();
                let bus_cloned = Arc::clone(&self.bus);

                tokio::task::spawn_blocking(move || {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                        
                    let branch_name = format!("strazh-heal/{}-{}", vuln_id_cloned, timestamp);
                    let commit_msg = format!("fix(security): automated remediation for {} [Strazh + Nemotron]", vuln_id_cloned);

                    match Self::create_and_checkout_branch(&branch_name) {
                        Ok(repo) => {
                            match Self::stage_and_commit(&repo, &file_path_cloned, &commit_msg) {
                                Ok(oid) => {
                                    bus_cloned.publish(SwarmEvent::GitCommitCreated {
                                        node_id: "global".into(),
                                        vuln_id: vuln_id_cloned.clone(),
                                        commit_hash: format!("{}", oid),
                                        branch: branch_name,
                                    });
                                    bus_cloned.publish(SwarmEvent::Log {
                                        agent: "GitAgent".into(),
                                        message: format!("✅ Automatically committed fix for {} to Git", vuln_id_cloned),
                                    });
                                }
                                Err(e) => {
                                    bus_cloned.publish(SwarmEvent::Log {
                                        agent: "GitAgent".into(),
                                        message: format!("Failed to create git commit: {}", e),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            bus_cloned.publish(SwarmEvent::Log {
                                agent: "GitAgent".into(),
                                message: format!("Failed to create git branch: {}", e),
                            });
                        }
                    }
                });
            }
        }
    }

    /// Opens the current directory as a Git repository, creates a new branch, and checks it out.
    pub fn create_and_checkout_branch(branch_name: &str) -> Result<Repository> {
        let repo = Repository::open(".").context("Failed to open local git repository")?;
        
        {
            // Find HEAD and the commit it points to
            let head = repo.head().context("Failed to find HEAD")?;
            let target = head.target().context("HEAD does not point to a valid id")?;
            let commit = repo.find_commit(target).context("Failed to find commit")?;

            // Create the new branch (force=false, so it fails if it exists)
            repo.branch(branch_name, &commit, false)
                .context("Failed to create new branch. Maybe it already exists?")?;

            // Checkout the newly created branch
            let obj = repo.revparse_single(&format!("refs/heads/{}", branch_name))?;
            repo.checkout_tree(&obj, None)?;
        }
        
        repo.set_head(&format!("refs/heads/{}", branch_name))?;

        println!("🌿 GitAgent: Switched to new branch '{}'", branch_name);
        
        Ok(repo)
    }

    /// Stages a modified file and creates a commit with an AI-generated message.
    pub fn stage_and_commit(
        repo: &Repository,
        relative_file_path: &str,
        commit_message: &str,
    ) -> Result<Oid> {
        // 1. Stage the file (git add)
        let mut index = repo.index().context("Failed to open index")?;
        index.add_path(Path::new(relative_file_path)).context("Failed to stage file")?;
        index.write().context("Failed to write index")?;
        
        let oid = index.write_tree().context("Failed to write index tree")?;
        let tree = repo.find_tree(oid).context("Failed to find index tree")?;

        // 2. Prepare the commit signature (Author / Committer)
        let signature = Signature::now("Strazh Agent", "strazh@localhost")
            .context("Failed to craft signature")?;

        // 3. Find HEAD to use as parent for the new commit
        let parent_commit = Self::get_head_commit(repo)?;
        
        // 4. Create the commit
        let commit_id = repo.commit(
            Some("HEAD"), // Update HEAD pointer
            &signature,   // Author
            &signature,   // Committer
            commit_message,
            &tree,
            &[&parent_commit],
        ).context("Failed to create commit")?;

        println!("✅ GitAgent: Committed changes as [{}]", commit_id);
        
        Ok(commit_id)
    }

    fn get_head_commit(repo: &Repository) -> Result<Commit> {
        let head = repo.head().context("Failed to find HEAD")?;
        let target = head.target().context("HEAD missing target")?;
        let commit = repo.find_commit(target).context("Failed to find commit pointing to HEAD")?;
        Ok(commit)
    }
}
