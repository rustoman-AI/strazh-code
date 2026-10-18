use crate::security::SandboxProvider;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::process::Command;

/// Linux sandboxing implementation using `bubblewrap` (`bwrap`).
/// Wraps standard commands to execute inside a strict user namespace,
/// removing network access and locking down mounts.
#[derive(Debug, Clone, Default)]
pub struct BubblewrapSandbox;

impl BubblewrapSandbox {
    pub fn new() -> Result<Self, String> {
        if Self::is_installed() {
            Ok(Self)
        } else {
            Err("Bubblewrap (`bwrap`) is not installed on the system.".into())
        }
    }

    fn is_installed() -> bool {
        std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl SandboxProvider for BubblewrapSandbox {
    fn run_sandboxed<'a>(
        &'a self,
        cmd: String,
        args: Vec<String>,
        workspace: PathBuf,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut bwrap_cmd = Command::new("bwrap");
            bwrap_cmd.args([
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64",
                "--ro-bind", "/bin", "/bin",
                "--dev", "/dev",
                "--proc", "/proc",
                "--bind", "/tmp", "/tmp",
                "--unshare-all",        // Isolate namespaces (no net)
                "--die-with-parent",    // Kill children if we die
            ]);

            // Bind the designated workspace for Read/Write
            let ws_str = workspace.to_string_lossy();
            bwrap_cmd.arg("--bind");
            bwrap_cmd.arg(&*ws_str);
            bwrap_cmd.arg(&*ws_str);

            bwrap_cmd.arg("--");
            bwrap_cmd.arg(&cmd);
            bwrap_cmd.args(&args);

            let output = bwrap_cmd.output().await.map_err(|e| e.to_string())?;

            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                let err = String::from_utf8_lossy(&output.stderr).to_string();
                Err(format!("Sandbox execution failed [{}]: {}", output.status, err))
            }
        })
    }
}
