pub mod audit;
pub mod canary_guard;
pub mod estop;
pub mod leak_detector;
pub mod playbooks;
pub mod prompt_guard;
pub mod sandboxing;
pub mod syscall_anomaly;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

pub trait SandboxProvider: Send + Sync {
    fn run_sandboxed<'a>(
        &'a self,
        cmd: String,
        args: Vec<String>,
        workspace: PathBuf,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}
