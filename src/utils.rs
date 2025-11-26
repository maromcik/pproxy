use crate::error::AppError;
use log::{debug, error};
use tokio::process::Command;

pub async fn call_script(script: &str) -> Result<String, AppError> {
    let output = Command::new("bash").arg("-c").arg(script).output().await;

    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&*o.stdout);
            let err = String::from_utf8_lossy(&*o.stderr);
            if !o.status.success() {
                debug!(
                    "script {} exited with non-zero status: {}",
                    script, o.status
                );
                return Err(AppError::CommandError(format!("script: {script} failed; {err}")));
            }
            debug!("script: {} STDOUT: {}", script, out);
            debug!("script: {} STDERR: {}", script, err);
            Ok(out.to_string())
        }
        Err(e) => {
            error!("failed to execute subprocess: {}", e);
            Err(AppError::CommandError(e.to_string()))
        }
    }
}
