use log::{error, info, warn};
use tokio::process::Command;
use crate::error::AppError;

pub async fn call_script(script: &str) -> Result<String, AppError> {
    let output = Command::new("bash").arg("-c").arg(script).output().await;

    match output {
        Ok(o) => {
            if !o.status.success() {
                warn!("Script exited with non-zero status: {}", o.status,);
            }
            let out = String::from_utf8_lossy(&*o.stdout);
            let err = String::from_utf8_lossy(&*o.stderr);
            info!("Script: {} STDOUT: {}", script, out);
            warn!("Script: {} STDERR: {}", script, err);
            Ok(out.to_string())
        }
        Err(e) => {
            error!("Failed to execute subprocess: {}", e);
            Err(AppError::CommandError(e.to_string()))
        }
    }
}
