use log::{error, info, warn};
use tokio::process::Command;

pub async fn call_script(script: &str, ) {
    let output = Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()
        .await;

    match output {
        Ok(o) => {
            if !o.status.success() {
                warn!("Script exited with non-zero status: {}",o.status,);
            }
            info!("STDOUT: {}\n, STDERR:{}", String::from_utf8_lossy(&*o.stdout),
                            String::from_utf8_lossy(&*o.stderr));
        }
        Err(e) => {
            error!("Failed to execute subprocess: {}", e);
        }
    }
}