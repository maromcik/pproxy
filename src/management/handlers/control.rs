use crate::error::AppError;
use crate::management::forms::control::ControlParams;
use crate::management::monitoring::monitor::Monitors;
use crate::management::templates::templates::ControlPageTemplate;
use crate::management::utils::call_script;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse};
use itertools::Itertools;
use std::sync::atomic::Ordering;
use tokio::time::Instant;
use tracing::{info, warn};

pub async fn control_monitor(
    Path(name): Path<String>,
    Query(params): Query<ControlParams>,
    State(monitors): State<Monitors>,
) -> Result<impl IntoResponse, AppError> {
    let monitor = monitors
        .get(&name)
        .ok_or(AppError::RequestError("monitor not found".to_string()))?;

    let message = match params.action.as_deref() {
        Some("resume") => {
            monitor.wake_up.store(true, Ordering::Release);
            let msg = "admin: upstream waking up";
            info!("{msg}");
            Some(msg.to_string())
        }
        Some("suspend") => {
            if monitor.suspending.load(Ordering::Acquire) {
                let msg = "admin: upstream already suspending";
                warn!("{msg}");
                Some(msg.to_string())
            } else {
                match call_script(&monitor.commands.suspend_command).await {
                    Ok(_) => {
                        let msg = "admin: upstream suspending";
                        info!("{msg}");
                        monitor.suspending.store(true, Ordering::Release);
                        Some(msg.to_string())
                    }
                    Err(e) => {
                        let msg = format!("admin: upstream suspend error: {e}");
                        warn!("{msg}");
                        Some(msg)
                    }
                }
            }
        }
        Some("status") => {
            if let Some(stat_command) = &monitor.commands.status_command {
                match call_script(stat_command).await {
                    Ok(out) => Some(format!("{}", out)),
                    Err(e) => Some(format!("Failed to execute command: {}", e)),
                }
            } else {
                Some("No status command configured".to_string())
            }
        }
        Some("enable") => {
            monitor.auto_suspend_enabled.store(true, Ordering::Release);
            {
                let mut timer = monitor.timer.write().await;
                *timer = Instant::now();
            }
            info!("auto-suspend: enabled");
            Some("Auto-suspend enabled.".to_string())
        }
        Some("disable") => {
            monitor.auto_suspend_enabled.store(false, Ordering::Release);
            info!("auto-suspend: disabled");
            Some("Auto-suspend disabled.".to_string())
        }
        Some(_) => return Err(AppError::RequestError("unknown action".to_string())),
        None => None,
    };

    let logs = monitor.logs.read().await.clone();
    let logs = logs
        .into_iter()
        .sorted_by_key(|(_, (d, _))| *d)
        .map(|(k, (d, l))| (k.to_string(), (d.to_string(), l)))
        .collect_vec();

    let elapsed = monitor.timer.read().await.elapsed();
    let time_monitoring = monitor.time_monitoring.read().await;
    let tmpl = ControlPageTemplate {
        message,
        enabled: monitor.auto_suspend_enabled.load(Ordering::Relaxed),
        suspended: monitor.suspended.load(Ordering::Relaxed),
        waking_up: monitor.wake_up.load(Ordering::Relaxed),
        suspending: monitor.suspending.load(Ordering::Relaxed),
        limit: format!("{:?}", monitor.limit),
        elapsed: format!("{:.2?}", elapsed),
        active_time: format!(
            "{:.2?} m",
            time_monitoring.active_time.as_secs() as f64 / 60_f64
        ),
        suspended_time: format!(
            "{:.2?} m",
            time_monitoring.suspended_time.as_secs() as f64 / 60_f64
        ),
        logs,
    };

    let body = tmpl.render()?;
    Ok(Html(body))
}
