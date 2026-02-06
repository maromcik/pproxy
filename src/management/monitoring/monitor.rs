use crate::config::CommandConfig;
use crate::management::utils::call_script;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tokio::time::{Instant, sleep};
use tracing::{debug, trace};

pub type Monitors = Arc<HashMap<String, Arc<MonitorState>>>;

#[derive(Default, Clone)]
pub struct TimeMonitoring {
    pub active_time: Duration,
    pub suspended_time: Duration,
}

pub struct MonitorState {
    pub timer: RwLock<Instant>,
    pub suspended: AtomicBool,
    pub limit: Duration,
    pub wake_up: AtomicBool,
    pub suspending: AtomicBool,
    pub auto_suspend_enabled: AtomicBool,
    pub commands: CommandConfig,
    pub time_monitoring: RwLock<TimeMonitoring>,
    pub logs: RwLock<HashMap<IpAddr, (OffsetDateTime, String)>>,
}

impl MonitorState {
    pub fn new(limit: Duration, commands: CommandConfig) -> Self {
        Self {
            timer: Instant::now().into(),
            suspended: Default::default(),
            limit,
            wake_up: Default::default(),
            suspending: Default::default(),
            auto_suspend_enabled: Default::default(),
            commands,
            time_monitoring: Default::default(),
            logs: Default::default(),
        }
    }

    pub async fn monitor_service(monitor: Arc<MonitorState>) {
        info!("Background Monitor Service Started");
        let interval = Duration::from_millis(1000);
        loop {
            let wall_time = Instant::now();
            sleep(interval).await;
            if call_script(&monitor.commands.check_command).await.is_err() {
                monitor.suspended.store(true, Ordering::Release);
                monitor.suspending.store(false, Ordering::Release);
                trace!("check failed: upstream suspended");
            } else {
                monitor.suspended.store(false, Ordering::Release);
                monitor.wake_up.store(false, Ordering::Release);
                trace!("check succeeded: upstream active");
            }

            if !monitor.auto_suspend_enabled.load(Ordering::Acquire) {
                trace!("auto-suspend disabled: skipping monitoring");
                continue;
            }

            if monitor.suspended.load(Ordering::Acquire) {
                if monitor.wake_up.load(Ordering::Acquire) {
                    debug!("waking up upstream");
                    let _ = call_script(&monitor.commands.wake_command).await;
                    let mut timer = monitor.timer.write().await;
                    *timer = Instant::now();
                }
                monitor.time_monitoring.write().await.suspended_time += wall_time.elapsed();
            } else {
                let last_activity = monitor.timer.read().await;
                if last_activity.elapsed() > monitor.limit
                    && !monitor.wake_up.load(Ordering::Acquire)
                    && !monitor.suspending.load(Ordering::Acquire)
                {
                    drop(last_activity);
                    monitor.suspending.store(true, Ordering::Release);
                    info!("timeout reached: suspending upstream");
                    match call_script(&monitor.commands.suspend_command).await {
                        Ok(_) => {
                            info!("timeout reached: upstream suspended");
                        }
                        Err(e) => {
                            warn!("error while suspending upstream: {}", e);
                        }
                    }
                } else {
                    trace!("upstream active: no need to suspend");
                }
                monitor.time_monitoring.write().await.active_time += wall_time.elapsed();
            }
        }
    }
}
