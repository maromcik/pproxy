use crate::ServerState;
use crate::templates::ControlPageTemplate;
use crate::utils::call_script;
use askama::Template;
use async_trait::async_trait;
use log::{debug, info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::server::{ListenFds, ShutdownWatch};
use pingora::services::Service;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::Instant;

pub struct ControlService {
    pub state: Arc<ServerState>,
}

#[async_trait]
impl ProxyHttp for ControlService {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(Error::explain(
            HTTPStatus(404),
            "Control endpoint has no upstream",
        ))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path();

        let message = if path == "/enable" {
            self.state
                .auto_suspend_enabled
                .store(true, Ordering::Release);
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            info!("auto-suspend: enabled");
            Some("Auto-suspend enabled.".to_string())
        } else if path == "/disable" {
            self.state
                .auto_suspend_enabled
                .store(false, Ordering::Release);
            info!("auto-suspend: disabled");
            Some("Auto-suspend disabled.".to_string())
        } else if path == "/resume" {
            match call_script(&self.state.commands.wake).await {
                Ok(_) => {
                    self.state.suspended.store(false, Ordering::Release);
                    let mut timer = self.state.timer.write().await;
                    *timer = Instant::now();
                    let msg = "Upstream woke up: timer reset";
                    Some(msg.to_string())
                }
                Err(e) => {
                    let msg = format!("Upstream resume error: {e}");
                    warn!("{msg}");
                    Some(msg)
                }
            }
        } else if path == "/suspend" {
            match call_script(&self.state.commands.suspend).await {
                Ok(_) => {
                    let msg = "Upstream suspended";
                    info!("{msg}");
                    self.state.suspended.store(true, Ordering::Release);
                    Some(msg.to_string())
                }
                Err(e) => {
                    let msg = format!("Upstream suspend error: {e}");
                    warn!("{msg}");
                    Some(msg)
                }
            }
        } else if path == "/status" {
            if let Some(stat_command) = &self.state.commands.status {
                match call_script(stat_command).await {
                    Ok(out) => Some(format!("{}", out)),
                    Err(e) => Some(format!("Failed to execute command: {}", e)),
                }
            } else {
                Some("No status command configured".to_string())
            }
        } else {
            None
        };
        let time_monitoring = self.state.time_monitoring.read().await;
        let tmpl = ControlPageTemplate {
            message,
            enabled: self.state.auto_suspend_enabled.load(Ordering::Relaxed),
            suspended: self.state.suspended.load(Ordering::Relaxed),
            waking_up: self.state.wake_up.load(Ordering::Relaxed),
            limit: format!("{:?}", self.state.limit),
            elapsed: format!("{:.2?}", self.state.timer.read().await.elapsed()),
            active_time: format!("{:.2?} m", time_monitoring.active_time.as_secs() as f64 / 60_f64),
            suspended_time: format!("{:.2?} m", time_monitoring.suspended_time.as_secs() as f64 / 60_f64),
        };

        let Ok(body) = tmpl.render() else {
            return Err(Error::explain(HTTPStatus(500), "Failed to render template"));
        };
        let bytes = body.as_bytes().to_vec();

        let mut response = ResponseHeader::build(200, Some(bytes.len()))?;
        response.insert_header("Content-Type", "text/html; charset=utf-8")?;
        let _ = response.insert_header("Content-Length", bytes.len().to_string());
        session
            .write_response_header(Box::new(response), false)
            .await?;
        session
            .write_response_body(Some(bytes.into()), false)
            .await?;
        Ok(true)
    }
}

pub struct MonitorService {
    pub state: Arc<ServerState>,
}

#[async_trait]
impl Service for MonitorService {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        _shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        info!("Background Monitor Service Started");
        let interval = Duration::from_millis(500);
        loop {
            let wall_time = Instant::now();
            sleep(interval).await;
            if !self.state.auto_suspend_enabled.load(Ordering::Acquire) {
                debug!("auto-suspend disabled: skipping monitoring");
                continue;
            }
            if call_script(&self.state.commands.check).await.is_err() {
                self.state.suspended.store(true, Ordering::Release);
                debug!("check failed: upstream suspended");
            } else {
                self.state.suspended.store(false, Ordering::Release);
                debug!("check succeeded: upstream active");
            }

            if self.state.suspended.load(Ordering::Acquire) {
                if self.state.wake_up.load(Ordering::Acquire) {
                    info!("waking up upstream");
                    while let Err(e) = call_script(&self.state.commands.check).await {
                        info!("error while checking upstream during wake up, waking up again: {}", e);
                    }
                    self.state.suspended.store(false, Ordering::Release);
                    self.state.wake_up.store(false, Ordering::Release);
                    let mut timer = self.state.timer.write().await;
                    *timer = Instant::now();
                    info!("upstream woke up: timer reset");
                }
                self.state.time_monitoring.write().await.suspended_time += wall_time.elapsed();
            } else {
                let last_activity = self.state.timer.read().await;
                if !self.state.wake_up.load(Ordering::Acquire)
                    && last_activity.elapsed() > self.state.limit
                {
                    drop(last_activity);
                    info!("timeout reached: suspending upstream");
                    match call_script(&self.state.commands.suspend).await {
                        Ok(_) => {
                            self.state.suspended.store(true, Ordering::Release);
                            info!("timeout reached: upstream suspended");
                        }
                        Err(e) => {
                            warn!("error while suspending upstream: {}", e);
                        }
                    }
                } else {
                    while let Err(e) = call_script(&self.state.commands.check).await {
                        info!("error while checking upstream that should be active, waking up again: {}", e);
                    }
                }
                self.state.time_monitoring.write().await.active_time += wall_time.elapsed();
            }
        }
    }

    fn name(&self) -> &str {
        "ActivityMonitor"
    }
}
