use crate::ServerState;
use crate::utils::call_script;
use async_trait::async_trait;
use log::info;
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

        let mut message = "".to_string();
        if path == "/enable" {
            self.state
                .auto_suspend_enabled
                .store(true, Ordering::Release);
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            info!("auto-suspend: enabled");
            message = "Auto-suspend ENABLED.".to_string();
        } else if path == "/disable" {
            self.state
                .auto_suspend_enabled
                .store(false, Ordering::Release);
            info!("auto-suspend: disabled");
            message = "Auto-suspend DISABLED.".to_string();
        } else if path == "/status" {
            if let Some(stat_command) = &self.state.commands.status
                && let Ok(out) = call_script(stat_command).await
            {
                message = out;
            }
        }  else if path == "/start" {
            let _ = call_script(&self.state.commands.wake).await;
            self.state.suspended.store(false, Ordering::Release);
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            info!("upstream woke up: timer reset");
            message = "Server woke up".to_string();
        } else if path == "/stop" {
            let _ = call_script(&self.state.commands.suspend).await;
            self.state.suspended.store(true, Ordering::Release);
            info!("upstream shutdown: timer reset");
            message = "Server woke up".to_string();
        }

        let enabled = self.state.auto_suspend_enabled.load(Ordering::Acquire);
        let suspended = self.state.suspended.load(Ordering::Acquire);
        let limit = self.state.limit;
        message.push_str(
            format!(
                "\nAuto-Suspend: {}\nSystem Suspended: {}\nLimit: {:?}",
                enabled, suspended, limit
            )
            .as_str(),
        );

        let bytes = message.as_bytes().to_vec();
        let mut response = ResponseHeader::build(200, Some(bytes.len()))?;
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
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        info!("Background Monitor Service Started");

        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("Shutdown signal received. Stopping ActivityMonitor...");
                    break;
                }

                _ = interval.tick() => {
                    if self.state.auto_suspend_enabled.load(Ordering::Acquire)
                       && !self.state.suspended.load(Ordering::Acquire) {
                        let last_activity = self.state.timer.read().await;
                        if last_activity.elapsed() > self.state.limit {
                            let _ = call_script(&self.state.commands.suspend).await;
                            self.state.suspended.store(true, Ordering::Release);
                            info!("timeout reached: upstream suspended");
                        }
                        if call_script(&self.state.commands.check).await.is_err() {
                            info!("check command failed: setting suspend=true; the next request should wake up again");
                            self.state.suspended.store(true, Ordering::Release);
                        }
                    }
                }
            }
        }

        info!("ActivityMonitor exited cleanly");
    }

    fn name(&self) -> &str {
        "ActivityMonitor"
    }
}
