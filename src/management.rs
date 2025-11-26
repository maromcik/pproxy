use crate::ServerState;
use crate::templates::ControlPageTemplate;
use crate::utils::call_script;
use askama::Template;
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

        let message = if path == "/enable" {
            self.state
                .auto_suspend_enabled
                .store(true, Ordering::Release);
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            info!("auto-suspend: enabled");
            Some("Auto-suspend ENABLED.".to_string())
        } else if path == "/disable" {
            self.state
                .auto_suspend_enabled
                .store(false, Ordering::Release);
            info!("auto-suspend: disabled");
            Some("Auto-suspend DISABLED.".to_string())
        } else if path == "/resume" {
            let _ = call_script(&self.state.commands.wake).await;
            self.state.suspended.store(false, Ordering::Release);
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            info!("upstream woke up: timer reset");
            Some("Upstream RESUMED".to_string())
        } else if path == "/suspend" {
            let _ = call_script(&self.state.commands.suspend).await;
            self.state.suspended.store(true, Ordering::Release);
            info!("upstream suspended");
            Some("Upstream SUSPENDED".to_string())
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

        let enabled = self.state.auto_suspend_enabled.load(Ordering::Acquire);
        let suspended = self.state.suspended.load(Ordering::Acquire);
        let limit = self.state.limit;
        let tmpl = ControlPageTemplate {
            message,
            enabled,
            suspended,
            limit: format!("{:?}", limit),
            elapsed: format!("{:?}", self.state.timer.read().await.elapsed()),
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
            if self.state.auto_suspend_enabled.load(Ordering::Acquire)
                && !self.state.suspended.load(Ordering::Acquire)
            {
                let last_activity = self.state.timer.read().await;
                if last_activity.elapsed() > self.state.limit {
                    drop(last_activity);
                    let _ = call_script(&self.state.commands.suspend).await;
                    self.state.suspended.store(true, Ordering::Release);
                    info!("timeout reached: upstream suspended");
                }
                if let Err(e) = call_script(&self.state.commands.check).await {
                    info!("error while checking upstream, waking up again: {}", e);
                    let _ = call_script(&self.state.commands.wake).await;
                }
            } else {
                if self.state.wake_up.load(Ordering::Acquire) {
                    let _ = call_script(&self.state.commands.wake).await;
                    while let Err(e) = call_script(&self.state.commands.check).await {
                        info!("error while checking upstream, waking up again: {}", e);
                        let _ = call_script(&self.state.commands.wake).await;
                    }
                    self.state.suspended.store(false, Ordering::Release);
                    self.state.wake_up.store(false, Ordering::Release);
                    let mut timer = self.state.timer.write().await;
                    *timer = Instant::now();
                    info!("upstream woke up: timer reset");
                }
            }
            sleep(interval).await;
        }
    }

    fn name(&self) -> &str {
        "ActivityMonitor"
    }
}
