use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use async_trait::async_trait;
use log::info;
use pingora::lb::LoadBalancer;
use pingora::prelude::{HttpPeer, ProxyHttp, RoundRobin, Session};
use pingora::server::{ListenFds, ShutdownWatch};
use pingora::services::Service;
use tokio::sync::RwLock;
use tokio::time::Instant;
use crate::utils::call_script;

pub struct LB(Arc<LoadBalancer<RoundRobin>>);

pub struct ServerState {
    pub timer: RwLock<Instant>,
    pub suspended: AtomicBool,
    pub limit: Duration,
    pub suspend_command: String,
    pub wake_command: String,
    pub waking: AtomicBool
}


pub struct ImmichProxy {
    pub upstream_addr: String,
    pub state: Arc<ServerState>,
}

#[async_trait]
impl ProxyHttp for ImmichProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let mut peer = Box::new(HttpPeer::new(
            &self.upstream_addr,
            false,
            "".to_string(),
        ));
        peer.options.connection_timeout = Some(Duration::from_secs(20));
        peer.options.read_timeout = Some(Duration::from_secs(20));
        Ok(peer)
    }


    async fn request_filter(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let suspended = self.state.suspended.load(Ordering::Relaxed);
        if suspended {
            if !self.state.waking.swap(true, Ordering::SeqCst) {
                info!("Traffic detected! Waking system up (First Responder)...");
                call_script(&self.state.wake_command).await;
                self.state.suspended.store(false, Ordering::SeqCst);
                self.state.waking.store(false, Ordering::SeqCst);
                let mut timer = self.state.timer.write().await;
                *timer = Instant::now();
            } else {
                while self.state.suspended.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        else {
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
        }

        Ok(false)
    }
}

pub struct MonitorService {
    pub state: Arc<ServerState>,
}

#[async_trait]
impl Service for MonitorService {
    async fn start_service(&mut self, fds: Option<ListenFds>, shutdown: ShutdownWatch, listeners_per_fd: usize) {
        info!("Background Monitor Service Started");
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            if !self.state.suspended.load(Ordering::Relaxed) {
                let last_activity = self.state.timer.read().await;
                if last_activity.elapsed() > self.state.limit {
                    drop(last_activity);

                    info!("Timeout reached ({:?}). Suspending system...", self.state.limit);
                    call_script(&self.state.suspend_command).await;

                    self.state.suspended.store(true, Ordering::Relaxed);
                }
            }
        }
    }


    fn name(&self) -> &str {
        "ActivityMonitor"
    }
}