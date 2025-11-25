use crate::ServerState;
use crate::utils::call_script;
use async_trait::async_trait;
use log::info;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::Instant;
use tracing::debug;

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
        let mut peer = Box::new(HttpPeer::new(&self.upstream_addr, false, "".to_string()));
        peer.options.connection_timeout = Some(Duration::from_secs(30));
        Ok(peer)
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        if self.state.auto_suspend_enabled.load(Ordering::Acquire)
            && self.state.suspended.load(Ordering::Acquire) {
            if !self.state.waking.swap(true, Ordering::AcqRel) {
                info!("traffic detected: waking up upstream");
                let _ = call_script(&self.state.commands.wake).await;
                self.state.suspended.store(false, Ordering::Release);
                self.state.waking.store(false, Ordering::Release);
                let mut timer = self.state.timer.write().await;
                *timer = Instant::now();
                info!("upstream woke up: timer reset");
            } else {
                while self.state.suspended.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    debug!("waiting for another request to wake up upstream");
                }
            }
        } else {
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            debug!("upstream running: timer reset")
        }

        Ok(false)
    }
}
