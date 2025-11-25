use crate::{ServerState, Upstreams};
use async_trait::async_trait;
use log::{info};
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::{Error, HTTPStatus};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::Instant;
use tracing::debug;
use crate::utils::call_script;

pub struct SuspendProxy {
    pub upstreams: Upstreams,
    pub state: Arc<ServerState>,
}

#[async_trait]
impl ProxyHttp for SuspendProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let Some(host) = session.req_header().headers.get("Host") else {
            return Err(Error::explain(
                HTTPStatus(404),
                "Endpoint not supported by pproxy",
            ));
        };
        debug!("upstream: {:?}", host);
        let mut peer = if host
            .to_str()
            .map_err(|e| pingora::Error::explain(HTTPStatus(400), format!("{e}")))?
            .starts_with("jellyfin.")
        {
            Box::new(HttpPeer::new(
                &self.upstreams.jellyfin,
                false,
                "".to_string(),
            ))
        } else if host
            .to_str()
            .map_err(|e| pingora::Error::explain(HTTPStatus(400), format!("{e}")))?
            .starts_with("immich.")
        {
            Box::new(HttpPeer::new(&self.upstreams.immich, false, "".to_string()))
        } else {
            return Err(Error::explain(
                HTTPStatus(404),
                "Endpoint not supported by pproxy",
            ));
        };

        peer.options.connection_timeout = Some(Duration::from_secs(30));
        Ok(peer)
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        if self.state.auto_suspend_enabled.load(Ordering::Acquire)
            && self.state.suspended.load(Ordering::Acquire)
        {
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
