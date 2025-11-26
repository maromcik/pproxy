use crate::templates::PublicPageTemplate;
use crate::{ServerState, Upstreams};
use askama::Template;
use async_trait::async_trait;
use log::info;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::{Error, HTTPStatus};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::Instant;
use tracing::debug;

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

        peer.options.connection_timeout = Some(Duration::from_secs(120));
        Ok(peer)
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        if self.state.auto_suspend_enabled.load(Ordering::Acquire)
            && self.state.suspended.load(Ordering::Acquire)
        {
            info!(
                "traffic detected: {:?} -- {:?} {:?} {:?}; User-Agent: {:?}",
                session
                    .req_header()
                    .headers
                    .get("X-Forwarded-For")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default(),
                session.req_header().method.as_str(),
                session
                    .req_header()
                    .headers
                    .get("Host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default(),
                session.req_header().uri.path(),
                session
                    .req_header()
                    .headers
                    .get("User-Agent")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default(),
            );

            self.state.wake_up.store(true, Ordering::Release);
            let tmpl = PublicPageTemplate {
                message: Some("The server is starting, please refresh this page".to_string()),
                enabled: self.state.auto_suspend_enabled.load(Ordering::Relaxed),
                suspended: self.state.suspended.load(Ordering::Relaxed),
                waking_up: self.state.wake_up.load(Ordering::Relaxed),
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
            return Ok(true);
        } else {
            let mut timer = self.state.timer.write().await;
            *timer = Instant::now();
            debug!("upstream running: timer reset")
        }

        Ok(false)
    }
}
