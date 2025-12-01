use crate::error::AppError;
use crate::geo::{CountryCode, GeoData};
use crate::templates::PublicPageTemplate;
use crate::{ServerState, Upstreams};
use askama::Template;
use async_trait::async_trait;
use log::info;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::{Error, HTTPStatus};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, error, warn};

pub struct SuspendProxy {
    pub upstreams: Upstreams,
    pub state: Arc<ServerState>,
    pub user_agent_blocklist: HashSet<String>,
    pub geo_fence_allowlist: HashSet<IpAddr>,
    pub geo_fence: RwLock<HashMap<IpAddr, CountryCode>>,
}

impl SuspendProxy {
    pub async fn is_blocked_ip_geolocation(&self, ip: &str) -> Result<bool, AppError> {
        let ip = ip.parse::<IpAddr>()?;
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    return Ok(false);
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unique_local() {
                    return Ok(false);
                }
            }
        }
        debug!("geolocating IP: {:?}", ip);
        if self.geo_fence_allowlist.contains(&ip) {
            debug!("geolocation allowlist hit: {:?}", ip);
            return Ok(true);
        }

        if let Some(code) = self.geo_fence.read().await.get(&ip) {
            debug!("geolocation cache hit: {:?}", code);
            return Ok(code.is_allowed());
        }

        let data = reqwest::get(format!("https://api.iplocation.net?ip={}", ip))
            .await?
            .json::<GeoData>()
            .await
            .map_err(|e| AppError::ParseError(format!("{e}")))?;

        info!("geolocation request data: {:?}", data);
        let mut fence = self.geo_fence.write().await;
        let country = fence.entry(ip).or_insert(data.country_code2);
        Ok(country.is_allowed())
    }
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
        let user_agent = session
            .req_header()
            .headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();

        let client = session
            .req_header()
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();

        let host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();

        match self.is_blocked_ip_geolocation(client).await {
            Ok(blocked) if blocked => {
                warn!("blocked IP: {client}, Host: {host}, User-Agent: {user_agent}");
                return Ok(true);
            }
            Err(e) => {
                error!("{e}");
                return Ok(true);
            },
            _ => {}
        }

        if self.user_agent_blocklist.iter().any(|ua| {
            user_agent
                .to_lowercase()
                .contains(ua.to_lowercase().as_str())
        }) {
            return Ok(true);
        }

        let message = match (
            self.state.auto_suspend_enabled.load(Ordering::Acquire),
            self.state.suspended.load(Ordering::Acquire),
        ) {
            (true, true) => {
                let msg = format!(
                    "traffic detected: {:?} -- {:?} {:?} {:?}; User-Agent: {:?}",
                    client,
                    session.req_header().method.as_str(),
                    host,
                    session.req_header().uri.path(),
                    user_agent
                );
                info!("{msg}");
                self.state.logs.lock().await.insert(
                    client.into(),
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        msg,
                    ),
                );
                self.state.wake_up.store(true, Ordering::Release);
                "The server is starting, the page will be refreshing automatically until you are redirected to immich/jellyfin. If not, try refreshing the page manually after about 10 seconds."
            }
            (false, true) => "Auto suspend/wake up is disabled, please contact the administrator.",
            _ => {
                let mut timer = self.state.timer.write().await;
                *timer = Instant::now();
                debug!("upstream running: timer reset");
                return Ok(false);
            }
        };

        let tmpl = PublicPageTemplate {
            message: Some(message.to_string()),
            enabled: self.state.auto_suspend_enabled.load(Ordering::Relaxed),
            suspended: self.state.suspended.load(Ordering::Relaxed),
            suspending: self.state.suspending.load(Ordering::Relaxed),
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
        Ok(true)
    }
}
