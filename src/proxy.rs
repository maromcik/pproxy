use crate::ServerState;
use crate::blocklist::BlocklistIp;
use crate::config::{ServerConfig, Servers};
use crate::error::AppError;
use crate::geo::GeoData;
use crate::templates::PublicPageTemplate;
use askama::Template;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::info;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::{Error, HTTPStatus};
use reqwest::Client;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

pub struct PingoraProxy {
    pub blocklist_url: String,
    pub geo_api_url: String,
    pub state: Arc<ServerState>,
    pub servers: Servers,
    pub geo_fence: RwLock<HashMap<IpAddr, String>>,
    pub geo_api_lock: Mutex<()>,
}

#[derive(Debug)]
struct RequestMetadata {
    user_agent: String,
    client_ip: IpAddr,
    host: String,
    method: String,
    uri: String,
}

impl RequestMetadata {
    pub fn parse(session: &Session) -> Result<Self, AppError> {
        let user_agent = session
            .req_header()
            .headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .unwrap_or_default();

        let client_ip = session
            .req_header()
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .unwrap_or_default();

        let host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .unwrap_or_default();

        let method = session.req_header().method.as_str().to_string();
        let uri = session.req_header().uri.path().to_string();

        Ok(Self {
            user_agent,
            client_ip: client_ip.parse()?,
            host,
            method,
            uri,
        })
    }
}

impl PingoraProxy {
    async fn add_ip_to_blocklist(&self, ip: IpAddr) {
        let client = Client::new();

        let body = BlocklistIp {
            ip: IpNetwork::from(ip),
        };
        match client
            .post(&self.blocklist_url)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        "error adding IP to blocklist; return code: {}",
                        resp.status()
                    );
                }
            }
            Err(e) => error!("Error adding IP: {ip} to the blocklist {e}"),
        };

        info!("added IP: {ip} to the blocklist");
    }

    async fn is_blocked_ip_geolocation(
        &self,
        ip: IpAddr,
        server: &ServerConfig,
    ) -> Result<bool, AppError> {
        let Some(geo_fence_allowlist) = &server.geo_fence_allowlist else {
            trace!("empty geo fence allowlist");
            return Ok(false);
        };
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
        if let Some(code) = self.geo_fence.read().await.get(&ip) {
            debug!("geolocation cache hit: {:?}", code);
            return Ok(!geo_fence_allowlist.contains(code));
        }
        {
            let _lock = self.geo_api_lock.lock().await;
            let client = Client::builder()
                .timeout(Duration::from_secs(3))
                .build()?;

            let data = client
                .get(format!("{}{}", self.geo_api_url, ip))
                .send()
                .await?
                .json::<GeoData>()
                .await
                .map_err(|e| AppError::ParseError(format!("{e}")))?;

            let mut fence = self.geo_fence.write().await;
            let country_code = data.country_code2.to_lowercase();
            debug!("country code: {country_code}");
            let code = fence.entry(ip).or_insert(country_code);
            info!("geolocation request data: {:?}", data);
            Ok(!geo_fence_allowlist.contains(code))
        }
    }

    async fn is_blocked(&self, metadata: &RequestMetadata, server: &ServerConfig) -> bool {
        if let Some(user_agent_blocklist) = &server.user_agent_blocklist {
            if user_agent_blocklist.iter().any(|ua| {
                metadata
                    .user_agent
                    .to_lowercase()
                    .contains(ua.to_lowercase().as_str())
            }) {
                self.add_ip_to_blocklist(metadata.client_ip).await;
                warn!(
                    "blocked user-agent: {}, Host: {}, User-Agent: {}",
                    metadata.client_ip, metadata.host, metadata.user_agent
                );
                return true;
            }
        }

        match self
            .is_blocked_ip_geolocation(metadata.client_ip, server)
            .await
        {
            Ok(blocked) if !blocked => false,
            Err(e) => {
                error!("{e}");
                true
            }
            _ => {
                self.add_ip_to_blocklist(metadata.client_ip).await;
                warn!(
                    "blocked IP: {}, Host: {}, User-Agent: {}",
                    metadata.client_ip, metadata.host, metadata.user_agent
                );
                true
            }
        }
    }


}

#[async_trait]
impl ProxyHttp for PingoraProxy {
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
                "Server name not supported by pproxy",
            ));
        };
        debug!("upstream: {:?}", host);

        let mut peer =
            if let Some(server_config) = self.servers.get(host.to_str().unwrap_or_default()) {
                Box::new(HttpPeer::new(
                    &server_config.upstream,
                    false,
                    "".to_string(),
                ))
            } else {
                return Err(Error::explain(
                    HTTPStatus(404),
                    "Server name not supported by pproxy",
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
        let metadata = match RequestMetadata::parse(&session) {
            Ok(h) => h,
            Err(e) => {
                error!("{e}");
                return Ok(true);
            }
        };

        let Some(server) = self.servers.get(&metadata.host) else {
            warn!(
                "could not find the server configuration for host: {}",
                metadata.host
            );
            return Ok(true);
        };

        if self.is_blocked(&metadata, server).await {
            info!("blocked request: {:?}", metadata);
            return Ok(true);
        }

        let message = match (
            server.suspending,
            self.state.auto_suspend_enabled.load(Ordering::Acquire),
            self.state.suspended.load(Ordering::Acquire),
        ) {
            (true, true, true) => {
                let msg = format!(
                    "traffic detected: {} -- {} {} {}; User-Agent: {}",
                    metadata.client_ip,
                    metadata.method,
                    metadata.host,
                    metadata.uri,
                    metadata.user_agent,
                );
                info!("{msg}");
                self.state.logs.lock().await.insert(
                    metadata.client_ip,
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        msg,
                    ),
                );
                self.state.wake_up.store(true, Ordering::Release);
                "The server is starting, the page will be refreshing automatically until you are redirected to immich/jellyfin. If not, try refreshing the page manually after about 10 seconds."
            }
            (true, false, true) => {
                "Auto suspend/wake up is disabled, please contact the administrator."
            }
            (false, _, _) => return Ok(false),
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
