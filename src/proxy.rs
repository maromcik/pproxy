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
use pingora::protocols::l4::socket::SocketAddr;
use pingora::{Error, HTTPStatus};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, error, warn};

pub struct PingoraProxy {
    pub blocklist_url: String,
    pub geo_api_url: String,
    pub state: Arc<ServerState>,
    pub servers: Servers,
    pub geo_fence: RwLock<HashMap<IpAddr, GeoData>>,
    pub geo_api_lock: Mutex<()>,
    pub blocked_ips: RwLock<HashSet<IpAddr>>,
}

#[derive(Debug)]
struct RequestMetadata {
    user_agent: String,
    client_ip: IpAddr,
    host: String,
    method: String,
    uri: String,
}

impl Display for RequestMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -- {} {}{} '{}'",
            self.client_ip, self.method, self.host, self.uri, self.user_agent
        )
    }
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

        let client_addr = session
            .client_addr()
            .map(|addr| match addr {
                SocketAddr::Inet(ip) => ip.ip().to_string(),
                SocketAddr::Unix(_) => String::new(),
            })
            .unwrap_or_default();

        let client_ip = session
            .req_header()
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .unwrap_or_else(|| client_addr);
        debug!("Client IP: {}", client_ip);

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
    async fn add_ip_to_blocklist(&self, data: &BlocklistIp) {
        if self.blocked_ips.read().await.contains(&data.ip.ip()) {
            info!("BLOCKLIST:DUPLICATE: {} already in the blocklist", data.ip);
            return;
        }

        let client = Client::new();

        match client.post(&self.blocklist_url).json(&data).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!("BLOCKLIST:ADDED; {}", data.ip);
                    self.blocked_ips.write().await.insert(data.ip.ip());
                } else {
                    warn!(
                        "BLOCKLIST:FAILED; adding IP {} failed with status code: {}",
                        data.ip,
                        resp.status()
                    );
                }
            }
            Err(e) => error!("BLOCKLIST:ERROR; adding IP {} failed with error: {}", data.ip, e),
        };
    }

    fn is_geo_data_blocked(&self, geo_data: &GeoData, server: &ServerConfig) -> bool {
        let country_allowed = server
            .geo_fence_country_allowlist
            .as_ref()
            .is_none_or(|geo| geo.contains(geo_data.country_code2.as_str()));
        let isp_blocked = server
            .geo_fence_isp_blocklist
            .as_ref()
            .is_some_and(|geo| geo.contains(geo_data.isp.as_str()));
        !country_allowed || isp_blocked
    }

    async fn is_blocked_ip_geolocation(
        &self,
        metadata: &RequestMetadata,
        server: &ServerConfig,
    ) -> Result<bool, AppError> {
        if server.geo_fence_isp_blocklist.is_none() && server.geo_fence_country_allowlist.is_none()
        {
            debug!("empty geo fence allowlist");
            return Ok(false);
        };

        match metadata.client_ip {
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
        if let Some(geo_data) = self.geo_fence.read().await.get(&metadata.client_ip) {
            debug!("geolocation cache hit: {:?}", geo_data);
            return Ok(self.is_geo_data_blocked(geo_data, server));
        }
        {
            let _lock = self.geo_api_lock.lock().await;
            let client = Client::builder().timeout(Duration::from_secs(3)).build()?;

            let data = client
                .get(format!("{}{}", self.geo_api_url, metadata.client_ip))
                .send()
                .await?
                .json::<GeoData>()
                .await
                .map_err(|e| AppError::ParseError(format!("{e}")))?;

            let mut fence = self.geo_fence.write().await;
            let geo_data = fence.entry(metadata.client_ip).or_insert(data);
            let blocked = self.is_geo_data_blocked(geo_data, server);
            if blocked {
                warn!("BLOCKED:GEO; LOC <{geo_data}>; REQ <{metadata}>");
                let blocklist_data = BlocklistIp {
                    ip: IpNetwork::from(geo_data.ip),
                    country_code: Some(geo_data.country_code2.clone()),
                    isp: Some(geo_data.isp.clone()),
                    user_agent: None,
                };
                self.add_ip_to_blocklist(&blocklist_data).await;
            } else {
                info!("ALLOWED:GEO; LOC: <{geo_data}>; REQ <{metadata}>");
            }

            Ok(blocked)
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
                let blocklist_data = BlocklistIp {
                    ip: IpNetwork::from(metadata.client_ip),
                    country_code: None,
                    isp: None,
                    user_agent: Some(metadata.user_agent.clone()),
                };
                self.add_ip_to_blocklist(&blocklist_data).await;
                warn!("BLOCKED:UA; {metadata}");
                return true;
            }
        }

        match self.is_blocked_ip_geolocation(metadata, server).await {
            Ok(blocked) if !blocked => false,
            Err(e) => {
                error!("{e}");
                true
            }
            _ => {
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
            info!("BLOCKED:REQ: {metadata}");
            return Ok(true);
        }

        let message = match (
            server.suspending,
            self.state.auto_suspend_enabled.load(Ordering::Acquire),
            self.state.suspended.load(Ordering::Acquire),
        ) {
            (true, true, true) => {
                info!("REQ:ENABLED:RESUMING: {metadata}");
                self.state.logs.write().await.insert(
                    metadata.client_ip,
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        format!("ENABLED:RESUMING: {metadata}")
                    ),
                );
                self.state.wake_up.store(true, Ordering::Release);
                "The server is starting, the page will be refreshing automatically until you are redirected to immich/jellyfin. If not, try refreshing the page manually after about 10 seconds."
            }
            (true, false, true) => {
                info!("REQ:DISABLED:ATTEMPT: {metadata}");
                self.state.logs.write().await.insert(
                    metadata.client_ip,
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        format!("DISABLED:ATTEMPT: {metadata}")
                    ),
                );
                "Auto suspend/wake up is disabled, please contact the administrator."
            }
            (true, _, _) => {
                info!("REQ:TRACKER_UPDATED: {metadata}");
                let mut timer = self.state.timer.write().await;
                *timer = Instant::now();
                return Ok(false);
            }
            (false, _, _) => {
                info!("REQ:NO_TRACKER: {metadata}");
                return Ok(false)
            },
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
