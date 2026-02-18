use crate::config::{IpSource, ServerConfig, Servers, WafConfig};
use crate::error::AppError;
use crate::management::monitoring::monitor::Monitors;
use crate::management::templates::templates::PublicPageTemplate;
use crate::proxy::blocklist::BlocklistIp;
use crate::proxy::geo::GeoData;
use askama::Template;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::info;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::TlsAccept;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::{HttpPeer, ProxyHttp, Session, http_proxy_service};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::protocols::tls::TlsRef;
use pingora::server::configuration::ServerConf;
use pingora::tls::ssl;
use pingora::{Error, HTTPStatus, tls};
use regex::Regex;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

#[derive(Debug, Clone)]
pub struct TlsSelector(
    HashMap<String, (Vec<tls::x509::X509>, tls::pkey::PKey<tls::pkey::Private>)>,
);

impl TlsSelector {
    pub fn new(servers: Servers) -> Result<Self, AppError> {
        let mut res = HashMap::new();
        for (sni, server) in servers.0.iter() {
            if let (Some(cert), Some(key)) = (server.cert_path.as_ref(), server.key_path.as_ref()) {
                let cert_bytes = std::fs::read(cert)?;
                let certs = tls::x509::X509::stack_from_pem(&cert_bytes)?;

                let key_bytes = std::fs::read(key)?;
                let key = tls::pkey::PKey::private_key_from_pem(&key_bytes)?;
                res.insert(sni.clone(), (certs, key));
            }
        }

        Ok(Self(res))
    }
}

#[async_trait]
impl TlsAccept for TlsSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let Some(sni_provided) = ssl.servername(ssl::NameType::HOST_NAME) else {
            warn!("No SNI provided");
            return;
        };
        debug!("SNI provided: {}", sni_provided);
        let Some((certs, key)) = self.0.get(
            &sni_provided
                .strip_prefix("www.")
                .unwrap_or(&sni_provided)
                .to_string(),
        ) else {
            warn!("No certificate found for SNI: {}", sni_provided);
            return;
        };

        let Some(cert) = certs.get(0) else {
            warn!(
                "Leaf certificate for SNI: {} could not be loaded",
                sni_provided
            );
            return;
        };

        if let Err(e) = tls::ext::ssl_use_certificate(ssl, cert) {
            error!("Could not add leaf cert: {}", e);
        }

        for (i, cert) in certs.iter().skip(1).enumerate() {
            if let Err(e) = tls::ext::ssl_add_chain_cert(ssl, cert) {
                error!("Could not add intermediate cert {}: {}", i, e);
            }
        }

        if let Err(e) = tls::ext::ssl_use_private_key(ssl, key) {
            error!("Could not set private key: {}", e);
        }
    }
}

pub struct PingoraService {
    pub monitors: Monitors,
    pub servers: Servers,
    pub waf_config: WafConfig,
    pub geo_fence: RwLock<HashMap<IpAddr, GeoData>>,
    pub geo_api_client: Mutex<Client>,
    pub blocked_ips: RwLock<HashSet<IpAddr>>,
    pub geo_cache_writer: mpsc::Sender<GeoData>,
}

impl PingoraService {
    pub fn new(
        monitors: Monitors,
        servers: Servers,
        geo_cache_writer: mpsc::Sender<GeoData>,
        geo_cache_data: HashMap<IpAddr, GeoData>,
        client: Client,
        waf_config: WafConfig,
    ) -> Self {
        Self {
            monitors,
            servers,
            waf_config,
            geo_fence: RwLock::new(geo_cache_data),
            geo_api_client: Mutex::new(client),
            blocked_ips: RwLock::new(HashSet::new()),
            geo_cache_writer,
        }
    }
    pub fn build_service(
        self,
        server_conf: Arc<ServerConf>,
        host: String,
        tls: bool,
    ) -> Result<impl pingora::services::Service, AppError> {
        let selector = Box::new(TlsSelector::new(self.servers.clone())?);
        let mut service = http_proxy_service(&server_conf.clone(), self);

        if tls {
            let tls_settings = TlsSettings::with_callbacks(selector.clone())?;
            service.add_tls_with_settings(host.as_str(), None, tls_settings);
        } else {
            service.add_tcp(host.as_str())
        }

        Ok(service)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProxyContext {
    metadata: Option<RequestMetadata>,
}

#[derive(Debug, Clone)]
struct RequestMetadata {
    user_agent: String,
    client_ip: IpAddr,
    forwarded_ip: Option<IpAddr>,
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
        debug!("Client SocketAddr: {}", client_addr);

        let client_forwarded = session
            .req_header()
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string());
        debug!("Client Forwarded IP: {:?}", client_forwarded);

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
            client_ip: client_addr.parse()?,
            forwarded_ip: client_forwarded.map(|ip| ip.parse().ok()).flatten(),
            host,
            method,
            uri,
        })
    }
}

impl PingoraService {
    async fn add_ip_to_blocklist(&self, data: &BlocklistIp) {
        let Some(blocklist_url) = &self.waf_config.blocklist_url else {
            trace!("Blocklist disabled");
            return;
        };

        if self.blocked_ips.read().await.contains(&data.ip.ip()) {
            info!("BLOCKLIST:DUPLICATE: {} already in the blocklist", data.ip);
            return;
        }

        let client = Client::new();

        match client.post(blocklist_url).json(&data).send().await {
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
            Err(e) => error!(
                "BLOCKLIST:ERROR; adding IP {} failed with error: {}",
                data.ip, e
            ),
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

    fn is_private(&self, metadata: &RequestMetadata) -> bool {
        match metadata.client_ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    true
                } else {
                    false
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unique_local() {
                    true
                } else {
                    false
                }
            }
        }
    }

    async fn check_geo_cache(
        &self,
        metadata: &RequestMetadata,
        server_config: &ServerConfig,
    ) -> Option<bool> {
        if let Some(geo_data) = self.geo_fence.read().await.get(&metadata.client_ip) {
            debug!("geolocation cache hit: {:?}", geo_data);
            return Some(self.is_geo_data_blocked(geo_data, server_config));
        }
        None
    }

    async fn is_blocked_ip_geolocation(
        &self,
        metadata: &RequestMetadata,
        server_config: &ServerConfig,
    ) -> Result<bool, AppError> {
        if server_config.geo_fence_isp_blocklist.is_none()
            && server_config.geo_fence_country_allowlist.is_none()
        {
            debug!("empty geo fence allowlist");
            return Ok(false);
        };

        if let Some(blocked) = self.check_geo_cache(metadata, server_config).await {
            return Ok(blocked);
        }

        let client = self.geo_api_client.lock().await;
        if let Some(blocked) = self.check_geo_cache(metadata, server_config).await {
            return Ok(blocked);
        }
        let data = client
            .get(format!(
                "{}{}",
                self.waf_config.geo_api_url, metadata.client_ip
            ))
            .send()
            .await?
            .json::<GeoData>()
            .await
            .map_err(|e| AppError::ParseError(format!("{e}")))?;
        let mut fence = self.geo_fence.write().await;
        let geo_data = fence.entry(metadata.client_ip).or_insert(data.clone());
        let blocked = self.is_geo_data_blocked(geo_data, server_config);
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
        if let Err(e) = self.geo_cache_writer.send(data.clone()).await {
            warn!("could not send GeoData: {data}; {e}")
        }
        Ok(blocked)
    }

    async fn is_blocked_by_rules(&self, metadata: &RequestMetadata, server: &ServerConfig) -> bool {
        let Some(rules) = server.ip_rules.as_ref() else {
            return false;
        };
        for rule in rules.iter() {
            match rule.source {
                IpSource::Direct => {
                    if rule.contains(Some(metadata.client_ip)) {
                        return rule.action.match_rule();
                    }
                }
                IpSource::Forwarded => {
                    if rule.contains(metadata.forwarded_ip) {
                        return rule.action.match_rule();
                    }
                }
            }
        }
        false
    }

    async fn is_blocked(&self, metadata: &RequestMetadata, server: &ServerConfig) -> bool {
        if self.is_blocked_by_rules(metadata, server).await {
            return true;
        }

        if self.is_private(metadata) {
            debug!("ALLOWED:PRIVATE IP");
            return false;
        }

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
            _ => true,
        }
    }

    async fn rewrite_request(&self, session: &mut Session, ctx: &mut ProxyContext) {
        let Some(metadata) = ctx.metadata.as_mut() else {
            return;
        };

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return;
        };

        if server.rewrite_rules.is_empty() {
            return;
        }

        for rule in &server.rewrite_rules {
            let Ok(re) = Regex::new(&rule.pattern) else {
                warn!("Invalid rewrite regex: {}", rule.pattern);
                continue;
            };

            if re.is_match(&metadata.uri) {
                let replaced = re.replace(&metadata.uri, rule.new.as_str()).to_string();
                if replaced != metadata.uri {
                    debug!(
                        "REWRITE: {} -> {} (RULE: {} -> {})",
                        metadata.uri, replaced, rule.pattern, rule.new
                    );
                    metadata.uri = replaced;
                } else {
                    return;
                }
            }
        }

        let req = session.req_header_mut();

        let full_uri = if let Some(q) = req.uri.query() {
            format!("{}?{}", metadata.uri, q)
        } else {
            metadata.uri.clone()
        };

        match full_uri.parse() {
            Ok(uri) => req.set_uri(uri),
            Err(e) => {
                error!("URI rewrite failed: {}", e);
                return;
            }
        }
    }

    async fn redirect_request(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> pingora::Result<bool> {
        let Some(metadata) = ctx.metadata.as_mut() else {
            return Ok(false);
        };
        let Some(server) = self.servers.get_server(&metadata.host) else {
            return Ok(false);
        };
        if server.redirect_rules.is_empty() {
            return Ok(false);
        }


        for rule in &server.redirect_rules {
            let Ok(re) = Regex::new(&rule.pattern) else {
                warn!("Invalid redirect regex: {}", rule.pattern);
                continue;
            };

            if re.is_match(&metadata.host) {
                let target = re.replace(&metadata.host, rule.new.as_str()).to_string();

                if target != metadata.host {
                    info!("REDIRECT: {} -> {}", metadata.host, target);
                    let status_code = 301;

                    let mut resp = ResponseHeader::build(status_code, None)
                        .map_err(|e| {
                            error!("Failed to build redirect response: {}", e);
                            Error::explain(HTTPStatus(500), "Internal server error")
                        })?;

                    resp.insert_header("Location", &target)
                        .map_err(|e| {
                            error!("Failed to set Location header: {}", e);
                            Error::explain(HTTPStatus(500), "Internal server error")
                        })?;

                    // Add cache-control headers to prevent caching of redirects
                    if status_code == 302 {
                        resp.insert_header("Cache-Control", "no-cache, no-store, must-revalidate")
                            .map_err(|e| {
                                error!("Failed to set Cache-Control header: {}", e);
                                Error::explain(HTTPStatus(500), "Internal server error")
                            })?;
                        resp.insert_header("Pragma", "no-cache")
                            .map_err(|e| {
                                error!("Failed to set Pragma header: {}", e);
                                Error::explain(HTTPStatus(500), "Internal server error")
                            })?;
                        resp.insert_header("Expires", "0")
                            .map_err(|e| {
                                error!("Failed to set Expires header: {}", e);
                                Error::explain(HTTPStatus(500), "Internal server error")
                            })?;
                        resp.insert_header("Content-Length", "0".to_string())?;
                    }

                    // Write the response
                    session.write_response_header(Box::new(resp), true).await
                        .map_err(|e| {
                            error!("Failed to write redirect response: {}", e);
                            Error::explain(HTTPStatus(500), "Internal server error")
                        })?;

                    session.write_response_body(None, true).await
                        .map_err(|e| {
                            error!("Failed to write redirect response body: {}", e);
                            Error::explain(HTTPStatus(500), "Internal server error")
                        })?;

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl ProxyHttp for PingoraService {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let Some(metadata) = ctx.metadata.as_ref() else {
            return Err(Error::explain(
                HTTPStatus(404),
                "Server name not supported by pproxy",
            ));
        };

        let mut peer = if let Some(server_config) = self.servers.get_server(&metadata.host) {
            Box::new(HttpPeer::new(
                &server_config.upstream,
                server_config.upstream_tls,
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
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let metadata = match RequestMetadata::parse(&session) {
            Ok(h) => h,
            Err(e) => {
                error!("{e}");
                session.set_keepalive(None);
                return Ok(true);
            }
        };

        ctx.metadata = Some(metadata.clone());

        let Some(server) = self.servers.get_server(&metadata.host) else {
            warn!(
                "could not find the server configuration for host: {}",
                metadata.host
            );
            session.set_keepalive(None);
            return Ok(true);
        };

        self.rewrite_request(session, ctx).await;
        self.redirect_request(session, ctx).await;

        if self.is_blocked(&metadata, server).await {
            info!("BLOCKED:REQ: {metadata}");
            session.set_keepalive(None);
            return Ok(true);
        }

        let Some(monitor) = server
            .monitor
            .as_ref()
            .and_then(|key| self.monitors.get(key))
        else {
            info!("REQ:NO_TRACKER: {metadata}");
            return Ok(false);
        };

        let message = match (
            monitor.auto_suspend_enabled.load(Ordering::Acquire),
            monitor.suspended.load(Ordering::Acquire),
        ) {
            (true, true) => {
                info!("REQ:ENABLED:RESUMING: {metadata}");
                monitor.logs.write().await.insert(
                    metadata.client_ip,
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        format!("ENABLED:RESUMING: {metadata}"),
                    ),
                );
                monitor.wake_up.store(true, Ordering::Release);
                "The server is starting, the page will be refreshing automatically until you are redirected to immich/jellyfin. If not, try refreshing the page manually after about 10 seconds."
            }
            (false, true) => {
                info!("REQ:DISABLED:ATTEMPT: {metadata}");
                monitor.logs.write().await.insert(
                    metadata.client_ip,
                    (
                        OffsetDateTime::now_local().unwrap_or(OffsetDateTime::now_utc()),
                        format!("DISABLED:ATTEMPT: {metadata}"),
                    ),
                );
                "Auto suspend/wake up is disabled, please contact the administrator."
            }
            (_, _) => {
                info!("REQ:TRACKER_UPDATED: {metadata}");
                let mut timer = monitor.timer.write().await;
                *timer = Instant::now();
                return Ok(false);
            }
        };

        let tmpl = PublicPageTemplate {
            message: Some(message.to_string()),
            enabled: monitor.auto_suspend_enabled.load(Ordering::Relaxed),
            suspended: monitor.suspended.load(Ordering::Relaxed),
            suspending: monitor.suspending.load(Ordering::Relaxed),
            waking_up: monitor.wake_up.load(Ordering::Relaxed),
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
        session.set_keepalive(None);
        Ok(true)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(upgrade) = session.get_header("Upgrade") {
            upstream_request.insert_header("Upgrade", upgrade)?;
        }

        let Some(metadata) = ctx.metadata.as_ref() else {
            return Ok(());
        };

        upstream_request.insert_header("X-Real-IP", metadata.client_ip.to_string())?;

        let mut forwarded_for = String::new();
        if let Some(existing_xff) = session
            .get_header("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
        {
            forwarded_for.push_str(existing_xff);
            forwarded_for.push_str(", ");
        }
        forwarded_for.push_str(&metadata.client_ip.to_string());

        upstream_request.insert_header("X-Forwarded-For", &forwarded_for)?;

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return Ok(());
        };

        let scheme = if server.cert_path.is_some() {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", scheme)?;

        for (k, v) in server.proxy_headers.iter() {
            upstream_request.insert_header(k.clone(), v)?;
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(metadata) = ctx.metadata.as_ref() else {
            return Ok(());
        };

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return Ok(());
        };

        for (k, v) in server.headers.iter() {
            upstream_response.insert_header(k.clone(), v)?;
        }

        Ok(())
    }
}
