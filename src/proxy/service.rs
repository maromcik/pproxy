use crate::config::{H2OptionsConfig, IpSource, ServerConfig};
use crate::error::AppError;
use crate::management::monitoring::monitor::Monitors;
use crate::management::templates::templates::PublicPageTemplate;
use crate::proxy::blocklist::BlocklistIp;
use crate::proxy::geo::GeoData;
use crate::proxy::tls::TlsSelector;
use crate::proxy::upstream::UpstreamSelector;
use crate::proxy::upstream::{ProxyMethod, ServersWithLoadBalancers};
use crate::proxy::utils::{self, RequestMetadata, apply_opt};
use crate::proxy::waf::{Waf, WafParsedConfig};
use askama::Template;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::info;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::protocols::http::v2::server::H2Options;
use pingora::proxy::HttpProxy;
use pingora::server::configuration::ServerConf;
use pingora::services::listening::Service;
use pingora::{Error, HTTPStatus};
use regex::Regex;
use reqwest::Client;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use time::OffsetDateTime;

use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

pub struct PingoraService {
    pub listen_addr: core::net::SocketAddr,
    pub tls: bool,
    pub h2_options: H2OptionsConfig,
    pub monitors: Monitors,
    pub servers: ServersWithLoadBalancers,
    pub waf: Option<Waf>,
}

impl PingoraService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen_addr: core::net::SocketAddr,
        tls: bool,
        h2_options: H2OptionsConfig,
        monitors: Monitors,
        servers: ServersWithLoadBalancers,
        waf: Option<WafParsedConfig>,
    ) -> Self {
        let waf = waf.map(Waf::from);
        Self {
            listen_addr,
            tls,
            h2_options,
            monitors,
            servers,
            waf,
        }
    }
    pub fn build_service(
        self,
        server_conf: Arc<ServerConf>,
        host: String,
        tls: bool,
    ) -> Result<impl pingora::services::Service, AppError> {
        let selector = Box::new(TlsSelector::new(&self.servers)?);
        let mut h2options = H2Options::default();

        apply_opt(self.h2_options.initial_connection_window_size, |v| {
            h2options.initial_connection_window_size(v);
        });
        apply_opt(self.h2_options.initial_window_size, |v| {
            h2options.initial_window_size(v);
        });
        apply_opt(self.h2_options.max_concurrent_streams, |v| {
            h2options.max_concurrent_streams(v);
        });
        apply_opt(self.h2_options.max_frame_size, |v| {
            h2options.max_frame_size(v);
        });
        apply_opt(self.h2_options.max_send_buffer_size, |v| {
            h2options.max_send_buffer_size(v);
        });

        let mut proxy = HttpProxy::new(self, server_conf.clone());
        proxy.handle_init_modules();
        proxy.h2_options = Some(h2options);

        let mut service = Service::new(host.to_string(), proxy);

        if tls {
            let mut tls_settings = TlsSettings::with_callbacks(selector.clone())?;
            tls_settings.enable_h2();
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

impl PingoraService {
    async fn add_ip_to_blocklist(&self, data: &BlocklistIp) {
        let Some(waf) = &self.waf else {
            return;
        };
        let Some(blocklist_url) = &waf.waf_config.blocklist_url else {
            trace!("BLOCKLIST: Blocklist disabled");
            return;
        };

        if waf.blocked_ips.read().await.contains(&data.ip.ip()) {
            info!("BLOCKLIST:DUPLICATE: {} already in the blocklist", data.ip);
            return;
        }

        let client = Client::new();

        match client.post(blocklist_url).json(&data).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!("BLOCKLIST:ADDED; {}", data.ip);
                    waf.blocked_ips.write().await.insert(data.ip.ip());
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
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(ipv6) => ipv6.is_unique_local(),
        }
    }

    async fn check_geo_cache(
        &self,
        metadata: &RequestMetadata,
        server_config: &ServerConfig,
    ) -> Option<bool> {
        let Some(waf) = &self.waf else {
            return None;
        };
        if let Some(geo_data) = waf.geo_fence.read().await.get(&metadata.client_ip) {
            debug!("GEO: Geolocation cache hit: {:?}", geo_data);
            return Some(self.is_geo_data_blocked(geo_data, server_config));
        }
        None
    }

    async fn is_blocked_ip_geolocation(
        &self,
        metadata: &RequestMetadata,
        server: &ServerConfig,
    ) -> Result<bool, AppError> {
        let Some(waf) = &self.waf else {
            return Ok(false);
        };

        if server.geo_fence_isp_blocklist.is_none() && server.geo_fence_country_allowlist.is_none()
        {
            debug!("GEO: Empty geo fence allowlist");
            return Ok(false);
        };

        if let Some(blocked) = self.check_geo_cache(metadata, server).await {
            return Ok(blocked);
        }

        let client = waf.geo_api_client.lock().await;
        if let Some(blocked) = self.check_geo_cache(metadata, server).await {
            return Ok(blocked);
        }
        let url =
            strfmt::strfmt!(&waf.waf_config.geo_api_url, ip => metadata.client_ip.to_string())?;
        let data = client
            .get(url)
            .send()
            .await?
            .json::<GeoData>()
            .await
            .map_err(|e| AppError::ParseError(format!("{e}")))?;
        let mut fence = waf.geo_fence.write().await;
        let geo_data = fence.entry(metadata.client_ip).or_insert(data.clone());
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
        if let Err(e) = waf.geo_cache_writer.send(data.clone()).await {
            warn!("GEO: could not send GeoData: {data}; {e}")
        }
        Ok(blocked)
    }

    fn is_blocked_by_rules(&self, metadata: &RequestMetadata, server: &ServerConfig) -> bool {
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
        if self.is_blocked_by_rules(metadata, server) {
            return true;
        }

        if self.is_private(metadata) {
            debug!("ALLOWED:PRIVATE IP");
            return false;
        }

        if let Some(user_agent_blocklist) = &server.user_agent_blocklist
            && user_agent_blocklist.iter().any(|ua| {
                metadata
                    .user_agent
                    .to_lowercase()
                    .contains(ua.to_lowercase().as_str())
            })
        {
            {
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

    fn rewrite_request(&self, session: &mut Session, ctx: &mut ProxyContext) {
        let Some(metadata) = ctx.metadata.as_mut() else {
            return;
        };

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return;
        };

        if server.server_config.rewrite_rules.is_empty() {
            return;
        }

        for rule in &server.server_config.rewrite_rules {
            let Ok(re) = Regex::new(&rule.pattern) else {
                warn!("REWRITE: Invalid rewrite regex: {}", rule.pattern);
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
                error!("REWRITE: URI rewrite failed: {}", e);
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
        if server.server_config.redirect_rules.is_empty() {
            return Ok(false);
        }

        for rule in &server.server_config.redirect_rules {
            let Ok(re) = Regex::new(&rule.pattern) else {
                warn!("REDIRECT: Invalid redirect regex: {}", rule.pattern);
                continue;
            };

            if re.is_match(metadata.full_url.as_str()) {
                let target = re
                    .replace(metadata.full_url.as_str(), rule.new.as_str())
                    .to_string();
                if target != metadata.full_url.as_str() {
                    debug!(
                        "REDIRECT: {} -> {} (RULE: {} -> {})",
                        metadata.full_url.as_str(),
                        target,
                        rule.pattern,
                        rule.new
                    );

                    let mut resp = ResponseHeader::build(302, None).map_err(|e| {
                        error!("REDIRECT: Failed to build redirect response: {}", e);
                        Error::explain(HTTPStatus(500), "Internal server error")
                    })?;

                    resp.insert_header("Location", target).map_err(|e| {
                        error!("REDIRECT: Failed to set Location header: {}", e);
                        Error::explain(HTTPStatus(500), "Internal server error")
                    })?;

                    session
                        .write_response_header(Box::new(resp), true)
                        .await
                        .map_err(|e| {
                            error!("REDIRECT: Failed to write redirect response: {}", e);
                            Error::explain(HTTPStatus(500), "Internal server error")
                        })?;

                    session.write_response_body(None, true).await.map_err(|e| {
                        error!("REDIRECT: Failed to write redirect response body: {}", e);
                        Error::explain(HTTPStatus(500), "Internal server error")
                    })?;

                    return Ok(true);
                }
            }
        }
        Ok(true)
    }

    fn select_upstream(
        &self,
        upstream_selector: &UpstreamSelector,
        metadata: &RequestMetadata,
    ) -> pingora::Result<Box<HttpPeer>> {
        let peer = match upstream_selector {
            UpstreamSelector::Direct(upstream) => {
                let mut peer = Box::new(HttpPeer::new(
                    &upstream.addr,
                    upstream.config.tls,
                    String::default(),
                ));
                utils::set_upstream_options(&mut peer, &upstream.config);
                peer
            }
            UpstreamSelector::LB(lb) => {
                let Some(upstream) = lb.lb.select(
                    format!("{};{}", metadata.client_ip, metadata.host).as_bytes(),
                    256,
                ) else {
                    return Err(Error::explain(
                        HTTPStatus(502),
                        "Upstream could not be selected from backend pool",
                    ));
                };
                let Some(upstream_config) = lb.configs.get(&upstream.addr.to_string()) else {
                    return Err(Error::explain(
                        HTTPStatus(502),
                        "Upstream not found in configuration",
                    ));
                };

                let mut peer = Box::new(HttpPeer::new(
                    &upstream,
                    upstream_config.tls,
                    String::default(),
                ));
                utils::set_upstream_options(&mut peer, upstream_config);
                peer.options.alpn = pingora::protocols::ALPN::H2;
                peer
            }
        };
        info!("REQ:PROXY: {} -> PROXY TO -> {}", metadata, peer._address);
        Ok(peer)
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

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return Err(Error::explain(
                HTTPStatus(502),
                "Server name not supported by pproxy",
            ));
        };
        for method in &server.proxy_methods.methods {
            match method {
                ProxyMethod::Exact(upstream_selector) => {
                    return self.select_upstream(upstream_selector, metadata);
                }
                ProxyMethod::Regex(path_upstream_selector) => {
                    if path_upstream_selector.path.is_match(&metadata.uri) {
                        return self.select_upstream(&path_upstream_selector.upstream, metadata);
                    }
                }
            }
        }

        Err(Error::explain(
            HTTPStatus(502),
            "Upstream could not be selected based on neither exact nor regex match",
        ))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let metadata = match RequestMetadata::parse(session, self.listen_addr, self.tls) {
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
                "REQ: Could not find the server configuration for host: {}",
                metadata.host
            );
            session.set_keepalive(None);
            return Ok(true);
        };

        self.rewrite_request(session, ctx);

        if self.redirect_request(session, ctx).await? {
            session.set_keepalive(None);
            return Ok(true);
        }

        if self.is_blocked(&metadata, &server.server_config).await {
            info!("BLOCKED:REQ: {metadata}");
            session.set_keepalive(None);
            return Ok(true);
        }

        let Some(monitor) = server
            .server_config
            .monitor
            .as_ref()
            .and_then(|key| self.monitors.get(key))
        else {
            debug!("REQ:NO_TRACKER: {metadata}");
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
                "The server is starting, the page will be refreshing automatically until you are redirected to the requested website. If not, try refreshing the page manually after about 10 seconds."
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
                debug!("REQ:TRACKER_UPDATED: {metadata}");
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
        debug!("UPSTREAM_REQUEST:HEADER:X-Forwarded-For: {forwarded_for}");
        upstream_request.insert_header("X-Forwarded-For", &forwarded_for)?;

        let Some(server) = self.servers.get_server(&metadata.host) else {
            return Ok(());
        };

        let scheme = if server.server_config.cert_path.is_some() {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", scheme)?;

        for (k, v) in &server.server_config.proxy_headers {
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

        for (k, v) in &server.server_config.headers {
            upstream_response.insert_header(k.clone(), v)?;
        }

        Ok(())
    }
}
