use std::fmt::Display;
use std::net::IpAddr;

use pingora::protocols::l4::socket::SocketAddr;

use log::debug;
use pingora::proxy::Session;
use pingora::{protocols::TcpKeepalive, upstreams::peer::HttpPeer};

use crate::config::UpstreamConfig;
use crate::error::AppError;

pub fn apply_opt<T, F>(opt: Option<T>, mut f: F)
where
    F: FnMut(T),
{
    if let Some(v) = opt {
        f(v);
    }
}

pub(crate) fn set_upstream_options(peer: &mut Box<HttpPeer>, upstream_config: &UpstreamConfig) {
    peer.options.tcp_keepalive = Some(TcpKeepalive::from(upstream_config.tcp_keepalive.clone()));

    apply_opt(upstream_config.connection_timeout, |v| {
        peer.options.connection_timeout = Some(v)
    });
    apply_opt(upstream_config.read_timeout, |v| {
        peer.options.read_timeout = Some(v)
    });
    apply_opt(upstream_config.write_timeout, |v| {
        peer.options.write_timeout = Some(v)
    });
    apply_opt(upstream_config.idle_timeout, |v| {
        peer.options.idle_timeout = Some(v)
    });
    apply_opt(upstream_config.total_connection_timeout, |v| {
        peer.options.total_connection_timeout = Some(v)
    });
    apply_opt(upstream_config.tcp_recv_buf, |v| {
        peer.options.tcp_recv_buf = Some(v)
    });
    apply_opt(upstream_config.max_h2_streams, |v| {
        peer.options.max_h2_streams = v
    });
    apply_opt(upstream_config.tcp_fast_open, |v| {
        peer.options.tcp_fast_open = v
    });
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct RequestMetadata {
    pub(crate) user_agent: String,
    pub(crate) client_ip: IpAddr,
    pub(crate) forwarded_ip: Option<IpAddr>,
    pub(crate) full_url: url::Url,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) scheme: String,
    pub(crate) query: String,
    pub(crate) version: String,
}

impl Display for RequestMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -- {} {} {} '{}'",
            self.client_ip,
            self.version,
            self.method,
            self.full_url.as_str(),
            self.user_agent
        )
    }
}

impl RequestMetadata {
    pub(crate) fn parse(
        session: &Session,
        listen_addr: core::net::SocketAddr,
        tls: bool,
    ) -> Result<Self, AppError> {
        let headers = session.req_header();

        let user_agent = headers
            .headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .map(String::from)
            .unwrap_or_default();

        let client_addr = session
            .client_addr()
            .map(|addr| match addr {
                SocketAddr::Inet(ip) => ip.ip().to_string(),
                SocketAddr::Unix(_) => String::new(),
            })
            .unwrap_or_default();
        debug!("METADATA: Client SocketAddr: {}", client_addr);

        let client_forwarded = headers
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .map(String::from);
        debug!("METADATA: Client ForwardedIP: {:?}", client_forwarded);
        let host = headers
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
            .or_else(|| headers.uri.authority().map(|a| a.as_str().to_string()))
            .unwrap_or_default();

        let method = headers.method.as_str().to_string();
        let uri = headers.uri.path().to_string();
        let scheme = if tls { "https" } else { "http" }.to_string();
        let query = headers.uri.query();
        let port = listen_addr.port();
        let mut full_url = url::Url::parse(&format!("{scheme}://{host}"))?;
        full_url.set_query(query);
        full_url.set_path(&uri);

        let parsed_ip: IpAddr = client_addr.parse()?;

        let normalized_ip = match parsed_ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(v6)
                }
            }
        };

        Ok(Self {
            user_agent,
            client_ip: normalized_ip,
            forwarded_ip: client_forwarded.and_then(|ip| ip.parse().ok()),
            full_url,
            host,
            port,
            method,
            uri,
            scheme,
            query: query.unwrap_or_default().to_string(),
            version: format!("{:?}", session.req_header().version),
        })
    }
}
