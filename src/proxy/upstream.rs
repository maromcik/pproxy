use std::{collections::HashMap, fmt::Debug, net::ToSocketAddrs, sync::Arc, time::Duration};

use itertools::Itertools;
use pingora::{
    lb::{LoadBalancer, health_check::TcpHealthCheck, selection::Consistent},
    services::background::{GenBackgroundService, background_service},
};
use regex::Regex;

use crate::{
    config::{ServerConfig, UpstreamConfig},
    error::AppError,
};

pub struct ServersWithLoadBalancers(pub HashMap<String, ProxyServer>);

impl ServersWithLoadBalancers {
    pub fn get_server(&self, name: &str) -> Option<&ProxyServer> {
        self.0.get(name.strip_prefix("www.").unwrap_or(name))
    }
}

pub struct ProxyServer {
    pub proxy_methods: ProxyMethods,
    pub server_config: ServerConfig,
}

pub struct ProxyServerWithHealthchecks {
    pub proxy_server: ProxyServer,
    pub healthchecks: Vec<GenBackgroundService<LoadBalancer<Consistent>>>,
}

impl ProxyServer {
    fn build_load_balancer_server(
        config: ServerConfig,
    ) -> Result<ProxyServerWithHealthchecks, AppError> {
        let mut proxy_methods: Vec<ProxyMethod> = Vec::new();
        let mut healthchecks: Vec<GenBackgroundService<LoadBalancer<Consistent>>> = Vec::new();
        for proxy_to_config in &config.proxy {
            let mut lb =
                LoadBalancer::try_from_iter(proxy_to_config.upstreams.keys().map(String::from))?;
            let mut new_upstreams: HashMap<String, UpstreamConfig> = HashMap::new();
            for (name, upstream) in &proxy_to_config.upstreams {
                for addr in name.to_socket_addrs()? {
                    new_upstreams.insert(addr.to_string(), upstream.clone());
                }
            }
            lb.set_health_check(TcpHealthCheck::new());
            lb.parallel_health_check = true;
            lb.health_check_frequency = config
                .health_check_interval
                .or_else(|| Some(Duration::from_secs(1)));
            let background = background_service(
                format!(
                    "Health Check for upstreams: <{}>",
                    proxy_to_config.upstreams.iter().map(|u| u.0).join("; ")
                )
                .as_str(),
                lb,
            );

            let lb: Arc<LoadBalancer<Consistent>> = background.task();
            let upstream = UpstreamSelector::LB(LbUpstream::new(lb, new_upstreams));
            let proxy_method = if let Some(path) = &proxy_to_config.path {
                let path =
                    Regex::new(path.as_str()).map_err(|e| AppError::ParseError(e.to_string()))?;
                ProxyMethod::Regex(PathUpstreamSelector { path, upstream })
            } else {
                ProxyMethod::Exact(upstream)
            };

            healthchecks.push(background);
            proxy_methods.push(proxy_method);
        }

        let proxy_server = Self {
            proxy_methods: ProxyMethods {
                methods: proxy_methods,
            },
            server_config: config,
        };

        Ok(ProxyServerWithHealthchecks {
            proxy_server,
            healthchecks,
        })
    }

    pub fn build_direct_server(
        config: ServerConfig,
    ) -> Result<ProxyServerWithHealthchecks, AppError> {
        let mut proxy_methods: Vec<ProxyMethod> = Vec::new();

        for proxy_to_config in &config.proxy {
            let upstream_config = proxy_to_config
                .upstreams
                .iter()
                .next()
                .ok_or_else(|| AppError::ParseError("No upstream config found".to_string()))?;
            let upstream = UpstreamSelector::Direct(DirectUpstream::new(
                upstream_config.0.clone(),
                upstream_config.1.clone(),
            ));
            let proxy_method = if let Some(path) = &proxy_to_config.path {
                let path =
                    Regex::new(path.as_str()).map_err(|e| AppError::ParseError(e.to_string()))?;
                ProxyMethod::Regex(PathUpstreamSelector { path, upstream })
            } else {
                ProxyMethod::Exact(upstream)
            };
            proxy_methods.push(proxy_method);
        }
        let proxy_server = Self {
            proxy_methods: ProxyMethods {
                methods: proxy_methods,
            },
            server_config: config,
        };
        Ok(ProxyServerWithHealthchecks {
            proxy_server,
            healthchecks: Vec::new(),
        })
    }

    pub fn from_config(config: ServerConfig) -> Result<Vec<ProxyServerWithHealthchecks>, AppError> {
        let mut servers = Vec::new();
        for proxy in &config.proxy {
            if proxy.upstreams.len() > 1 {
                let server = Self::build_load_balancer_server(config.clone())?;
                servers.push(server);
            } else {
                let server = Self::build_direct_server(config.clone())?;
                servers.push(server);
            }
        }
        Ok(servers)
    }
}

#[derive(Clone, Debug)]
pub struct ProxyMethods {
    pub methods: Vec<ProxyMethod>,
}

#[derive(Clone, Debug)]
pub enum ProxyMethod {
    Exact(UpstreamSelector),
    Regex(PathUpstreamSelector),
}

#[derive(Clone, Debug)]
pub struct PathUpstreamSelector {
    pub path: Regex,
    pub upstream: UpstreamSelector,
}

#[derive(Clone, Debug)]
pub enum UpstreamSelector {
    Direct(DirectUpstream),
    LB(LbUpstream),
}

#[derive(Debug, Clone)]
pub struct DirectUpstream {
    pub addr: String,
    pub config: UpstreamConfig,
}

impl DirectUpstream {
    pub fn new(addr: String, config: UpstreamConfig) -> Self {
        Self { addr, config }
    }
}

#[derive(Clone)]
pub struct LbUpstream {
    pub lb: Arc<LoadBalancer<Consistent>>,
    pub configs: HashMap<String, UpstreamConfig>,
}

impl Debug for LbUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LbUpstream for configs: {:?}", self.configs)
    }
}

impl LbUpstream {
    pub fn new(
        lb: Arc<LoadBalancer<Consistent>>,
        configs: HashMap<String, UpstreamConfig>,
    ) -> Self {
        Self { lb, configs }
    }
}
