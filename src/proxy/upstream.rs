use std::{collections::HashMap, net::ToSocketAddrs, sync::Arc, time::Duration};

use itertools::Itertools;
use log::error;
use pingora::{
    lb::{LoadBalancer, health_check::TcpHealthCheck, selection::Consistent},
    services::background::{GenBackgroundService, background_service},
};
use regex::Regex;

use crate::{
    config::{ServerConfig, UpstreamConfig},
    error::AppError,
};

pub struct ProxyServerConfig {
    pub proxy: ProxyMethods,
    pub server_config: ServerConfig,
}

pub struct ProxyServerConfigWithHealthchecks {
    pub proxy_server: ProxyServerConfig,
    pub healthchecks: Vec<GenBackgroundService<LoadBalancer<Consistent>>>,
}

impl ProxyServerConfig {
    fn build_load_balancer_server(
        config: ServerConfig,
    ) -> Result<ProxyServerConfigWithHealthchecks, AppError> {
        let mut proxy_configs: Vec<ProxyMethod> = Vec::new();
        let mut healthchecks: Vec<GenBackgroundService<LoadBalancer<Consistent>>> = Vec::new();
        for proxy in &config.proxy {
            let mut lb = LoadBalancer::try_from_iter(proxy.upstreams.keys().map(String::from))?;
            let mut new_upstreams: HashMap<String, UpstreamConfig> = HashMap::new();
            for (name, upstream) in &proxy.upstreams {
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
                    proxy.upstreams.iter().map(|u| u.0).join("; ")
                )
                .as_str(),
                lb,
            );

            let lb: Arc<LoadBalancer<Consistent>> = background.task();
            error!("upstreams: {:?}", new_upstreams);
            let proxy_config = if let Some(path) = &proxy.path {
                ProxyMethod::Regex(PathUpstreamSelector {
                    path: Regex::new(path.as_str())
                        .map_err(|e| AppError::ParseError(e.to_string()))?,
                    upstream: UpstreamSelector::LB(LbUpstream::new(lb, new_upstreams)),
                })
            } else {
                ProxyMethod::Exact(UpstreamSelector::LB(LbUpstream::new(lb, new_upstreams)))
            };

            healthchecks.push(background);
            proxy_configs.push(proxy_config);
        }

        let proxy_server_config = Self {
            proxy: ProxyMethods {
                methods: proxy_configs,
            },
            server_config: config,
        };

        Ok(ProxyServerConfigWithHealthchecks {
            proxy_server: proxy_server_config,
            healthchecks,
        })
    }

    pub fn build_direct_server(config: ServerConfig) -> Result<ProxyServerConfig, AppError> {
        let proxy_to = config.proxy.first().ok_or_else(|| {
            AppError::ConfigError(
                "Server config must contain exactly 1 proxy configuration".to_string(),
            )
        })?;

        let (addr, upstream_config) = proxy_to.upstreams.iter().next().ok_or_else(|| {
            AppError::ConfigError("Proxy config must contain exactly 1 upstream server".to_string())
        })?;

        let proxy_config = if let Some(path) = &proxy_to.path {
            Self {
                proxy: ProxyMethods {
                    methods: vec![ProxyMethod::Regex(PathUpstreamSelector {
                        path: Regex::new(path.as_str())
                            .map_err(|e| AppError::ParseError(e.to_string()))?,
                        upstream: UpstreamSelector::Direct(DirectUpstream::new(
                            addr.clone(),
                            upstream_config.clone(),
                        )),
                    })],
                },
                server_config: config,
            }
        } else {
            Self {
                proxy: ProxyMethods {
                    methods: vec![ProxyMethod::Exact(UpstreamSelector::Direct(
                        DirectUpstream::new(addr.clone(), upstream_config.clone()),
                    ))],
                },
                server_config: config,
            }
        };

        Ok(proxy_config)
    }

    pub fn from_config(
        config: ServerConfig,
    ) -> Result<Vec<ProxyServerConfigWithHealthchecks>, AppError> {
        let mut servers = Vec::new();
        for proxy in &config.proxy {
            if proxy.upstreams.len() > 1 {
                let server = Self::build_load_balancer_server(config.clone())?;
                servers.push(server);
            } else {
                let server =
                    ProxyServerConfig::build_direct_server(config.clone()).map(|proxy_server| {
                        ProxyServerConfigWithHealthchecks {
                            proxy_server,
                            healthchecks: Vec::new(),
                        }
                    })?;
                servers.push(server);
            }
        }
        Ok(servers)
    }
}

pub struct ServersWithLoadBalancers(pub HashMap<String, ProxyServerConfig>);

impl ServersWithLoadBalancers {
    pub fn get_server(&self, name: &str) -> Option<&ProxyServerConfig> {
        self.0.get(name.strip_prefix("www.").unwrap_or(name))
    }
}

pub struct DirectUpstream {
    pub addr: String,
    pub config: UpstreamConfig,
}

impl DirectUpstream {
    pub fn new(addr: String, config: UpstreamConfig) -> Self {
        Self { addr, config }
    }
}

pub struct LbUpstream {
    pub lb: Arc<LoadBalancer<Consistent>>,
    pub configs: HashMap<String, UpstreamConfig>,
}

impl LbUpstream {
    pub fn new(
        lb: Arc<LoadBalancer<Consistent>>,
        configs: HashMap<String, UpstreamConfig>,
    ) -> Self {
        Self { lb, configs }
    }
}

pub struct PathUpstreamSelector {
    pub path: Regex,
    pub upstream: UpstreamSelector,
}

pub enum UpstreamSelector {
    Direct(DirectUpstream),
    LB(LbUpstream),
}

pub struct ProxyMethods {
    pub methods: Vec<ProxyMethod>,
}

pub enum ProxyMethod {
    Exact(UpstreamSelector),
    Regex(PathUpstreamSelector),
}
