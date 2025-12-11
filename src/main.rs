pub mod blocklist;
mod config;
mod error;
mod geo;
mod management;
mod proxy;
mod templates;
mod utils;

use crate::config::{CommandConfig, AppConfig};
use crate::error::AppError;
use crate::management::{ControlService, MonitorService};
use crate::proxy::PingoraProxy;
use clap::Parser;
use pingora::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use pingora::server::configuration::ServerConf;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "CONFIG_FILE", default_value = "pproxy.toml")]
    config: String,
}

pub struct Upstreams {
    pub jellyfin: String,
    pub immich: String,
}

pub struct TimeMonitoring {
    pub active_time: Duration,
    pub suspended_time: Duration,
}

pub struct ServerState {
    pub timer: RwLock<Instant>,
    pub suspended: AtomicBool,
    pub limit: Duration,
    pub wake_up: AtomicBool,
    pub suspending: AtomicBool,
    pub auto_suspend_enabled: AtomicBool,
    pub commands: CommandConfig,
    pub time_monitoring: RwLock<TimeMonitoring>,
    pub logs: RwLock<HashMap<IpAddr, (OffsetDateTime, String)>>,
}

fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    let config = AppConfig::parse_config(&cli.config)?;
    let env = EnvFilter::new(
        format!("pproxy={},{}", config.app_log_level, config.all_log_level).as_str(),
    );
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    debug!("Using config: {:?}", &config);

    // let conf = ServerConf {
    //     version: 0,
    //     client_bind_to_ipv4: vec![],
    //     client_bind_to_ipv6: vec![],
    //     ca_file: None,
    //     daemon: false,
    //     error_log: None,
    //     upstream_debug_ssl_keylog: false,
    //     pid_file: "/tmp/pingora.pid".to_string(),
    //     upgrade_sock: "/tmp/pingora_upgrade.sock".to_string(),
    //     user: None,
    //     group: None,
    //     threads: num_cpus::get(),
    //     listener_tasks_per_fd: 1,
    //     work_stealing: true,
    //     upstream_keepalive_pool_size: 128,
    //     upstream_connect_offload_threadpools: None,
    //     upstream_connect_offload_thread_per_pool: None,
    //     grace_period_seconds: None,
    //     graceful_shutdown_timeout_seconds: None,
    //     max_retries: 16,
    // };

    let mut server = Server::new(Some(Opt::default())).unwrap();
    info!("Server conf: {:?}", server.configuration);
    server.bootstrap();

    let state = Arc::new(ServerState {
        timer: Instant::now().into(),
        suspended: AtomicBool::new(false),
        limit: Duration::from_secs(config.suspend_timeout),
        wake_up: AtomicBool::new(false),
        suspending: AtomicBool::new(false),
        auto_suspend_enabled: AtomicBool::new(false),
        commands: config.commands,
        time_monitoring: RwLock::new(TimeMonitoring {
            active_time: Duration::from_secs(0),
            suspended_time: Duration::from_secs(0),
        }),
        logs: RwLock::new(HashMap::new()),
    });

    info!("Bootstrap done");

    let monitor_service = MonitorService {
        state: state.clone(),
    };
    server.add_service(monitor_service);

    let mut control_service = http_proxy_service(
        &server.configuration,
        ControlService {
            state: state.clone(),
        },
    );

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        PingoraProxy {
            blocklist_url: config.blocklist_url,
            geo_api_url: config.geo_api_url,
            state,
            servers: config.servers,
            geo_fence: RwLock::new(HashMap::new()),
            geo_api_lock: Mutex::new(()),
            blocked_ips: RwLock::new(HashSet::new()),
        },
    );
    //
    proxy_service.add_tcp(&config.listen_host);
    control_service.add_tcp(&config.listen_control_host);

    server.add_service(proxy_service);
    server.add_service(control_service);
    info!("Server starting");
    server.run_forever();
}
