pub mod blocklist;
mod config;
mod error;
mod geo;
mod management;
mod proxy;
mod templates;
mod utils;

use crate::config::{AppConfig, CommandConfig};
use crate::error::AppError;
use crate::geo::{GeoData, GeoWriter};
use crate::management::{ControlService, MonitorService};
use crate::proxy::PingoraProxy;
use clap::Parser;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, mpsc};
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

fn init_pingora(
    config: AppConfig,
    geo_writer: mpsc::Sender<GeoData>,
    geo_cache_data: HashMap<IpAddr, GeoData>,
) -> Result<(), AppError> {
    let conf = ServerConf {
        version: 1,
        client_bind_to_ipv4: vec![],
        client_bind_to_ipv6: vec![],
        ca_file: None,
        daemon: false,
        error_log: None,
        upstream_debug_ssl_keylog: false,
        pid_file: "/tmp/pingora.pid".to_string(),
        upgrade_sock: "/tmp/pingora_upgrade.sock".to_string(),
        user: None,
        group: None,
        threads: num_cpus::get(),
        listener_tasks_per_fd: 1,
        work_stealing: true,
        upstream_keepalive_pool_size: 128,
        upstream_connect_offload_threadpools: None,
        upstream_connect_offload_thread_per_pool: None,
        grace_period_seconds: None,
        graceful_shutdown_timeout_seconds: None,
        max_retries: 16,
    };

    let mut server = Server::new_with_opt_and_conf(None, conf);
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
        time_monitoring: TimeMonitoring {
            active_time: Duration::from_secs(0),
            suspended_time: Duration::from_secs(0),
        }
        .into(),
        logs: HashMap::new().into(),
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

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let mut proxy_service = http_proxy_service(
        &server.configuration,
        PingoraProxy {
            blocklist_url: config.blocklist_url,
            geo_api_url: config.geo_api_url,
            state,
            servers: config.servers,
            geo_fence: RwLock::new(geo_cache_data),
            geo_api_client: Mutex::new(client),
            blocked_ips: RwLock::new(HashSet::new()),
            geo_cache_writer: geo_writer,
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

#[tokio::main]
async fn main() -> Result<(), AppError> {
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

    let get_cache_data = GeoData::load_geo_data(config.geo_cache_file_path.as_str())
        .await
        .unwrap_or(HashMap::new());
    let (geo_writer, geo_receiver) = mpsc::channel(1000);
    debug!("Using config: {:?}", &config);
    let local_config = config.clone();
    let writer = GeoWriter::open(&config.geo_cache_file_path, geo_receiver).await?;
    writer.run().await;
    tokio::task::spawn_blocking(move || {
        init_pingora(local_config, geo_writer, get_cache_data)?;
        Ok::<(), AppError>(())
    })
    .await??;
    Ok(())
}
