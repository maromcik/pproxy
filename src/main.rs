mod config;
mod error;
mod management;
mod proxy;

use crate::config::{AppConfig, HostConfig};
use crate::error::AppError;
use crate::management::init_control;
use crate::management::monitoring::monitor::{MonitorState, Monitors};
use crate::proxy::geo::{GeoData, GeoWriter};
use crate::proxy::service::PingoraService;
use clap::Parser;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "CONFIG_FILE", default_value = "pproxy.toml")]
    config: String,
}

fn init_pingora(
    config: AppConfig,
    geo_writer: mpsc::Sender<GeoData>,
    geo_cache_data: HashMap<IpAddr, GeoData>,
    monitors: Monitors,
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
        upstream_keepalive_pool_size: 1000,
        upstream_connect_offload_threadpools: None,
        upstream_connect_offload_thread_per_pool: None,
        grace_period_seconds: None,
        graceful_shutdown_timeout_seconds: None,
        max_retries: 16,
        upgrade_sock_connect_accept_max_retries: None,
    };

    let mut server = Server::new_with_opt_and_conf(None, conf);
    info!("Pingora Config: {:#?}", server.configuration);
    server.bootstrap();
    info!("Bootstrap done");
    info!("PProxy Config: {:#?}", config);

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;

    for (addr, HostConfig { tls, servers }) in config.hosts.into_iter() {
        let addr: SocketAddr = addr.parse()?;
        let pproxy = PingoraService::new(
            addr,
            tls,
            monitors.clone(),
            servers.clone(),
            geo_writer.clone(),
            geo_cache_data.clone(),
            client.clone(),
            config.waf.clone(),
        );
        let service = pproxy.build_service(server.configuration.clone(), addr.to_string(), tls)?;
        server.add_service(service);
    }

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
    debug!("Using config: {:?}", &config);

    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let get_cache_data = GeoData::load_geo_data(config.waf.geo_cache_file_path.as_str())
        .await
        .unwrap_or(HashMap::new());
    let (geo_writer, geo_receiver) = mpsc::channel(1000);

    let local_config = config.clone();
    let writer = GeoWriter::open(&config.waf.geo_cache_file_path, geo_receiver).await?;
    writer.run().await;

    let monitors: Arc<HashMap<String, Arc<MonitorState>>> = Arc::new(
        config
            .monitors
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v.into())))
            .collect(),
    );

    let monitors_local = monitors.clone();

    tokio::spawn(async move {
        if let Err(e) = init_control(
            config.control,
            monitors_local,
            config.static_files_path.as_str(),
        )
        .await
        {
            error!("{e}");
        }
    });

    for monitor in monitors.values() {
        let local = monitor.clone();
        tokio::spawn(async move {
            MonitorState::monitor_service(local).await;
        });
    }

    let monitors_local = monitors.clone();
    tokio::task::spawn_blocking(move || {
        init_pingora(local_config, geo_writer, get_cache_data, monitors_local)?;
        Ok::<(), AppError>(())
    })
    .await??;
    Ok(())
}
