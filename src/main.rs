pub mod blocklist;
mod config;
mod error;
mod geo;
mod management;
mod proxy;
mod templates;
mod utils;

use crate::config::{AppConfig, HostConfig};
use crate::error::AppError;
use crate::geo::{GeoData, GeoWriter};
use crate::management::{ControlService, MonitorService, MonitorState};
use clap::Parser;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use reqwest::Client;
use std::collections::{HashMap};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{mpsc};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use crate::proxy::PProxy;

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
        upgrade_sock_connect_accept_max_retries: None,
    };

    let mut server = Server::new_with_opt_and_conf(None, conf);
    info!("Server conf: {:?}", server.configuration);
    server.bootstrap();

    let state = MonitorState::new(
        Duration::from_secs(config.monitors.get("hp").unwrap().suspend_timeout),
        config.monitors.get("hp").unwrap().commands.clone());


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
    
    for (addr, HostConfig {tls, servers }) in config.hosts.into_iter() {
        let pproxy = PProxy::new(state.clone(), servers.clone(), geo_writer.clone(), geo_cache_data.clone(), client.clone(), config.waf.clone());
        let service = pproxy.build_service(server.configuration.clone(), addr, tls);
        server.add_service(service);
    }

    control_service.add_tcp(&config.listen_control);
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
    tokio::task::spawn_blocking(move || {
        init_pingora(local_config, geo_writer, get_cache_data)?;
        Ok::<(), AppError>(())
    })
    .await??;
    Ok(())
}
