mod config;
mod error;
mod management;
mod proxy;

use crate::config::{AppConfig, HostConfig};
use crate::error::AppError;
use crate::management::init_control;
use crate::management::monitoring::monitor::{MonitorState, Monitors};
use crate::proxy::service::PingoraService;
use crate::proxy::upstream::{ProxyServer, ServersWithLoadBalancers};
use crate::proxy::waf::WafParsedConfig;
use clap::Parser;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info};
use tracing_appender::non_blocking;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional path to a `YAML or TOML` with configuration.
    #[clap(short, long, value_name = "CONFIG_FILE", default_value = "pproxy.yaml")]
    config: String,
}

fn init_pingora(
    config: AppConfig,
    waf_config: Option<WafParsedConfig>,
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
        working_directory: None,
        group: None,
        threads: num_cpus::get(),
        listener_tasks_per_fd: 1,
        work_stealing: true,
        runtime_enable_alt_timer: false,
        upstream_keepalive_pool_size: 2000,
        upstream_connect_offload_threadpools: None,
        upstream_connect_offload_thread_per_pool: None,
        grace_period_seconds: None,
        graceful_shutdown_timeout_seconds: None,
        max_retries: 16,
        upgrade_sock_connect_accept_max_retries: None,
        max_blocking_threads: None,
        blocking_threads_ttl_seconds: None,
        fast_timeout_to_tokio_threshold_seconds: Some(
            pingora_timeout::fast_timeout::DEFAULT_FAST_TIMEOUT_TO_TOKIO_THRESHOLD.as_secs(),
        ),
        runtime_metrics_poll_time_histogram: false,
        runtime_metrics_poll_time_histogram_scale: None,
        runtime_metrics_poll_time_histogram_resolution_micros: None,
        runtime_metrics_poll_time_histogram_buckets: None,
        daemon_ready_timeout_seconds: None,
        daemon_wait_for_ready: false,
        daemon_notify_timeout_seconds: None,
        downstream_tls_offload_threadpools: None,
        downstream_tls_offload_thread_per_pool: None,
    };

    let mut server = Server::new_with_opt_and_conf(None, conf);
    info!("Pingora Config: {:#?}", server.configuration);
    server.bootstrap();
    info!("Bootstrap done");
    info!("PProxy Config: {:#?}", config);

    for (
        addr,
        HostConfig {
            tls,
            h2_options,
            servers,
        },
    ) in config.hosts
    {
        let addr: SocketAddr = addr.parse()?;
        let mut servers_with_load_balancers = HashMap::new();

        for (sni, server_config) in servers.0 {
            let proxy_server_with_healthcheck = ProxyServer::from_config(server_config)?;

            for srv in proxy_server_with_healthcheck {
                for health_check in srv.healthchecks {
                    server.add_service(health_check);
                }
                servers_with_load_balancers.insert(sni.clone(), srv.proxy_server);
            }
        }

        let pproxy = PingoraService::new(
            addr,
            tls,
            h2_options,
            monitors.clone(),
            ServersWithLoadBalancers(servers_with_load_balancers),
            waf_config.clone(),
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
    let (non_blocking, _non_blocking_guard) = non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let local_config = config.clone();
    let monitors: Arc<HashMap<String, Arc<MonitorState>>> = Arc::new(
        config
            .monitors
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v.into())))
            .collect(),
    );

    let monitors_local = monitors.clone();

    if let Some(control) = config.control {
        tokio::spawn(async move {
            if let Err(e) =
                init_control(control, monitors_local, config.static_files_path.as_str()).await
            {
                error!("{e}");
            }
        });
    }

    for monitor in monitors.values() {
        let local = monitor.clone();
        tokio::spawn(async move {
            MonitorState::monitor_service(local).await;
        });
    }

    let waf_config = WafParsedConfig::new(config.waf).await?;

    let monitors_local = monitors.clone();
    tokio::task::spawn_blocking(move || {
        init_pingora(local_config, waf_config, monitors_local)?;
        Ok::<(), AppError>(())
    })
    .await??;
    Ok(())
}
