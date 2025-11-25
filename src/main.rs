mod proxy;
mod utils;
mod error;

use crate::proxy::{ImmichProxy, MonitorService, ServerState};
use clap::Parser;
use pingora::prelude::*;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::time::Instant;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser, Default)]
struct PreCli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,

    /// Server host to proxy to, e.g. example.com or 192.168.0.10.
    #[clap(short = 'u', long, value_name = "ORIGIN_HOST", env = "ORIGIN_HOST")]
    origin_host: String,

    #[clap(short = 'l', long, value_name = "LISTEN_HOST", env = "LISTEN_HOST")]
    listen_host: String,

    #[clap(
        short = 's',
        long,
        value_name = "SUSPEND_COMMAND",
        env = "SUSPEND_COMMAND"
    )]
    suspend_command: String,

    #[clap(
        short = 'c',
        long,
        value_name = "CHECK_COMMAND",
        env = "CHECK_COMMAND"
    )]
    check_command: String,
    
    #[clap(short = 'w', long, value_name = "WAKE_COMMAND", env = "WAKE_COMMAND")]
    wake_command: String,

    #[clap(
        short = 't',
        long,
        value_name = "SUSPEND_TIMEOUT",
        env = "SUSPEND_TIMEOUT",
        default_value = "10"
    )]
    suspend_timeout: u64,

    /// Optional log level.
    #[clap(
        long,
        value_name = "LOG_LEVEL",
        env = "LOG_LEVEL",
        default_value = "info"
    )]
    log_level: String,
}

fn main() {
    let pre = PreCli::try_parse().unwrap_or_default();
    if let Some(env_file) = pre.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
    } else {
        dotenvy::dotenv().ok();
    }

    let cli = Cli::parse();

    let env = EnvFilter::new(cli.log_level);
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let mut server = Server::new(Some(Opt::default())).unwrap();
    server.bootstrap();
    let state = Arc::new(ServerState {
        timer: Instant::now().into(),
        suspended: AtomicBool::new(false),
        limit: Duration::from_secs(cli.suspend_timeout),
        suspend_command: cli.suspend_command,
        check_command: cli.check_command,
        wake_command: cli.wake_command,
        waking: AtomicBool::new(false),
    });

    let monitor_service = MonitorService {
        state: state.clone(),
    };
    server.add_service(monitor_service);

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        ImmichProxy {
            upstream_addr: cli.origin_host,
            state,
        },
    );

    proxy_service.add_tcp(&cli.listen_host);

    server.add_service(proxy_service);
    server.run_forever();
}
