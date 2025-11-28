mod error;
mod management;
mod proxy;
mod templates;
mod utils;

use crate::management::{ControlService, MonitorService};
use crate::proxy::SuspendProxy;
use clap::Parser;
use pingora::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{error, info};
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

    /// Jellyfin host to proxy to, e.g. example.com or 192.168.0.10.
    #[clap(short = 'j', long, value_name = "JELLYFIN_HOST", env = "JELLYFIN_HOST")]
    jellyfin_host: String,

    /// Immich host to proxy to, e.g. example.com or 192.168.0.10.
    #[clap(short = 'i', long, value_name = "IMMICH_HOST", env = "IMMICH_HOST")]
    immich_host: String,

    /// Host to listen on for HTTP requests.
    #[clap(short = 'l', long, value_name = "LISTEN_HOST", env = "LISTEN_HOST")]
    listen_host: String,

    /// Host to listen on for the control endpoint.
    #[clap(
        short = 'm',
        long,
        value_name = "LISTEN_CONTROL_HOST",
        env = "LISTEN_CONTROL_HOST"
    )]
    listen_control_host: String,

    /// Command to execute when suspending the server.
    #[clap(
        short = 's',
        long,
        value_name = "SUSPEND_COMMAND",
        env = "SUSPEND_COMMAND"
    )]
    suspend_command: String,

    /// Command to execute when checking if the server is suspended.
    #[clap(short = 'c', long, value_name = "CHECK_COMMAND", env = "CHECK_COMMAND")]
    check_command: String,

    /// Command to execute when waking up the server.
    #[clap(short = 'w', long, value_name = "WAKE_COMMAND", env = "WAKE_COMMAND")]
    wake_command: String,

    #[clap(
        short = 'g',
        long,
        value_name = "STATUS_COMMAND",
        env = "STATUS_COMMAND"
    )]
    status_command: Option<String>,

    /// User agents that will never wake up the server.
    #[clap(
        short = 'u',
        long,
        value_name = "USER_AGENT_BLOCKLIST",
        env = "USER_AGENT_BLOCKLIST"
    )]
    user_agent_blocklist: Option<String>,

    /// Timeout in seconds for suspending the server.
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
        value_name = "APP_LOG_LEVEL",
        env = "APP_LOG_LEVEL",
        default_value = "info"
    )]
    app_log_level: String,

    /// Optional log level for all included components, such as pingora.
    #[clap(
        long,
        value_name = "ALL_LOG_LEVEL",
        env = "ALL_LOG_LEVEL",
        default_value = ""
    )]
    all_log_level: String,
}

pub struct Commands {
    pub suspend: String,
    pub wake: String,
    pub check: String,
    pub status: Option<String>,
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
    pub commands: Commands,
    pub time_monitoring: RwLock<TimeMonitoring>,
    pub logs: Mutex<HashMap<String, (OffsetDateTime, String)>>,
}

fn main() {
    let pre = PreCli::try_parse().unwrap_or_default();
    if let Some(env_file) = pre.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
    } else {
        dotenvy::dotenv().ok();
    }

    let cli = Cli::parse();

    let env =
        EnvFilter::new(format!("pproxy={},{}", cli.app_log_level, cli.all_log_level).as_str());
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let mut server = match Server::new(Some(Opt::default())) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create server: {e}");
            return;
        }
    };
    server.bootstrap();

    let state = Arc::new(ServerState {
        timer: Instant::now().into(),
        suspended: AtomicBool::new(false),
        limit: Duration::from_secs(cli.suspend_timeout),
        wake_up: AtomicBool::new(false),
        suspending: AtomicBool::new(false),
        auto_suspend_enabled: AtomicBool::new(true),
        commands: Commands {
            suspend: cli.suspend_command,
            wake: cli.wake_command,
            check: cli.check_command,
            status: cli.status_command,
        },
        time_monitoring: RwLock::new(TimeMonitoring {
            active_time: Duration::from_secs(0),
            suspended_time: Duration::from_secs(0),
        }),
        logs: Mutex::new(HashMap::new()),
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

    let user_agent_blocklist = cli
        .user_agent_blocklist
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<HashSet<String>>();

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        SuspendProxy {
            upstreams: Upstreams {
                jellyfin: cli.jellyfin_host,
                immich: cli.immich_host,
            },
            state,
            user_agent_blocklist,
        },
    );

    proxy_service.add_tcp(&cli.listen_host);
    control_service.add_tcp(&cli.listen_control_host);

    server.add_service(proxy_service);
    server.add_service(control_service);
    info!("Server starting");
    server.run_forever();
}
