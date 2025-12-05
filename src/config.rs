use crate::error::AppError;
use crate::geo::CountryCode;
use config::Config;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type Servers = HashMap<String, ServerConfig>;

fn default_info<'a>() -> String {
    String::from("info")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub upstream: String,
    #[serde(default)]
    pub suspending: bool,
    #[serde(default)]
    pub user_agent_blocklist: Option<HashSet<String>>,
    pub geo_fence_allowlist: Option<HashSet<CountryCode>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandConfig {
    pub check_command: String,
    pub wake_command: String,
    pub suspend_command: String,
    #[serde(default)]
    pub status_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub listen_host: String,
    pub listen_control_host: String,
    #[serde(default)]
    pub servers: Servers,
    pub commands: CommandConfig,
    pub suspend_timeout: u64,
    #[serde(default = "default_info")]
    pub app_log_level: String,
    #[serde(default = "default_info")]
    pub all_log_level: String,
}

pub fn parse_config(settings_path: &str) -> Result<AppConfig, AppError> {
    let settings = Config::builder()
        .add_source(config::File::with_name(settings_path))
        .add_source(config::Environment::with_prefix("APP"))
        .build()?;

    let config = settings.try_deserialize::<AppConfig>()?;

    Ok(config)
}
