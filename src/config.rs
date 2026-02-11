use crate::error::AppError;
use crate::management::monitoring::monitor::MonitorState;
use config::Config;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use ipnetwork::IpNetwork;
use tracing::debug;



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Servers(pub HashMap<String, ServerConfig>);

impl Servers {
    pub fn get_server(&self, name: &str) -> Option<&ServerConfig> {
        self.0.get(name.strip_prefix("www.").unwrap_or(name))
    }
}

fn default_info<'a>() -> String {
    String::from("info")
}
fn default_static_files<'a>() -> String {
    String::from("static")
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub upstream: String,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub user_agent_blocklist: Option<HashSet<String>>,
    #[serde(default)]
    pub geo_fence_country_allowlist: Option<HashSet<String>>,
    #[serde(default)]
    pub geo_fence_isp_blocklist: Option<HashSet<String>>,
    #[serde(default)]
    pub ip_rules: Option<Vec<IpRule>>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub proxy_headers: HashMap<String, String>,
    #[serde(default)]
    pub monitor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpRule {
    pub subnet: IpNetwork,
    pub action: RuleAction,
    pub source: IpSource,
}

impl RuleAction {
    pub fn match_rule(&self) -> bool {
        match self {
            RuleAction::Deny => {
                debug!("BLOCKED:RULE: {:?}", self);
                true
            }
            RuleAction::Allow => {
                debug!("ALLOWED:RULE: {:?}", self);
                false
            }
        }
    }
}

impl IpRule {
    pub fn contains(&self, addr: Option<IpAddr>) -> bool {
        if let Some(ip) = addr && self.subnet.contains(ip) {
            true
        }
        else {
            false
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub enum IpSource {
    Forwarded,
    Direct,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub enum RuleAction {
    Deny,
    Allow,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostConfig {
    pub tls: bool,
    pub servers: Servers,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorConfig {
    pub suspend_timeout: u64,
    pub commands: CommandConfig,
}

impl From<MonitorConfig> for MonitorState {
    fn from(value: MonitorConfig) -> Self {
        Self::new(Duration::from_secs(value.suspend_timeout), value.commands)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandConfig {
    pub check_command: String,
    pub wake_command: String,
    pub suspend_command: String,
    #[serde(default)]
    pub status_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlConfig {
    pub listen: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    #[serde(default)]
    pub blocklist_url: Option<String>,
    #[serde(default)]
    pub geo_api_url: String,
    #[serde(default)]
    pub geo_cache_file_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub control: ControlConfig,

    #[serde(default)]
    pub hosts: HashMap<String, HostConfig>,

    #[serde(default)]
    pub monitors: HashMap<String, MonitorConfig>,

    // #[serde(default)]
    pub waf: WafConfig,

    #[serde(default = "default_info")]
    pub app_log_level: String,
    #[serde(default = "default_info")]
    pub all_log_level: String,
    #[serde(default = "default_static_files")]
    pub static_files_path: String,
}

impl AppConfig {
    pub fn parse_config(settings_path: &str) -> Result<AppConfig, AppError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(settings_path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        let config = settings.try_deserialize::<AppConfig>()?;

        Ok(config)
    }
}
