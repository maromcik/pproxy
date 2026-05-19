use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc};

use reqwest::Client;

use crate::config::WafConfig;
use crate::error::AppError;
use crate::proxy::geo::{GeoData, GeoWriter};

#[derive(Clone)]
pub struct WafParsedConfig {
    pub waf_config: WafConfig,
    pub geo_cache_writer: mpsc::Sender<GeoData>,
    pub geo_cache_data: HashMap<IpAddr, GeoData>,
    pub geo_api_client: Client,
}

impl WafParsedConfig {
    pub async fn new(waf_config: Option<WafConfig>) -> Result<Option<Self>, AppError> {
        let Some(waf) = waf_config else {
            return Ok(None);
        };
        let get_cache_data = GeoData::load_geo_data(waf.geo_cache_file_path.as_str())
            .await
            .unwrap_or(HashMap::new());
        let (geo_writer, geo_receiver) = mpsc::channel(1000);
        let writer = GeoWriter::open(&waf.geo_cache_file_path, geo_receiver).await?;
        writer.run().await;
        let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
        Ok(Some(Self {
            waf_config: waf,
            geo_cache_writer: geo_writer,
            geo_cache_data: get_cache_data,
            geo_api_client: client,
        }))
    }
}

pub struct Waf {
    pub waf_config: WafConfig,
    pub geo_fence: RwLock<HashMap<IpAddr, GeoData>>,
    pub geo_api_client: Mutex<Client>,
    pub blocked_ips: RwLock<HashSet<IpAddr>>,
    pub geo_cache_writer: mpsc::Sender<GeoData>,
}

impl From<WafParsedConfig> for Waf {
    fn from(waf_parsed_config: WafParsedConfig) -> Self {
        Self {
            geo_fence: RwLock::new(waf_parsed_config.geo_cache_data),
            geo_api_client: Mutex::new(waf_parsed_config.geo_api_client),
            blocked_ips: RwLock::new(HashSet::new()),
            geo_cache_writer: waf_parsed_config.geo_cache_writer.clone(),
            waf_config: waf_parsed_config.waf_config,
        }
    }
}
