use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use reqwest::Client;
use tokio::sync::{mpsc, Mutex, RwLock};
use crate::config::Servers;
use crate::geo::GeoData;
use crate::ServerState;

pub struct PService {
    pub state: Arc<ServerState>,
    pub servers: Servers,
    pub geo_fence: RwLock<HashMap<IpAddr, GeoData>>,
    pub geo_api_client: Mutex<Client>,
    pub blocked_ips: RwLock<HashSet<IpAddr>>,
    pub geo_cache_writer: mpsc::Sender<GeoData>,
}

pub struct PServiceBuilder {

}