use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct BlocklistIp {
    pub ip: ipnet::IpNet,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub user_agent: Option<String>,
}
