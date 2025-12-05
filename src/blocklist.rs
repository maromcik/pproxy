use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct BlocklistIp {
    pub ip: ipnetwork::IpNetwork,
}
