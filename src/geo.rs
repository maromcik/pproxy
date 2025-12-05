use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

// #[derive(Debug, Clone, Copy)]
// pub enum CountryCode {
//     Sk,
//     Cz,
//     Gb,
//     Other,
// }
//
// impl CountryCode {
//     pub fn is_blocked(&self) -> bool {
//         match self {
//             CountryCode::Sk | CountryCode::Cz | CountryCode::Gb => false,
//             CountryCode::Other => true,
//         }
//     }
// }
//
// impl From<&str> for CountryCode {
//     fn from(s: &str) -> Self {
//         match s.to_lowercase().as_str() {
//             "sk" => Self::Sk,
//             "cz" => Self::Cz,
//             "gb" => Self::Gb,
//             _ => Self::Other,
//         }
//     }
// }
//
// impl Display for CountryCode {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             CountryCode::Sk => write!(f, "sk"),
//             CountryCode::Cz => write!(f, "cz"),
//             CountryCode::Gb => write!(f, "gb"),
//             CountryCode::Other => write!(f, "other"),
//         }
//     }
// }

// impl Serialize for CountryCode {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         serializer.serialize_str(&self.to_string())
//     }
// }
//
// impl<'de> Deserialize<'de> for CountryCode {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let s = String::deserialize(deserializer)?;
//         Ok(CountryCode::from(s.as_str()))
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct GeoData {
    pub ip: IpAddr,
    pub country_name: String,
    // pub ip_version: String,
    pub country_code2: CountryCode,
    // pub ip_number: u16,
    pub isp: String,
    pub response_message: String,
    pub response_code: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct CountryCode {
    code: String,
}

impl CountryCode {
    pub fn is_blocked(&self, allow_list: &HashSet<CountryCode>) -> bool {
        allow_list.contains(self)
    }
}
