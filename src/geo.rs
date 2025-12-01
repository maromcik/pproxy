use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Display;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum CountryCode {
    Sk,
    Cz,
    Gb,
    Other,
}

impl CountryCode {
    pub fn is_allowed(&self) -> bool {
        match self {
            CountryCode::Sk | CountryCode::Cz | CountryCode::Gb => true,
            CountryCode::Other => false,
        }
    }
}

impl From<&str> for CountryCode {
    fn from(s: &str) -> Self {
        match s {
            "SK" => Self::Sk,
            "CZ" => Self::Cz,
            "GB" => Self::Gb,
            _ => Self::Other,
        }
    }
}

impl Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CountryCode::Sk => write!(f, "SK"),
            CountryCode::Cz => write!(f, "CZ"),
            CountryCode::Gb => write!(f, "GB"),
            CountryCode::Other => write!(f, "Other"),
        }
    }
}

impl Serialize for CountryCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CountryCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(CountryCode::from(s.as_str()))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GeoData {
    pub ip: IpAddr,
    pub country_name: String,
    // pub ip_version: String,
    pub country_code2: CountryCode,
    // pub ip_number: String,
    // pub isp: String,
    pub response_message: String,
    // pub response_code: u16,
}
