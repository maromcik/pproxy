use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::IpAddr;
use serde_json::from_str;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::warn;
use crate::error::AppError;
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

pub struct GeoWriter {
    file: tokio::fs::File,
    rx: tokio::sync::mpsc::Receiver<GeoData>,
}

impl GeoWriter {
    pub async fn open(
        path: &str,
        rx: tokio::sync::mpsc::Receiver<GeoData>,
    ) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self { file, rx })
    }

    pub async fn run(mut self) {
        tokio::spawn(async move {
            while let Some(data) = self.rx.recv().await {
                let mut json = match serde_json::to_string(&data) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("could not serialize: {data}; {e}");
                        continue;
                    }
                };
                json = json + "\n";
                if let Err(e) = self.file.write_all(json.as_bytes()).await {
                    warn!("could not write to file: {e}");
                }
            }
        });
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GeoData {
    pub ip: IpAddr,
    pub country_name: String,
    // pub ip_version: String,
    pub country_code2: String,
    // pub ip_number: u16,
    pub isp: String,
    pub response_message: String,
    pub response_code: String,
}

impl GeoData {
    pub async fn load_geo_data(path: &str) -> Result<HashMap<IpAddr, GeoData>, AppError> {
        let file = File::open(path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut results: HashMap<IpAddr, GeoData> = HashMap::new();
        
        while let Some(line) = lines.next_line().await? {
            let data: GeoData = from_str(&line)?;
            results.insert(data.ip, data);
        }
        Ok(results)
    }
}

impl Display for GeoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IP: {}, CN: {}, CC: {}, ISP: {}",
            self.ip, self.country_name, self.country_code2, self.isp
        )
    }
}

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
// pub struct CountryCode {
//     code: String,
// }
//
// impl CountryCode {
//     pub fn is_blocked(&self, allow_list: &HashSet<CountryCode>) -> bool {
//         allow_list.contains(self)
//     }
// }
