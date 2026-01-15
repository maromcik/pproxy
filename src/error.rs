use std::fmt::Debug;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum AppError {
    #[error("command error: {0}")]
    CommandError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("request error: {0}")]
    RequestError(String),
    #[error("task/join error: {0}")]
    TaskError(String),
    #[error("I/O error: {0}")]
    IOError(String),
    #[error("serialize/deserialize error: {0}")]
    SerdeError(String),
}

impl Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}

impl From<AddrParseError> for AppError {
    fn from(e: AddrParseError) -> Self {
        Self::ParseError(e.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        Self::RequestError(e.to_string())
    }
}

impl From<config::ConfigError> for AppError {
    fn from(e: config::ConfigError) -> Self {
        Self::ConfigError(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeError(e.to_string())
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::TaskError(e.to_string())
    }
}
