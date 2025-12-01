use std::fmt::Debug;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum AppError {
    #[error("command error: {0}")]
    CommandError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("request error: {0}")]
    RequestError(String),
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
