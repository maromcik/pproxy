use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum AppError {
    #[error("command error: {0}")]
    CommandError(String),
}

impl Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}
