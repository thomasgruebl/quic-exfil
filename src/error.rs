//! Copyright thomasgruebl 2025
//! License: GNU GPLv3

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CustomError {
    #[error("Parsing error occurred")]
    ParsingError,
    #[error("Network error occurred")]
    NetworkError,
    #[error("IO error occurred")]
    IOError,
    #[error("Unknown error")]
    Unknown,
}

