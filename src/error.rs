//! Copyright thomasgruebl 2025
//! License: GNU GPLv3

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CustomError {
    #[error("Parsing error occurred")]
    ParsingError,
    #[error("Network error occurred")]
    NetworkError,
    #[error("IO error occurred. Check the filepath to the file you'd like to exfiltrate.")]
    IOError,
    #[error("Unknown error")]
    Unknown,
}

