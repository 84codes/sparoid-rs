use std::fmt::{Debug, Display};

#[derive(Debug)]
pub enum SparoidError {
    Http(reqwest::Error),
    AddrParseError(std::net::AddrParseError),
    Io(std::io::Error),
}

impl From<reqwest::Error> for SparoidError {
    fn from(err: reqwest::Error) -> Self {
        SparoidError::Http(err)
    }
}

impl From<std::net::AddrParseError> for SparoidError {
    fn from(err: std::net::AddrParseError) -> Self {
        SparoidError::AddrParseError(err)
    }
}

impl From<std::io::Error> for SparoidError {
    fn from(err: std::io::Error) -> Self {
        SparoidError::Io(err)
    }
}

impl Display for SparoidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SparoidError::Http(e) => write!(f, "HTTP error: {}", e),
            SparoidError::AddrParseError(e) => write!(f, "Address Parse error: {}", e),
            SparoidError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for SparoidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SparoidError::AddrParseError(e) => Some(e),
            SparoidError::Http(e) => Some(e),
            SparoidError::Io(e) => Some(e),
        }
    }
}
