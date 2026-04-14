pub mod cache;
pub mod config;
pub mod credential;
pub mod mfa;
pub mod okta;
pub mod profile;
pub mod sts;

use thiserror::Error;

#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDeserialize(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid cache format: {0}")]
    CacheFormat(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("MFA error: {0}")]
    Mfa(String),

    #[error("STS error: {0}")]
    Sts(String),

    #[error("SAML error: {0}")]
    Saml(String),

    #[error("profile error: {0}")]
    Profile(String),

    #[error("invalid profile name: {0}")]
    InvalidProfileName(String),

    #[error("missing configuration: {0}")]
    MissingConfig(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

pub type Result<T> = std::result::Result<T, Error>;
