/// Error type for the ipdata client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP transport error from reqwest.
    #[error("{0}")]
    Http(#[from] reqwest::Error),

    /// API returned a non-success status code.
    #[error("API error (HTTP {status}): {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Error message from the API response.
        message: String,
    },

    /// The provided string is not a valid IP address.
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Bulk lookup exceeds the maximum of 100 IPs.
    #[error("bulk lookup exceeds maximum of 100 IPs")]
    BulkLimitExceeded,

    /// Bulk lookup requires at least one IP address.
    #[error("bulk lookup requires at least one IP address")]
    BulkEmpty,
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// API error response body.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub message: String,
}

impl Error {
    /// Returns the HTTP status code if this is an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}
