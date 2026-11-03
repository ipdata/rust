use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

use crate::error::{ApiErrorResponse, Error, Result};
use crate::types::{Asn, BulkResponse, Carrier, Currency, IpInfo, Threat, TimeZone};

/// Default global API endpoint.
const DEFAULT_BASE_URL: &str = "https://api.ipdata.co";

/// EU-specific API endpoint (GDPR-compliant, backed by EU datacenters).
const EU_BASE_URL: &str = "https://eu-api.ipdata.co";

/// Maximum number of IPs in a single bulk request.
const BULK_LIMIT: usize = 100;

/// SDK version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Idle time after which the client closes a pooled connection.
///
/// The API drops idle connections itself after roughly two minutes; closing them
/// earlier on the client side avoids sending a request into a socket the server has
/// already given up on.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between HTTP/2 keep-alive PING frames.
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Time a keep-alive PING may stay unanswered before the connection is closed.
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between TCP keep-alive probes.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// Client for the ipdata.co API.
///
/// An `IpData` owns a [`reqwest::Client`] whose pool of HTTPS connections is kept
/// alive and reused across requests. Build the client once (per process, or one per
/// API key or endpoint) and reuse it for every lookup: each call to [`IpData::new`],
/// [`IpData::eu`] or [`IpData::with_base_url`] creates a new pool, and the first
/// request on a new pool pays a fresh TCP and TLS handshake. Requests use HTTP/2 when
/// the server negotiates it and fall back to HTTP/1.1 keep-alive otherwise.
///
/// `IpData` is `Send + Sync`, so one instance can be shared across tasks and threads
/// by reference or in an `Arc`. `Clone` is cheap: a clone shares the connection pool
/// of the client it was cloned from. There is no close method; dropping the last clone
/// releases the pool and its connections. Pooled connections are closed after 60
/// seconds idle, HTTP/2 connections are kept alive with a PING every 30 seconds, and
/// TCP keep-alive probes are sent every 30 seconds.
///
/// To reuse an existing [`reqwest::Client`], or to set timeouts, proxies or TLS
/// options, use [`IpData::with_client`].
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> ipdata::Result<()> {
/// let client = ipdata::IpData::new("your-api-key");
/// let info = client.lookup("8.8.8.8").await?;
/// println!("{} is in {}", info.ip, info.country_name.unwrap_or_default());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct IpData {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl IpData {
    /// Creates a new client using the global API endpoint.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_base_url(api_key, DEFAULT_BASE_URL)
    }

    /// Creates a new client using the EU API endpoint.
    ///
    /// The EU endpoint is backed by datacenters in Frankfurt, Paris, and Ireland.
    pub fn eu(api_key: impl Into<String>) -> Self {
        Self::with_base_url(api_key, EU_BASE_URL)
    }

    /// Creates a new client with a custom base URL.
    pub fn with_base_url(api_key: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self::with_client(api_key, base_url, build_http_client())
    }

    /// Creates a client that sends its requests through a caller-supplied
    /// [`reqwest::Client`].
    ///
    /// Use this to share one connection pool with the rest of your application, or to
    /// configure timeouts, proxies, TLS roots or other options the default client does
    /// not set. The client is used as given: the SDK's `User-Agent` header
    /// (`ipdata-rust/<version>`) and its keep-alive tuning are only applied by the
    /// default client, so add them to your builder if you want them. `base_url` is the
    /// API endpoint, normally `https://api.ipdata.co` or `https://eu-api.ipdata.co`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn example() -> Result<(), reqwest::Error> {
    /// let http = reqwest::Client::builder()
    ///     .timeout(std::time::Duration::from_secs(10))
    ///     .build()?;
    /// let client = ipdata::IpData::with_client("your-api-key", "https://api.ipdata.co", http);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_client(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            client,
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Looks up geolocation and threat data for an IP address.
    ///
    /// Accepts IPv4 and IPv6 addresses. Returns all available fields.
    pub async fn lookup(&self, ip: &str) -> Result<IpInfo> {
        validate_ip(ip)?;
        let url = format!("{}/{}", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Looks up geolocation and threat data for the caller's own IP.
    pub async fn lookup_self(&self) -> Result<IpInfo> {
        self.get(&self.base_url, &[]).await
    }

    /// Looks up an IP address returning only the specified fields.
    ///
    /// # Arguments
    ///
    /// * `ip` - IPv4 or IPv6 address
    /// * `fields` - List of field names (e.g. `["ip", "country_name", "asn"]`)
    pub async fn lookup_fields(&self, ip: &str, fields: &[&str]) -> Result<IpInfo> {
        validate_ip(ip)?;
        let url = format!("{}/{}", self.base_url, ip);
        self.get(&url, fields).await
    }

    /// Looks up a single field for an IP address.
    ///
    /// Returns the raw JSON value for the requested field.
    ///
    /// # Arguments
    ///
    /// * `ip` - IPv4 or IPv6 address
    /// * `field` - Field name (e.g. `"asn"`, `"threat"`, `"currency"`)
    pub async fn lookup_field(&self, ip: &str, field: &str) -> Result<serde_json::Value> {
        validate_ip(ip)?;
        let url = format!("{}/{}/{}", self.base_url, ip, field);
        self.get(&url, &[]).await
    }

    /// Returns ASN (Autonomous System Number) data for an IP address.
    pub async fn asn(&self, ip: &str) -> Result<Asn> {
        validate_ip(ip)?;
        let url = format!("{}/{}/asn", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Returns mobile carrier data for an IP address.
    pub async fn carrier(&self, ip: &str) -> Result<Carrier> {
        validate_ip(ip)?;
        let url = format!("{}/{}/carrier", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Returns currency data for an IP address.
    pub async fn currency(&self, ip: &str) -> Result<Currency> {
        validate_ip(ip)?;
        let url = format!("{}/{}/currency", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Returns time zone data for an IP address.
    pub async fn time_zone(&self, ip: &str) -> Result<TimeZone> {
        validate_ip(ip)?;
        let url = format!("{}/{}/time_zone", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Returns threat intelligence data for an IP address.
    pub async fn threat(&self, ip: &str) -> Result<Threat> {
        validate_ip(ip)?;
        let url = format!("{}/{}/threat", self.base_url, ip);
        self.get(&url, &[]).await
    }

    /// Performs a bulk lookup for up to 100 IP addresses.
    ///
    /// Requires a paid API key. Returns results in the same order as the input.
    ///
    /// The lookup is a `POST`, which the HTTP stack does not retry on its own once the
    /// request has been written. If a pooled connection turns out to be dead before any
    /// response byte arrives (reset, EOF or broken pipe on a reused socket), the request
    /// is sent again exactly once on a fresh connection. HTTP error statuses and
    /// failures while reading the response body are never retried.
    pub async fn bulk(&self, ips: &[&str]) -> Result<Vec<IpInfo>> {
        if ips.is_empty() {
            return Err(Error::BulkEmpty);
        }
        if ips.len() > BULK_LIMIT {
            return Err(Error::BulkLimitExceeded);
        }

        for ip in ips {
            validate_ip(ip)?;
        }

        let url = format!("{}/bulk", self.base_url);
        let resp = match self.post_bulk(&url, ips).await {
            Ok(resp) => resp,
            // The server or a middlebox can drop a pooled connection while it is idle
            // without the client noticing until the next request fails on it. hyper
            // transparently re-sends a request it had not yet written to such a
            // connection; one that was already written is retried once here. The failed
            // connection has been discarded, so the retry uses a fresh one.
            Err(e) if is_stale_connection_error(&e) => self.post_bulk(&url, ips).await?,
            Err(e) => return Err(e.into()),
        };

        let bulk: BulkResponse = decode_response(resp).await?;
        Ok(bulk.responses)
    }

    /// Sends the bulk `POST` once and returns the raw response.
    async fn post_bulk(&self, url: &str, ips: &[&str]) -> reqwest::Result<reqwest::Response> {
        self.client
            .post(url)
            .query(&[("api-key", &self.api_key)])
            .json(&ips)
            .send()
            .await
    }

    /// Internal GET helper shared by the full lookups, the raw single-field lookup and
    /// the typed sub-resources: sends the API key and, when `fields` is not empty, a
    /// comma-separated `fields` filter, then decodes the JSON body into `T`.
    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str, fields: &[&str]) -> Result<T> {
        let mut req = self.client.get(url).query(&[("api-key", &self.api_key)]);

        if !fields.is_empty() {
            let fields_str = fields.join(",");
            req = req.query(&[("fields", &fields_str)]);
        }

        decode_response(req.send().await?).await
    }
}

/// Builds the [`reqwest::Client`] used by [`IpData::new`], [`IpData::eu`] and
/// [`IpData::with_base_url`].
///
/// The client identifies the SDK with a `User-Agent` default header and is tuned for
/// connection reuse: HTTP/2 is negotiated through ALPN with automatic HTTP/1.1
/// fallback, pooled connections are closed after 60 s idle, HTTP/2 connections are kept
/// alive with a PING every 30 s (10 s to answer, also while idle) and TCP keep-alive
/// probes run every 30 s. No total request timeout is set.
fn build_http_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    let ua = format!("ipdata-rust/{VERSION}");
    headers.insert(USER_AGENT, HeaderValue::from_str(&ua).unwrap());

    reqwest::Client::builder()
        .default_headers(headers)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .tcp_keepalive(TCP_KEEPALIVE)
        .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .http2_keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .build()
        .expect("failed to build HTTP client")
}

/// Whether a `send()` failure means the request died on an established connection
/// before any response arrived: a reset, EOF or broken pipe on a reused socket.
///
/// Connection-level failures (DNS, TCP connect, TLS, proxy) and timeouts are excluded:
/// a retry would not help, or the server may already have received the request.
fn is_stale_connection_error(e: &reqwest::Error) -> bool {
    e.is_request() && !e.is_connect() && !e.is_timeout()
}

/// Validates that a string is a valid IPv4 or IPv6 address.
fn validate_ip(ip: &str) -> Result<()> {
    ip.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| Error::InvalidIp(ip.to_string()))
}

/// Decodes the JSON body of a successful response into `T`. A non-success status
/// becomes [`Error::Api`] with the message from the response body.
async fn decode_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        return Err(parse_error(status.as_u16(), resp).await);
    }

    Ok(resp.json().await?)
}

/// Parses an error response from the API.
async fn parse_error(status: u16, resp: reqwest::Response) -> Error {
    let message = match resp.json::<ApiErrorResponse>().await {
        Ok(body) => body.message,
        Err(_) => format!("request failed with status {status}"),
    };
    Error::Api { status, message }
}
