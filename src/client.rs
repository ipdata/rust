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

/// Client for the ipdata.co API.
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
        let mut headers = HeaderMap::new();
        let ua = format!("ipdata-rust/{VERSION}");
        headers.insert(USER_AGENT, HeaderValue::from_str(&ua).unwrap());

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("failed to build HTTP client");

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
    pub async fn lookup_field(
        &self,
        ip: &str,
        field: &str,
    ) -> Result<serde_json::Value> {
        validate_ip(ip)?;
        let url = format!("{}/{}/{}", self.base_url, ip, field);
        let resp = self
            .client
            .get(&url)
            .query(&[("api-key", &self.api_key)])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(parse_error(status.as_u16(), resp).await);
        }

        let text = resp.text().await?;
        match serde_json::from_str(&text) {
            Ok(value) => Ok(value),
            Err(_) => Ok(serde_json::Value::String(text.trim().to_string())),
        }
    }

    /// Returns ASN (Autonomous System Number) data for an IP address.
    pub async fn asn(&self, ip: &str) -> Result<Asn> {
        validate_ip(ip)?;
        let url = format!("{}/{}/asn", self.base_url, ip);
        self.get_typed(&url).await
    }

    /// Returns mobile carrier data for an IP address.
    pub async fn carrier(&self, ip: &str) -> Result<Carrier> {
        validate_ip(ip)?;
        let url = format!("{}/{}/carrier", self.base_url, ip);
        self.get_typed(&url).await
    }

    /// Returns currency data for an IP address.
    pub async fn currency(&self, ip: &str) -> Result<Currency> {
        validate_ip(ip)?;
        let url = format!("{}/{}/currency", self.base_url, ip);
        self.get_typed(&url).await
    }

    /// Returns time zone data for an IP address.
    pub async fn time_zone(&self, ip: &str) -> Result<TimeZone> {
        validate_ip(ip)?;
        let url = format!("{}/{}/time_zone", self.base_url, ip);
        self.get_typed(&url).await
    }

    /// Returns threat intelligence data for an IP address.
    pub async fn threat(&self, ip: &str) -> Result<Threat> {
        validate_ip(ip)?;
        let url = format!("{}/{}/threat", self.base_url, ip);
        self.get_typed(&url).await
    }

    /// Performs a bulk lookup for up to 100 IP addresses.
    ///
    /// Requires a paid API key. Returns results in the same order as the input.
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
        let resp = self
            .client
            .post(&url)
            .query(&[("api-key", &self.api_key)])
            .json(&ips)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(parse_error(status.as_u16(), resp).await);
        }

        let bulk: BulkResponse = resp.json().await?;
        Ok(bulk.responses)
    }

    /// Internal typed GET helper for sub-resource endpoints.
    async fn get_typed<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self
            .client
            .get(url)
            .query(&[("api-key", &self.api_key)])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(parse_error(status.as_u16(), resp).await);
        }

        Ok(resp.json().await?)
    }

    /// Internal GET helper for IP lookups with optional field filtering.
    async fn get(&self, url: &str, fields: &[&str]) -> Result<IpInfo> {
        let mut req = self.client.get(url).query(&[("api-key", &self.api_key)]);

        if !fields.is_empty() {
            let fields_str = fields.join(",");
            req = req.query(&[("fields", &fields_str)]);
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(parse_error(status.as_u16(), resp).await);
        }

        Ok(resp.json().await?)
    }
}

/// Validates that a string is a valid IPv4 or IPv6 address.
fn validate_ip(ip: &str) -> Result<()> {
    ip.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| Error::InvalidIp(ip.to_string()))
}

/// Parses an error response from the API.
async fn parse_error(status: u16, resp: reqwest::Response) -> Error {
    let message = match resp.json::<ApiErrorResponse>().await {
        Ok(body) => body.message,
        Err(_) => format!("request failed with status {status}"),
    };
    Error::Api { status, message }
}
