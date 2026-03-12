use serde::{Deserialize, Serialize};

/// Full IP geolocation and threat intelligence response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpInfo {
    /// The queried IP address.
    #[serde(default)]
    pub ip: String,

    /// Whether the IP is in an EU member country.
    #[serde(default)]
    pub is_eu: Option<bool>,

    /// City name.
    #[serde(default)]
    pub city: Option<String>,

    /// Region / state / province name.
    #[serde(default)]
    pub region: Option<String>,

    /// Region code (e.g. "CA" for California).
    #[serde(default)]
    pub region_code: Option<String>,

    /// Type of region (e.g. "state", "province").
    #[serde(default)]
    pub region_type: Option<String>,

    /// Full country name.
    #[serde(default)]
    pub country_name: Option<String>,

    /// ISO 3166-1 alpha-2 country code.
    #[serde(default)]
    pub country_code: Option<String>,

    /// Continent name.
    #[serde(default)]
    pub continent_name: Option<String>,

    /// Continent code (e.g. "NA", "EU").
    #[serde(default)]
    pub continent_code: Option<String>,

    /// Latitude.
    #[serde(default)]
    pub latitude: Option<f64>,

    /// Longitude.
    #[serde(default)]
    pub longitude: Option<f64>,

    /// Postal / ZIP code.
    #[serde(default)]
    pub postal: Option<String>,

    /// International calling code (e.g. "1" for US).
    #[serde(default)]
    pub calling_code: Option<String>,

    /// URL to the country flag image.
    #[serde(default)]
    pub flag: Option<String>,

    /// Emoji flag (e.g. "🇺🇸").
    #[serde(default)]
    pub emoji_flag: Option<String>,

    /// Unicode code points for the emoji flag.
    #[serde(default)]
    pub emoji_unicode: Option<String>,

    /// Organization / ISP name.
    #[serde(default)]
    pub organisation: Option<String>,

    /// Autonomous System Number information.
    #[serde(default)]
    pub asn: Option<Asn>,

    /// Company / organization information.
    #[serde(default)]
    pub company: Option<Company>,

    /// Mobile carrier information.
    #[serde(default)]
    pub carrier: Option<Carrier>,

    /// Languages spoken in the country.
    #[serde(default)]
    pub languages: Vec<Language>,

    /// Local currency information.
    #[serde(default)]
    pub currency: Option<Currency>,

    /// Time zone information.
    #[serde(default)]
    pub time_zone: Option<TimeZone>,

    /// Threat intelligence data.
    #[serde(default)]
    pub threat: Option<Threat>,

    /// Number of API requests made in the current period.
    #[serde(default)]
    pub count: Option<String>,

    /// HTTP status code (present in some error responses).
    #[serde(default)]
    pub status: Option<i32>,

    /// Error message (present in bulk responses for failed lookups).
    #[serde(default)]
    pub message: Option<String>,
}

/// Autonomous System Number information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Asn {
    /// ASN string (e.g. "AS15169").
    #[serde(default)]
    pub asn: String,

    /// Organization name.
    #[serde(default)]
    pub name: String,

    /// Organization domain.
    #[serde(default)]
    pub domain: String,

    /// Route prefix (e.g. "8.8.8.0/24").
    #[serde(default)]
    pub route: String,

    /// ASN type: "isp", "business", "education", "hosting", or "inactive".
    #[serde(default, rename = "type")]
    pub asn_type: String,
}

/// Company / organization that owns the IP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Company {
    /// Company name.
    #[serde(default)]
    pub name: String,

    /// Company domain.
    #[serde(default)]
    pub domain: String,

    /// Network CIDR.
    #[serde(default)]
    pub network: String,

    /// Type: "isp", "business", "education", or "hosting".
    #[serde(default, rename = "type")]
    pub company_type: String,
}

/// Mobile carrier information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Carrier {
    /// Carrier name.
    #[serde(default)]
    pub name: Option<String>,

    /// Mobile Country Code.
    #[serde(default)]
    pub mcc: Option<String>,

    /// Mobile Network Code.
    #[serde(default)]
    pub mnc: Option<String>,
}

/// Language spoken in the country.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Language {
    /// Language name in English.
    #[serde(default)]
    pub name: String,

    /// Language name in its native form.
    #[serde(default)]
    pub native: String,

    /// ISO 639-1 language code.
    #[serde(default)]
    pub code: Option<String>,
}

/// Currency used in the country.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Currency {
    /// Currency name (e.g. "US Dollar").
    #[serde(default)]
    pub name: String,

    /// ISO 4217 currency code (e.g. "USD").
    #[serde(default)]
    pub code: String,

    /// Currency symbol (e.g. "$").
    #[serde(default)]
    pub symbol: String,

    /// Native currency symbol.
    #[serde(default)]
    pub native: String,

    /// Plural form of the currency name.
    #[serde(default)]
    pub plural: String,
}

/// Time zone information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeZone {
    /// IANA time zone name (e.g. "America/New_York").
    #[serde(default)]
    pub name: Option<String>,

    /// Time zone abbreviation (e.g. "EST").
    #[serde(default, rename = "abbr")]
    pub abbreviation: Option<String>,

    /// UTC offset string (e.g. "-0500").
    #[serde(default)]
    pub offset: Option<String>,

    /// Whether daylight saving time is active.
    #[serde(default)]
    pub is_dst: bool,

    /// Current time in the time zone (ISO 8601).
    #[serde(default)]
    pub current_time: Option<String>,
}

/// Threat intelligence data for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Threat {
    /// Whether the IP is a known Tor exit node.
    #[serde(default)]
    pub is_tor: bool,

    /// Whether the IP belongs to a known VPN provider.
    #[serde(default)]
    pub is_vpn: bool,

    /// Whether the IP is an iCloud Private Relay address.
    #[serde(default)]
    pub is_icloud_relay: bool,

    /// Whether the IP is a known proxy.
    #[serde(default)]
    pub is_proxy: bool,

    /// Whether the IP belongs to a data center.
    #[serde(default)]
    pub is_datacenter: bool,

    /// Whether the IP is anonymous (Tor, proxy, or VPN).
    #[serde(default)]
    pub is_anonymous: bool,

    /// Whether the IP is a known attacker.
    #[serde(default)]
    pub is_known_attacker: bool,

    /// Whether the IP is a known abuser.
    #[serde(default)]
    pub is_known_abuser: bool,

    /// Whether the IP is listed in any threat feed.
    #[serde(default)]
    pub is_threat: bool,

    /// Whether the IP is a bogon (unallocated/reserved).
    #[serde(default)]
    pub is_bogon: bool,

    /// Threat feeds that list this IP.
    #[serde(default)]
    pub blocklists: Vec<Blocklist>,

    /// Machine-learning-based threat scores.
    #[serde(default)]
    pub scores: Option<ThreatScores>,
}

/// Machine-learning-based reputation scores for an IP address.
///
/// Each score is a value between 0 and 100.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatScores {
    /// VPN likelihood score.
    #[serde(default)]
    pub vpn_score: i32,

    /// Proxy likelihood score.
    #[serde(default)]
    pub proxy_score: i32,

    /// Overall threat score.
    #[serde(default)]
    pub threat_score: i32,

    /// Trust / reputation score.
    #[serde(default)]
    pub trust_score: i32,
}

/// A threat blocklist entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blocklist {
    /// Blocklist name.
    #[serde(default)]
    pub name: String,

    /// Blocklist website URL.
    #[serde(default)]
    pub site: String,

    /// Blocklist category / type.
    #[serde(default, rename = "type")]
    pub blocklist_type: String,
}

/// Response wrapper for bulk lookups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct BulkResponse {
    pub responses: Vec<IpInfo>,
}
