//! # ipdata
//!
//! Rust client for the [ipdata.co](https://ipdata.co) IP geolocation and
//! threat intelligence API.
//!
//! ## Quick Start
//!
//! ```no_run
//! # async fn example() -> ipdata::Result<()> {
//! let client = ipdata::IpData::new("your-api-key");
//!
//! // Look up a specific IP
//! let info = client.lookup("8.8.8.8").await?;
//! println!("{} is in {}", info.ip, info.country_name.unwrap_or_default());
//!
//! // Look up your own IP
//! let me = client.lookup_self().await?;
//!
//! // Bulk lookup (up to 100 IPs, requires paid key)
//! let results = client.bulk(&["8.8.8.8", "1.1.1.1"]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Response types
//!
//! [`IpInfo`] and the nested types ([`Asn`], [`Threat`], [`TimeZone`] and the others)
//! ignore unknown keys and decode a missing key and an explicit JSON `null` the same
//! way: `Option` fields read `None`, every other field reads its default (`""`, `false`,
//! `0`, `0.0` or an empty list). A `null` anywhere in a response never fails a lookup.

mod client;
mod error;
mod types;

pub use client::IpData;
pub use error::{Error, Result};
pub use types::{
    Asn, Blocklist, Carrier, Company, Currency, IpInfo, Language, Threat, ThreatScores, TimeZone,
};
