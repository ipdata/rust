# ipdata

Rust client for the [ipdata.co](https://ipdata.co) IP geolocation and threat intelligence API.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ipdata = "0.1"
```

## Usage

### Single IP Lookup

```rust
let client = ipdata::IpData::new("your-api-key");
let info = client.lookup("8.8.8.8").await?;
println!("{} is in {}", info.ip, info.country_name.unwrap_or_default());
```

### Look Up Your Own IP

```rust
let info = client.lookup_self().await?;
```

### Field Filtering

Request only specific fields to reduce response size:

```rust
let info = client.lookup_fields("8.8.8.8", &["ip", "country_name", "asn"]).await?;
```

### Single Field Lookup

```rust
let asn = client.lookup_field("8.8.8.8", "asn").await?;
```

### Bulk Lookup

Look up to 100 IPs in a single request (requires a paid API key):

```rust
let results = client.bulk(&["8.8.8.8", "1.1.1.1"]).await?;
for info in &results {
    println!("{} -> {}", info.ip, info.country_name.as_deref().unwrap_or("unknown"));
}
```

### Typed Sub-resource Lookups

Get specific data with strongly-typed return values:

```rust
let asn = client.asn("8.8.8.8").await?;
println!("ASN: {} ({})", asn.asn, asn.name);

let threat = client.threat("8.8.8.8").await?;
println!("Is threat: {}", threat.is_threat);

let tz = client.time_zone("8.8.8.8").await?;
println!("Timezone: {}", tz.name);

let currency = client.currency("8.8.8.8").await?;
println!("Currency: {} ({})", currency.name, currency.code);

let carrier = client.carrier("8.8.8.8").await?;
println!("Carrier: {}", carrier.name);
```

### EU Endpoint

Use the EU-specific endpoint backed by datacenters in Frankfurt, Paris, and Ireland:

```rust
let client = ipdata::IpData::eu("your-api-key");
```

### Custom Endpoint

```rust
let client = ipdata::IpData::with_base_url("your-api-key", "https://custom-endpoint.example.com");
```

## Connection reuse and HTTP/2

An `IpData` client keeps a persistent HTTPS connection pool for as long as it lives. Create one client per process (or one per API key or endpoint), keep it, and reuse it for every lookup: each new client pays a fresh TLS handshake. Requests to api.ipdata.co are multiplexed over HTTP/2 when the platform negotiates it, and fall back to HTTP/1.1 keep-alive otherwise.

`IpData` is `Send + Sync`: share one instance across tasks by reference or in an `Arc`, or `clone()` it; clones are cheap and share the same pool. There is no close method: dropping the last clone releases the pool and its connections. To bring your own `reqwest::Client` (a pool shared with the rest of your application, timeouts, a proxy or TLS settings), use `IpData::with_client`; the client is used as given, so set the `User-Agent` yourself if you want to keep the SDK's `ipdata-rust/<version>` header.

```rust
let http = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(10))
    .build()?;
let client = ipdata::IpData::with_client("your-api-key", "https://api.ipdata.co", http);
```

The default client, used by `IpData::new`, `IpData::eu` and `IpData::with_base_url`, negotiates HTTP/2 through ALPN with automatic HTTP/1.1 fallback and is tuned for reuse: pooled connections idle for 60 s are closed, HTTP/2 connections are kept alive with a PING every 30 s, and TCP keep-alive probes run every 30 s. No total request timeout is set. A bulk lookup (`POST /bulk`) whose pooled connection turns out to be dead before any response byte arrives is sent again exactly once on a fresh connection; HTTP error statuses are never retried.

## Error Handling

```rust
match client.lookup("8.8.8.8").await {
    Ok(info) => println!("{}", info.ip),
    Err(ipdata::Error::Api { status, message }) => {
        eprintln!("API error ({}): {}", status, message);
    }
    Err(ipdata::Error::InvalidIp(ip)) => {
        eprintln!("Bad IP: {}", ip);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Response Types

The main response type is `IpInfo` which includes:

- **Geolocation**: `city`, `region`, `country_name`, `country_code`, `continent_name`, `latitude`, `longitude`, `postal`
- **Flags**: `is_eu` (EU member country), plus two flags the API sends only when they are true, so the typed fields read `false` when the key is absent:
  - `is_satellite`: the IP belongs to a satellite internet provider
  - `is_anycast`: the IP is an anycast address announced from several locations at once
- **ASN**: `asn` (struct with `asn`, `name`, `domain`, `route`, `asn_type`)
- **Company**: `company` (struct with `name`, `domain`, `network`, `company_type`)
- **Carrier**: `carrier` (struct with `name`, `mcc`, `mnc`)
- **Currency**: `currency` (struct with `name`, `code`, `symbol`, `native`, `plural`)
- **Time Zone**: `time_zone` (struct with `name`, `abbreviation`, `offset`, `is_dst`, `current_time`)
- **Organisation**: `organisation` (ISP / organization name)
- **Threat**: `threat` (struct with `is_tor`, `is_vpn`, `is_proxy`, `is_anonymous`, `is_threat`, `is_bogon`, `blocklists`, `scores`, and more)
- **Blocklist entries**: each `Blocklist` in `threat.blocklists` has `name`, `site` and `blocklist_type`, plus three fields that are `None` when a feed does not report them (ipdata's own vpn feed, for example):
  - `first_seen`: first day the IP was seen on the list, as a `YYYY-MM-DD` string (UTC)
  - `last_seen`: most recent day the IP was seen on the list, as a `YYYY-MM-DD` string (UTC)
  - `days_seen`: number of days the IP has been seen on the list
- **Languages**: `languages` (vec of `Language` with `name`, `native`, `code`)

All response structs ignore unknown keys and decode a missing key and an explicit `null` alike: `Option` fields read `None`, every other field reads its default (`""`, `false`, `0`, `0.0` or an empty list), so a `null` anywhere in a response does not fail the lookup.

## License

MIT
