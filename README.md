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

### EU Endpoint

Use the EU-specific endpoint backed by datacenters in Frankfurt, Paris, and Ireland:

```rust
let client = ipdata::IpData::eu("your-api-key");
```

### Custom Endpoint

```rust
let client = ipdata::IpData::with_base_url("your-api-key", "https://custom-endpoint.example.com");
```

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
- **ASN**: `asn` (struct with `asn`, `name`, `domain`, `route`, `asn_type`)
- **Company**: `company` (struct with `name`, `domain`, `network`, `company_type`)
- **Carrier**: `carrier` (struct with `name`, `mcc`, `mnc`)
- **Currency**: `currency` (struct with `name`, `code`, `symbol`, `native`, `plural`)
- **Time Zone**: `time_zone` (struct with `name`, `abbreviation`, `offset`, `is_dst`, `current_time`)
- **Threat**: `threat` (struct with `is_tor`, `is_proxy`, `is_anonymous`, `is_threat`, `is_bogon`, `blocklists`, and more)
- **Languages**: `languages` (vec of `Language` with `name`, `native`, `code`)

## License

MIT
