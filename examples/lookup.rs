use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = env::var("IPDATA_API_KEY").expect("set IPDATA_API_KEY env var");
    let client = ipdata::IpData::new(api_key);

    // Look up a specific IP
    let info = client.lookup("8.8.8.8").await?;
    println!("IP: {}", info.ip);
    println!("Country: {}", info.country_name.unwrap_or_default());
    println!("City: {}", info.city.unwrap_or_default());
    println!("Latitude: {:?}, Longitude: {:?}", info.latitude, info.longitude);

    if let Some(asn) = &info.asn {
        println!("ASN: {} ({})", asn.asn, asn.name);
    }

    if let Some(threat) = &info.threat {
        println!("Is threat: {}", threat.is_threat);
        println!("Is Tor: {}", threat.is_tor);
    }

    // Bulk lookup
    let results = client.bulk(&["8.8.8.8", "1.1.1.1"]).await?;
    for result in &results {
        println!("{} -> {}", result.ip, result.country_name.as_deref().unwrap_or("unknown"));
    }

    Ok(())
}
