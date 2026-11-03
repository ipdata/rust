//! Decoding tests for the response types, built from API samples in `tests/fixtures`:
//! a satellite ISP (`is_satellite`), an anycast address with dated blocklist entries
//! (`is_anycast`) and a VPN exit whose blocklist includes an entry without dates.

use ipdata::{Blocklist, IpInfo, Threat, TimeZone};
use serde_json::{json, Value};

const SATELLITE: &str = include_str!("fixtures/satellite.json");
const ANYCAST: &str = include_str!("fixtures/anycast.json");
const VPN_EXIT: &str = include_str!("fixtures/vpn_exit.json");

#[test]
fn satellite_sample_sets_is_satellite_and_reads_is_anycast_as_false() {
    let info: IpInfo = serde_json::from_str(SATELLITE).unwrap();

    assert_eq!(info.ip, "98.97.34.0");
    assert!(info.is_satellite);
    assert!(!info.is_anycast);
    assert!(!info.is_eu);
    assert_eq!(info.city.as_deref(), Some("Seattle"));
    assert_eq!(
        info.asn.unwrap().name,
        "Space Exploration Technologies Corporation"
    );
    assert!(info.threat.unwrap().blocklists.is_empty());
}

#[test]
fn anycast_sample_sets_is_anycast_and_decodes_dated_blocklist_entries() {
    let info: IpInfo = serde_json::from_str(ANYCAST).unwrap();

    assert_eq!(info.ip, "8.8.8.8");
    assert!(info.is_anycast);
    assert!(!info.is_satellite);
    assert_eq!(info.city, None);
    assert_eq!(info.country_code.as_deref(), Some("US"));
    assert_eq!(info.languages.len(), 1);
    assert_eq!(info.currency.unwrap().code, "USD");

    let threat = info.threat.unwrap();
    assert!(threat.is_datacenter);
    assert_eq!(threat.blocklists.len(), 2);
    let entry = &threat.blocklists[0];
    assert_eq!(entry.name, "ipdata");
    assert_eq!(entry.site, "https://ipdata.co");
    assert_eq!(entry.blocklist_type, "cloud");
    assert_eq!(entry.first_seen.as_deref(), Some("2026-11-02"));
    assert_eq!(entry.last_seen.as_deref(), Some("2026-11-02"));
    assert_eq!(entry.days_seen, Some(1));
    assert_eq!(threat.blocklists[1].blocklist_type, "open_resolvers");
    assert_eq!(threat.scores.unwrap().trust_score, 2);
}

#[test]
fn anycast_sample_decodes_a_time_zone_of_nulls_to_defaults() {
    let info: IpInfo = serde_json::from_str(ANYCAST).unwrap();

    let tz = info.time_zone.unwrap();
    assert_eq!(tz.name, "");
    assert_eq!(tz.abbreviation, "");
    assert_eq!(tz.offset, "");
    assert!(!tz.is_dst);
    assert_eq!(tz.current_time, "");

    let tz: TimeZone = serde_json::from_value(json!({
        "name": "America/Chicago",
        "abbr": "CDT",
        "offset": "-0500",
        "is_dst": true,
        "current_time": "2026-11-02T10:00:00-05:00"
    }))
    .unwrap();
    assert_eq!(tz.name, "America/Chicago");
    assert_eq!(tz.abbreviation, "CDT");
    assert!(tz.is_dst);
}

#[test]
fn vpn_exit_sample_reads_both_flags_as_false_and_tolerates_undated_entries() {
    let info: IpInfo = serde_json::from_str(VPN_EXIT).unwrap();

    assert_eq!(info.ip, "187.13.250.1");
    assert!(!info.is_satellite);
    assert!(!info.is_anycast);

    let threat = info.threat.unwrap();
    assert!(threat.is_vpn);
    assert!(threat.is_threat);
    assert_eq!(threat.blocklists.len(), 6);

    let dated = &threat.blocklists[0];
    assert_eq!(dated.name, "Gluetun");
    assert_eq!(dated.first_seen.as_deref(), Some("2026-10-31"));
    assert_eq!(dated.last_seen.as_deref(), Some("2026-11-02"));
    assert_eq!(dated.days_seen, Some(2));

    let undated = &threat.blocklists[2];
    assert_eq!(undated.name, "ipdata");
    assert_eq!(undated.site, "https://ipdata.co");
    assert_eq!(undated.blocklist_type, "vpn");
    assert_eq!(undated.first_seen, None);
    assert_eq!(undated.last_seen, None);
    assert_eq!(undated.days_seen, None);

    assert_eq!(threat.blocklists[5].name, "X4BNet");
}

#[test]
fn threat_and_blocklist_decode_on_their_own() {
    let sample: Value = serde_json::from_str(VPN_EXIT).unwrap();
    let threat: Threat = serde_json::from_value(sample["threat"].clone()).unwrap();
    assert!(threat.is_known_attacker);
    assert_eq!(threat.blocklists[3].name, "NordVPN");
    assert_eq!(threat.blocklists[3].days_seen, Some(2));

    let entry: Blocklist = serde_json::from_value(
        json!({ "name": "ipdata", "site": "https://ipdata.co", "type": "vpn" }),
    )
    .unwrap();
    assert_eq!(entry.blocklist_type, "vpn");
    assert_eq!(entry.first_seen, None);
    assert_eq!(entry.last_seen, None);
    assert_eq!(entry.days_seen, None);
}

#[test]
fn flags_default_to_false_when_the_keys_are_absent() {
    let info: IpInfo = serde_json::from_value(json!({ "ip": "1.1.1.1", "is_eu": false })).unwrap();
    assert!(!info.is_satellite);
    assert!(!info.is_anycast);

    let info = IpInfo::default();
    assert!(!info.is_satellite);
    assert!(!info.is_anycast);
}

#[test]
fn unknown_keys_are_ignored_at_every_level() {
    let mut sample: Value = serde_json::from_str(ANYCAST).unwrap();
    sample["brand_new_field"] = json!({ "nested": true });
    sample["threat"]["brand_new_flag"] = json!(true);
    sample["threat"]["blocklists"][0]["brand_new_detail"] = json!("x");
    sample["asn"]["brand_new_detail"] = json!(1);

    let info: IpInfo = serde_json::from_value(sample).unwrap();

    assert!(info.is_anycast);
    assert_eq!(info.threat.unwrap().blocklists[0].days_seen, Some(1));
}

#[test]
fn new_fields_round_trip_through_serialization() {
    let info: IpInfo = serde_json::from_str(ANYCAST).unwrap();

    let value = serde_json::to_value(&info).unwrap();

    assert_eq!(value["is_anycast"], json!(true));
    assert_eq!(value["is_satellite"], json!(false));
    assert_eq!(
        value["threat"]["blocklists"][0]["first_seen"],
        json!("2026-11-02")
    );
    assert_eq!(value["threat"]["blocklists"][0]["days_seen"], json!(1));
    let again: IpInfo = serde_json::from_value(value).unwrap();
    assert!(again.is_anycast);
}
