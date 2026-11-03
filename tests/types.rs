//! Decoding tests for the response types, built from API samples in `tests/fixtures`:
//! a satellite ISP (`is_satellite`), an anycast address with dated blocklist entries
//! (`is_anycast`) and a VPN exit whose blocklist includes an entry without dates; plus
//! hand-written documents that put an explicit `null` in every kind of field.

use ipdata::{
    Asn, Blocklist, Carrier, Company, Currency, IpInfo, Language, Threat, ThreatScores, TimeZone,
};
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

// --- Explicit nulls ---------------------------------------------------------------

#[test]
fn every_typed_model_decodes_explicit_nulls_to_defaults() {
    let asn: Asn = serde_json::from_value(json!({
        "asn": null, "name": null, "domain": null, "route": null, "type": null
    }))
    .unwrap();
    assert_eq!(asn.asn, "");
    assert_eq!(asn.name, "");
    assert_eq!(asn.domain, "");
    assert_eq!(asn.route, "");
    assert_eq!(asn.asn_type, "");

    let company: Company = serde_json::from_value(json!({
        "name": null, "domain": null, "network": null, "type": null
    }))
    .unwrap();
    assert_eq!(company.name, "");
    assert_eq!(company.domain, "");
    assert_eq!(company.network, "");
    assert_eq!(company.company_type, "");

    let carrier: Carrier =
        serde_json::from_value(json!({ "name": null, "mcc": null, "mnc": null })).unwrap();
    assert_eq!(carrier.name, "");
    assert_eq!(carrier.mcc, "");
    assert_eq!(carrier.mnc, "");

    let language: Language =
        serde_json::from_value(json!({ "name": null, "native": null, "code": null })).unwrap();
    assert_eq!(language.name, "");
    assert_eq!(language.native, "");
    assert_eq!(language.code, None);

    let currency: Currency = serde_json::from_value(json!({
        "name": null, "code": null, "symbol": null, "native": null, "plural": null
    }))
    .unwrap();
    assert_eq!(currency.name, "");
    assert_eq!(currency.code, "");
    assert_eq!(currency.symbol, "");
    assert_eq!(currency.native, "");
    assert_eq!(currency.plural, "");

    let scores: ThreatScores = serde_json::from_value(json!({
        "vpn_score": null, "proxy_score": null, "threat_score": null, "trust_score": null
    }))
    .unwrap();
    assert_eq!(scores.vpn_score, 0);
    assert_eq!(scores.proxy_score, 0);
    assert_eq!(scores.threat_score, 0);
    assert_eq!(scores.trust_score, 0);

    let entry: Blocklist = serde_json::from_value(json!({
        "name": null, "site": null, "type": null,
        "first_seen": null, "last_seen": null, "days_seen": null
    }))
    .unwrap();
    assert_eq!(entry.name, "");
    assert_eq!(entry.site, "");
    assert_eq!(entry.blocklist_type, "");
    assert_eq!(entry.first_seen, None);
    assert_eq!(entry.last_seen, None);
    assert_eq!(entry.days_seen, None);
}

#[test]
fn threat_decodes_null_flags_lists_and_scores_to_defaults() {
    let threat: Threat = serde_json::from_value(json!({
        "is_tor": null, "is_vpn": null, "is_icloud_relay": null, "is_proxy": null,
        "is_datacenter": null, "is_anonymous": null, "is_known_attacker": null,
        "is_known_abuser": null, "is_threat": null, "is_bogon": null,
        "blocklists": null, "scores": null
    }))
    .unwrap();
    assert!(!threat.is_tor);
    assert!(!threat.is_vpn);
    assert!(!threat.is_icloud_relay);
    assert!(!threat.is_proxy);
    assert!(!threat.is_datacenter);
    assert!(!threat.is_anonymous);
    assert!(!threat.is_known_attacker);
    assert!(!threat.is_known_abuser);
    assert!(!threat.is_threat);
    assert!(!threat.is_bogon);
    assert!(threat.blocklists.is_empty());
    assert!(threat.scores.is_none());

    // A null inside an otherwise populated object only affects that one field.
    let threat: Threat = serde_json::from_value(json!({
        "is_vpn": true,
        "blocklists": [{ "name": "Gluetun", "site": null, "type": "vpn" }],
        "scores": { "vpn_score": 100, "trust_score": null }
    }))
    .unwrap();
    assert!(threat.is_vpn);
    assert_eq!(threat.blocklists[0].name, "Gluetun");
    assert_eq!(threat.blocklists[0].site, "");
    let scores = threat.scores.unwrap();
    assert_eq!(scores.vpn_score, 100);
    assert_eq!(scores.trust_score, 0);
}

#[test]
fn ip_info_decodes_null_scalars_lists_and_objects_to_defaults() {
    let info: IpInfo = serde_json::from_value(json!({
        "ip": null, "is_eu": null, "is_satellite": null, "is_anycast": null,
        "latitude": null, "longitude": null, "languages": null,
        "city": null, "region": null, "country_name": null, "postal": null,
        "asn": null, "company": null, "carrier": null, "currency": null,
        "time_zone": null, "threat": null, "count": null, "status": null, "message": null
    }))
    .unwrap();

    assert_eq!(info.ip, "");
    assert!(!info.is_eu);
    assert!(!info.is_satellite);
    assert!(!info.is_anycast);
    assert_eq!(info.latitude, 0.0);
    assert_eq!(info.longitude, 0.0);
    assert!(info.languages.is_empty());
    assert_eq!(info.city, None);
    assert_eq!(info.region, None);
    assert_eq!(info.country_name, None);
    assert_eq!(info.postal, None);
    assert!(info.asn.is_none());
    assert!(info.company.is_none());
    assert!(info.carrier.is_none());
    assert!(info.currency.is_none());
    assert!(info.time_zone.is_none());
    assert!(info.threat.is_none());
    assert_eq!(info.count, None);
    assert_eq!(info.status, None);
    assert_eq!(info.message, None);
}

#[test]
fn nulls_scattered_through_a_full_response_leave_the_other_values_intact() {
    let mut sample: Value = serde_json::from_str(ANYCAST).unwrap();
    sample["latitude"] = Value::Null;
    sample["asn"]["domain"] = Value::Null;
    sample["company"]["network"] = Value::Null;
    sample["languages"][0]["native"] = Value::Null;
    sample["currency"]["symbol"] = Value::Null;
    sample["threat"]["is_datacenter"] = Value::Null;
    sample["threat"]["blocklists"][0]["site"] = Value::Null;
    sample["threat"]["scores"]["trust_score"] = Value::Null;

    let info: IpInfo = serde_json::from_value(sample).unwrap();

    assert_eq!(info.ip, "8.8.8.8");
    assert!(info.is_anycast);
    assert_eq!(info.latitude, 0.0);
    assert!((info.longitude + 98.5).abs() < 0.01);
    let asn = info.asn.unwrap();
    assert_eq!(asn.name, "Google LLC");
    assert_eq!(asn.domain, "");
    assert_eq!(asn.route, "8.8.8.0/24");
    let company = info.company.unwrap();
    assert_eq!(company.name, "Google LLC");
    assert_eq!(company.network, "");
    assert_eq!(info.languages[0].name, "English");
    assert_eq!(info.languages[0].native, "");
    assert_eq!(info.languages[0].code.as_deref(), Some("en"));
    let currency = info.currency.unwrap();
    assert_eq!(currency.code, "USD");
    assert_eq!(currency.symbol, "");
    let threat = info.threat.unwrap();
    assert!(!threat.is_datacenter);
    assert_eq!(threat.blocklists.len(), 2);
    assert_eq!(threat.blocklists[0].name, "ipdata");
    assert_eq!(threat.blocklists[0].site, "");
    assert_eq!(threat.blocklists[0].days_seen, Some(1));
    let scores = threat.scores.unwrap();
    assert_eq!(scores.vpn_score, 100);
    assert_eq!(scores.trust_score, 0);
}

#[test]
fn null_tolerance_still_rejects_values_of_the_wrong_type() {
    assert!(serde_json::from_value::<IpInfo>(json!({ "latitude": "north" })).is_err());
    assert!(serde_json::from_value::<IpInfo>(json!({ "is_eu": "yes" })).is_err());
    assert!(serde_json::from_value::<IpInfo>(json!({ "languages": {} })).is_err());
    assert!(serde_json::from_value::<Asn>(json!({ "asn": 15169 })).is_err());
    assert!(serde_json::from_value::<Threat>(json!({ "is_tor": 1 })).is_err());
    assert!(serde_json::from_value::<ThreatScores>(json!({ "vpn_score": "100" })).is_err());
    assert!(serde_json::from_value::<TimeZone>(json!({ "is_dst": "true" })).is_err());
}
