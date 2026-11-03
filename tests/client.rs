//! Integration tests for [`ipdata::IpData`] against local HTTP servers.
//!
//! Every request goes to a server started by the test itself; nothing here talks to
//! api.ipdata.co. The servers speak HTTP/1.1 only (reqwest negotiates HTTP/2 through
//! TLS ALPN alone), so these tests cover request shape, response decoding, error
//! mapping and connection reuse over HTTP/1.1 keep-alive. The HTTP/2 negotiation
//! against the real API is checked by hand and recorded in the pull request.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipdata::{Error, IpData};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const API_KEY: &str = "test-key";
const USER_AGENT: &str = concat!("ipdata-rust/", env!("CARGO_PKG_VERSION"));

/// Time to let hyper hand a connection back to the pool between two lookups, as
/// happens between real requests.
const BETWEEN_REQUESTS: Duration = Duration::from_millis(100);

/// A full lookup response in today's shape, trimmed to what the tests assert.
fn ip_info_json() -> Value {
    json!({
        "ip": "8.8.8.8",
        "is_eu": false,
        "city": null,
        "country_name": "United States",
        "country_code": "US",
        "continent_code": "NA",
        "latitude": 39.7599983215332,
        "longitude": -98.5,
        "asn": {
            "asn": "AS15169",
            "name": "Google LLC",
            "domain": "about.google",
            "route": "8.8.8.0/24",
            "type": "hosting"
        },
        "threat": {
            "is_tor": false,
            "is_vpn": false,
            "is_datacenter": true,
            "is_threat": false,
            "blocklists": [],
            "scores": { "vpn_score": 0, "proxy_score": 1, "threat_score": 8, "trust_score": 97 }
        },
        "count": "0"
    })
}

fn asn_json() -> Value {
    json!({
        "asn": "AS15169",
        "name": "Google LLC",
        "domain": "about.google",
        "route": "8.8.8.0/24",
        "type": "hosting"
    })
}

fn client_for(server: &MockServer) -> IpData {
    IpData::with_base_url(API_KEY, server.uri())
}

/// Mounts a GET mock for `request_path` that checks the API key and answers `body`.
async fn mock_get(server: &MockServer, request_path: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(request_path))
        .and(query_param("api-key", API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn lookup_sends_api_key_and_user_agent_and_decodes_the_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .and(query_param("api-key", API_KEY))
        .and(header("user-agent", USER_AGENT))
        .respond_with(ResponseTemplate::new(200).set_body_json(ip_info_json()))
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server).lookup("8.8.8.8").await.unwrap();

    assert_eq!(info.ip, "8.8.8.8");
    assert!(!info.is_eu);
    assert_eq!(info.city, None);
    assert_eq!(info.country_name.as_deref(), Some("United States"));
    assert_eq!(info.country_code.as_deref(), Some("US"));
    assert!((info.latitude - 39.76).abs() < 0.01);
    assert!((info.longitude + 98.5).abs() < 0.01);
    let asn = info.asn.unwrap();
    assert_eq!(asn.asn, "AS15169");
    assert_eq!(asn.asn_type, "hosting");
    let threat = info.threat.unwrap();
    assert!(threat.is_datacenter);
    assert!(!threat.is_threat);
    assert!(threat.blocklists.is_empty());
    assert_eq!(threat.scores.unwrap().trust_score, 97);
    assert_eq!(info.count.as_deref(), Some("0"));
}

#[tokio::test]
async fn lookup_self_requests_the_base_url() {
    let server = MockServer::start().await;
    mock_get(&server, "/", ip_info_json()).await;

    let info = client_for(&server).lookup_self().await.unwrap();

    assert_eq!(info.ip, "8.8.8.8");
}

#[tokio::test]
async fn lookup_fields_sends_the_comma_separated_fields_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .and(query_param("api-key", API_KEY))
        .and(query_param("fields", "ip,country_name,asn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "8.8.8.8",
            "country_name": "United States",
            "asn": asn_json()
        })))
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server)
        .lookup_fields("8.8.8.8", &["ip", "country_name", "asn"])
        .await
        .unwrap();

    assert_eq!(info.ip, "8.8.8.8");
    assert_eq!(info.country_name.as_deref(), Some("United States"));
    assert_eq!(info.asn.unwrap().name, "Google LLC");
    assert!(info.threat.is_none());
}

#[tokio::test]
async fn lookup_field_returns_the_raw_json_value() {
    let server = MockServer::start().await;
    mock_get(&server, "/8.8.8.8/asn", asn_json()).await;
    mock_get(&server, "/8.8.8.8/is_eu", json!(false)).await;
    let client = client_for(&server);

    let asn = client.lookup_field("8.8.8.8", "asn").await.unwrap();
    assert_eq!(asn["asn"], "AS15169");
    assert_eq!(asn["type"], "hosting");

    let is_eu = client.lookup_field("8.8.8.8", "is_eu").await.unwrap();
    assert_eq!(is_eu, Value::Bool(false));
}

#[tokio::test]
async fn asn_decodes_the_typed_sub_resource() {
    let server = MockServer::start().await;
    mock_get(&server, "/8.8.8.8/asn", asn_json()).await;

    let asn = client_for(&server).asn("8.8.8.8").await.unwrap();

    assert_eq!(asn.asn, "AS15169");
    assert_eq!(asn.name, "Google LLC");
    assert_eq!(asn.domain, "about.google");
    assert_eq!(asn.route, "8.8.8.0/24");
    assert_eq!(asn.asn_type, "hosting");
}

#[tokio::test]
async fn carrier_decodes_the_typed_sub_resource() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/1.2.3.4/carrier",
        json!({ "name": "T-Mobile", "mcc": "310", "mnc": "160" }),
    )
    .await;

    let carrier = client_for(&server).carrier("1.2.3.4").await.unwrap();

    assert_eq!(carrier.name, "T-Mobile");
    assert_eq!(carrier.mcc, "310");
    assert_eq!(carrier.mnc, "160");
}

#[tokio::test]
async fn currency_decodes_the_typed_sub_resource() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/8.8.8.8/currency",
        json!({
            "name": "US Dollar",
            "code": "USD",
            "symbol": "$",
            "native": "$",
            "plural": "US dollars"
        }),
    )
    .await;

    let currency = client_for(&server).currency("8.8.8.8").await.unwrap();

    assert_eq!(currency.name, "US Dollar");
    assert_eq!(currency.code, "USD");
    assert_eq!(currency.symbol, "$");
    assert_eq!(currency.plural, "US dollars");
}

#[tokio::test]
async fn time_zone_decodes_the_typed_sub_resource() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/8.8.8.8/time_zone",
        json!({
            "name": "America/Chicago",
            "abbr": "CDT",
            "offset": "-0500",
            "is_dst": true,
            "current_time": "2026-11-02T10:00:00-05:00"
        }),
    )
    .await;

    let tz = client_for(&server).time_zone("8.8.8.8").await.unwrap();

    assert_eq!(tz.name, "America/Chicago");
    assert_eq!(tz.abbreviation, "CDT");
    assert_eq!(tz.offset, "-0500");
    assert!(tz.is_dst);
    assert_eq!(tz.current_time, "2026-11-02T10:00:00-05:00");
}

#[tokio::test]
async fn threat_decodes_the_typed_sub_resource() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/2001:db8::1/threat",
        json!({
            "is_tor": false,
            "is_vpn": true,
            "is_icloud_relay": false,
            "is_proxy": false,
            "is_datacenter": true,
            "is_anonymous": true,
            "is_known_attacker": false,
            "is_known_abuser": false,
            "is_threat": false,
            "is_bogon": false,
            "blocklists": [
                { "name": "Gluetun", "site": "https://github.com/qdm12/gluetun", "type": "vpn" }
            ],
            "scores": { "vpn_score": 100, "proxy_score": 99, "threat_score": 100, "trust_score": 0 }
        }),
    )
    .await;

    let threat = client_for(&server).threat("2001:db8::1").await.unwrap();

    assert!(threat.is_vpn);
    assert!(threat.is_anonymous);
    assert!(!threat.is_tor);
    assert_eq!(threat.blocklists.len(), 1);
    assert_eq!(threat.blocklists[0].name, "Gluetun");
    assert_eq!(threat.blocklists[0].blocklist_type, "vpn");
    let scores = threat.scores.unwrap();
    assert_eq!(scores.vpn_score, 100);
    assert_eq!(scores.trust_score, 0);
}

#[tokio::test]
async fn sub_resources_answered_with_nulls_decode_to_defaults() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/8.8.8.8/carrier",
        json!({ "name": null, "mcc": null, "mnc": null }),
    )
    .await;
    mock_get(
        &server,
        "/8.8.8.8/asn",
        json!({
            "asn": "AS15169",
            "name": "Google LLC",
            "domain": null,
            "route": null,
            "type": null
        }),
    )
    .await;
    mock_get(
        &server,
        "/8.8.8.8/time_zone",
        json!({ "name": null, "abbr": null, "offset": null, "is_dst": null, "current_time": null }),
    )
    .await;
    let client = client_for(&server);

    let carrier = client.carrier("8.8.8.8").await.unwrap();
    assert_eq!(carrier.name, "");
    assert_eq!(carrier.mcc, "");
    assert_eq!(carrier.mnc, "");

    let asn = client.asn("8.8.8.8").await.unwrap();
    assert_eq!(asn.asn, "AS15169");
    assert_eq!(asn.name, "Google LLC");
    assert_eq!(asn.domain, "");
    assert_eq!(asn.route, "");
    assert_eq!(asn.asn_type, "");

    let tz = client.time_zone("8.8.8.8").await.unwrap();
    assert_eq!(tz.name, "");
    assert!(!tz.is_dst);
}

#[tokio::test]
async fn bulk_posts_the_ip_list_and_returns_results_in_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bulk"))
        .and(query_param("api-key", API_KEY))
        .and(header("content-type", "application/json"))
        .and(header("user-agent", USER_AGENT))
        .and(body_json(json!(["8.8.8.8", "1.1.1.1"])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "responses": [
                { "ip": "8.8.8.8", "country_code": "US", "asn": asn_json() },
                { "ip": "1.1.1.1", "country_code": "AU" }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let results = client_for(&server)
        .bulk(&["8.8.8.8", "1.1.1.1"])
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].ip, "8.8.8.8");
    assert_eq!(results[0].country_code.as_deref(), Some("US"));
    assert_eq!(results[0].asn.as_ref().unwrap().asn, "AS15169");
    assert_eq!(results[1].ip, "1.1.1.1");
    assert_eq!(results[1].country_code.as_deref(), Some("AU"));
    assert!(results[1].asn.is_none());
}

#[tokio::test]
async fn api_errors_carry_the_status_and_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({ "message": "You have not provided a valid API Key." })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client_for(&server).lookup("8.8.8.8").await.unwrap_err();

    assert!(matches!(
        &err,
        Error::Api { status: 401, message } if message == "You have not provided a valid API Key."
    ));
    assert_eq!(err.status(), Some(401));
    assert_eq!(
        err.to_string(),
        "API error (HTTP 401): You have not provided a valid API Key."
    );
}

#[tokio::test]
async fn api_errors_without_a_json_body_get_a_generic_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8/asn"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(1)
        .mount(&server)
        .await;

    let err = client_for(&server).asn("8.8.8.8").await.unwrap_err();

    assert!(matches!(
        &err,
        Error::Api { status: 503, message } if message == "request failed with status 503"
    ));
}

#[tokio::test]
async fn an_unparseable_success_body_is_a_transport_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&server)
        .await;

    let err = client_for(&server).lookup("8.8.8.8").await.unwrap_err();

    assert!(matches!(err, Error::Http(_)), "unexpected error: {err:?}");
    assert_eq!(err.status(), None);
}

#[tokio::test]
async fn invalid_input_is_rejected_before_any_request_is_sent() {
    let server = MockServer::start().await;
    let client = client_for(&server);

    assert!(matches!(
        client.lookup("not-an-ip").await.unwrap_err(),
        Error::InvalidIp(ip) if ip == "not-an-ip"
    ));
    assert!(matches!(
        client.asn("300.1.1.1").await.unwrap_err(),
        Error::InvalidIp(_)
    ));
    assert!(matches!(
        client.bulk(&[]).await.unwrap_err(),
        Error::BulkEmpty
    ));
    let too_many = vec!["8.8.8.8"; 101];
    assert!(matches!(
        client.bulk(&too_many).await.unwrap_err(),
        Error::BulkLimitExceeded
    ));
    assert!(matches!(
        client.bulk(&["8.8.8.8", "nope"]).await.unwrap_err(),
        Error::InvalidIp(ip) if ip == "nope"
    ));

    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_trailing_slash_in_the_base_url_is_ignored() {
    let server = MockServer::start().await;
    mock_get(&server, "/8.8.8.8", ip_info_json()).await;

    let client = IpData::with_base_url(API_KEY, format!("{}/", server.uri()));

    assert_eq!(client.lookup("8.8.8.8").await.unwrap().ip, "8.8.8.8");
}

#[tokio::test]
async fn with_client_sends_requests_through_the_supplied_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .and(query_param("api-key", API_KEY))
        .and(header("x-ipdata-test", "injected"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ip_info_json()))
        .expect(1)
        .mount(&server)
        .await;

    let mut headers = HeaderMap::new();
    headers.insert("x-ipdata-test", HeaderValue::from_static("injected"));
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    let client = IpData::with_client(API_KEY, server.uri(), http);

    let info = client.lookup("8.8.8.8").await.unwrap();

    assert_eq!(info.ip, "8.8.8.8");
}

#[test]
fn ipdata_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<IpData>();
}

#[tokio::test]
async fn sequential_lookups_on_one_client_reuse_one_connection() {
    let server = ScriptedServer::start(vec![Step::Respond; 3], ip_info_json().to_string());
    let client = IpData::with_base_url(API_KEY, &server.uri);

    for _ in 0..3 {
        let info = client.lookup("8.8.8.8").await.unwrap();
        assert_eq!(info.ip, "8.8.8.8");
        tokio::time::sleep(BETWEEN_REQUESTS).await;
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests
        .iter()
        .all(|r| r.request_line == "GET /8.8.8.8?api-key=test-key HTTP/1.1"));
    assert_eq!(
        server.connections(),
        1,
        "every lookup should reuse the first connection"
    );
}

#[tokio::test]
async fn clones_share_the_connection_pool() {
    let server = ScriptedServer::start(vec![Step::Respond; 2], ip_info_json().to_string());
    let client = IpData::with_base_url(API_KEY, &server.uri);
    let clone = client.clone();

    client.lookup("8.8.8.8").await.unwrap();
    tokio::time::sleep(BETWEEN_REQUESTS).await;
    clone.lookup("8.8.8.8").await.unwrap();

    assert_eq!(server.requests().len(), 2);
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn a_connection_closed_by_the_server_while_idle_is_replaced() {
    let server = ScriptedServer::start(
        vec![Step::RespondAndClose, Step::Respond],
        ip_info_json().to_string(),
    );
    let client = IpData::with_base_url(API_KEY, &server.uri);

    client.lookup("8.8.8.8").await.unwrap();
    tokio::time::sleep(BETWEEN_REQUESTS).await;
    client.lookup("8.8.8.8").await.unwrap();

    assert_eq!(server.requests().len(), 2);
    assert_eq!(server.connections(), 2);
}

fn bulk_json() -> String {
    json!({ "responses": [{ "ip": "8.8.8.8" }, { "ip": "1.1.1.1" }] }).to_string()
}

#[tokio::test]
async fn bulk_is_retried_once_when_a_pooled_connection_dies_before_the_response() {
    let server = ScriptedServer::start(
        vec![Step::Respond, Step::Hangup, Step::Respond],
        bulk_json(),
    );
    let client = IpData::with_base_url(API_KEY, &server.uri);

    // First request: served normally, connection stays in the pool.
    client.bulk(&["8.8.8.8", "1.1.1.1"]).await.unwrap();
    tokio::time::sleep(BETWEEN_REQUESTS).await;
    // Second request: the server reads it from the pooled connection and closes
    // without answering; the SDK sends it again on a fresh connection.
    let results = client.bulk(&["8.8.8.8", "1.1.1.1"]).await.unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[1].ip, "1.1.1.1");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests
        .iter()
        .all(|r| r.request_line == "POST /bulk?api-key=test-key HTTP/1.1"));
    assert_eq!(requests[2].body, r#"["8.8.8.8","1.1.1.1"]"#);
    assert_eq!(requests[1].body, requests[2].body);
    assert_eq!(server.connections(), 2);
}

#[tokio::test]
async fn bulk_is_retried_at_most_once() {
    let server =
        ScriptedServer::start(vec![Step::Respond, Step::Hangup, Step::Hangup], bulk_json());
    let client = IpData::with_base_url(API_KEY, &server.uri);

    client.bulk(&["8.8.8.8"]).await.unwrap();
    tokio::time::sleep(BETWEEN_REQUESTS).await;
    let err = client.bulk(&["8.8.8.8"]).await.unwrap_err();

    assert!(matches!(err, Error::Http(_)), "unexpected error: {err:?}");
    assert_eq!(server.requests().len(), 3);
    assert_eq!(server.connections(), 2);
}

#[tokio::test]
async fn bulk_is_not_retried_on_an_http_error_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bulk"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "message": "boom" })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client_for(&server).bulk(&["8.8.8.8"]).await.unwrap_err();

    assert!(matches!(&err, Error::Api { status: 500, message } if message == "boom"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// What the scripted server does with the next request it receives.
#[derive(Clone, Copy)]
enum Step {
    /// Answer with `200 OK` and keep the connection open.
    Respond,
    /// Answer with `200 OK`, then close the connection.
    RespondAndClose,
    /// Read the request, then close the connection without answering.
    Hangup,
}

/// One request as seen by the scripted server.
#[derive(Clone, Debug)]
struct Recorded {
    /// The request line, e.g. `GET /8.8.8.8?api-key=test-key HTTP/1.1`.
    request_line: String,
    /// The request body (empty for GET).
    body: String,
}

/// A plain HTTP/1.1 keep-alive server on a std thread that follows a script request
/// by request and records every connection and request it sees. wiremock cannot tell
/// which TCP connection carried a request, so connection reuse and stale-connection
/// handling are tested against this instead.
struct ScriptedServer {
    uri: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl ScriptedServer {
    fn start(script: Vec<Step>, body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = Self {
            uri,
            connections: Arc::clone(&connections),
            requests: Arc::clone(&requests),
        };

        std::thread::spawn(move || {
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let mut script = script.into_iter();
            'connections: loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                // A stalled read means the client went elsewhere; serve the next
                // connection instead of hanging the test.
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = Vec::new();
                loop {
                    let Some(request) = read_request(&mut stream, &mut buf) else {
                        continue 'connections;
                    };
                    requests.lock().unwrap().push(request);
                    let Some(step) = script.next() else {
                        return;
                    };
                    match step {
                        Step::Hangup => continue 'connections,
                        Step::Respond | Step::RespondAndClose => {
                            if stream.write_all(response.as_bytes()).is_err() {
                                continue 'connections;
                            }
                        }
                    }
                    if script.len() == 0 {
                        return;
                    }
                    if matches!(step, Step::RespondAndClose) {
                        continue 'connections;
                    }
                }
            }
        });

        server
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

/// Reads one HTTP/1.1 request (head plus `Content-Length` body) from `stream`, using
/// `buf` to carry over bytes between requests. Returns `None` when the connection is
/// closed or idle for too long.
fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Recorded> {
    let mut chunk = [0u8; 4096];
    let head_len = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_len]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while buf.len() < head_len + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = String::from_utf8_lossy(&buf[head_len..head_len + content_length]).into_owned();
    buf.drain(..head_len + content_length);
    Some(Recorded {
        request_line: head.lines().next().unwrap_or_default().to_string(),
        body,
    })
}

// --- New response fields: is_satellite, is_anycast and dated blocklist entries ------

const SATELLITE_FIXTURE: &str = include_str!("fixtures/satellite.json");
const ANYCAST_FIXTURE: &str = include_str!("fixtures/anycast.json");
const VPN_EXIT_FIXTURE: &str = include_str!("fixtures/vpn_exit.json");

fn fixture(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

#[tokio::test]
async fn lookup_decodes_is_satellite_and_is_anycast() {
    let server = MockServer::start().await;
    mock_get(&server, "/98.97.34.0", fixture(SATELLITE_FIXTURE)).await;
    mock_get(&server, "/8.8.8.8", fixture(ANYCAST_FIXTURE)).await;
    let client = client_for(&server);

    let satellite = client.lookup("98.97.34.0").await.unwrap();
    assert!(satellite.is_satellite);
    assert!(!satellite.is_anycast);

    let anycast = client.lookup("8.8.8.8").await.unwrap();
    assert!(anycast.is_anycast);
    assert!(!anycast.is_satellite);
    let entry = &anycast.threat.unwrap().blocklists[0];
    assert_eq!(entry.first_seen.as_deref(), Some("2026-11-02"));
    assert_eq!(entry.last_seen.as_deref(), Some("2026-11-02"));
    assert_eq!(entry.days_seen, Some(1));
}

#[tokio::test]
async fn lookup_fields_accepts_the_new_field_names() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/8.8.8.8"))
        .and(query_param("api-key", API_KEY))
        .and(query_param("fields", "is_satellite,is_anycast"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "is_anycast": true })))
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server)
        .lookup_fields("8.8.8.8", &["is_satellite", "is_anycast"])
        .await
        .unwrap();

    assert!(info.is_anycast);
    assert!(!info.is_satellite);
}

#[tokio::test]
async fn lookup_field_fetches_the_new_flags_on_their_own() {
    let server = MockServer::start().await;
    mock_get(&server, "/8.8.8.8/is_anycast", json!(true)).await;
    mock_get(&server, "/98.97.34.0/is_satellite", json!(true)).await;
    let client = client_for(&server);

    let is_anycast = client.lookup_field("8.8.8.8", "is_anycast").await.unwrap();
    assert_eq!(is_anycast, Value::Bool(true));
    let is_satellite = client
        .lookup_field("98.97.34.0", "is_satellite")
        .await
        .unwrap();
    assert_eq!(is_satellite, Value::Bool(true));
}

#[tokio::test]
async fn threat_decodes_blocklist_entries_with_and_without_dates() {
    let server = MockServer::start().await;
    mock_get(
        &server,
        "/187.13.250.1/threat",
        fixture(VPN_EXIT_FIXTURE)["threat"].clone(),
    )
    .await;

    let threat = client_for(&server).threat("187.13.250.1").await.unwrap();

    assert!(threat.is_vpn);
    assert_eq!(threat.blocklists.len(), 6);
    assert_eq!(threat.blocklists[0].name, "Gluetun");
    assert_eq!(threat.blocklists[0].days_seen, Some(2));
    let undated = &threat.blocklists[2];
    assert_eq!(undated.name, "ipdata");
    assert_eq!(undated.blocklist_type, "vpn");
    assert_eq!(undated.first_seen, None);
    assert_eq!(undated.last_seen, None);
    assert_eq!(undated.days_seen, None);
}

#[tokio::test]
async fn bulk_items_carry_the_new_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bulk"))
        .and(query_param("api-key", API_KEY))
        .and(body_json(json!(["98.97.34.0", "8.8.8.8", "187.13.250.1"])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "responses": [
                fixture(SATELLITE_FIXTURE),
                fixture(ANYCAST_FIXTURE),
                fixture(VPN_EXIT_FIXTURE)
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let results = client_for(&server)
        .bulk(&["98.97.34.0", "8.8.8.8", "187.13.250.1"])
        .await
        .unwrap();

    assert_eq!(results.len(), 3);
    assert!(results[0].is_satellite);
    assert!(!results[0].is_anycast);
    assert!(results[1].is_anycast);
    assert!(!results[1].is_satellite);
    assert!(!results[2].is_satellite);
    assert!(!results[2].is_anycast);
    let threat = results[2].threat.as_ref().unwrap();
    assert!(threat.is_vpn);
    assert_eq!(threat.blocklists[2].first_seen, None);
    assert_eq!(threat.blocklists[3].name, "NordVPN");
    assert_eq!(threat.blocklists[3].days_seen, Some(2));
}
