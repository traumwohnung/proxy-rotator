use crate::rotator::Rotator;
use crate::tunnel;

use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub async fn run_proxy(bind_addr: &str, rotator: Arc<Rotator>) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    info!("Proxy rotator listening on {bind_addr}");
    info!("Available proxy sets: {:?}", rotator.set_names());
    for name in rotator.set_names() {
        if let Some(count) = rotator.set_info(name) {
            info!("  set '{}': {} proxies", name, count);
        }
    }
    info!("Usage: Proxy-Authorization: Basic base64(<proxyset>-<minutes>-<sessionkey>:)");
    info!("  proxyset: alphanumeric proxy set name");
    info!("  minutes: 0 (rotate every request) to 1440 (24h sticky session)");
    info!("  sessionkey: alphanumeric session identifier");

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("Accepted connection from {peer}");

        let rotator = Arc::clone(&rotator);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let result = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let rotator = Arc::clone(&rotator);
                        async move { handle_request(req, rotator, peer).await }
                    }),
                )
                .with_upgrades()
                .await;

            if let Err(e) = result {
                let msg = format!("{e}");
                if msg.contains("incomplete")
                    || msg.contains("connection closed")
                    || msg.contains("early eof")
                {
                    debug!("Connection finished: {e}");
                } else {
                    error!("Connection error: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Proxy-Authorization parsing
// ---------------------------------------------------------------------------

/// Parsed proxy authorization: proxy set name, affinity minutes, and session key.
struct ProxyAuth {
    set_name: String,
    affinity_minutes: u16,
    session_key: String,
}

/// Extract and parse the Proxy-Authorization header from a request.
fn parse_proxy_auth(req: &Request<Incoming>) -> Result<ProxyAuth, String> {
    let header_val = req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing Proxy-Authorization header")?;

    parse_proxy_auth_value(header_val)
}

/// Parse a Proxy-Authorization header value.
/// Format: `Basic base64(<proxyset>-<minutes>-<sessionkey>:)`
///
/// All three parts are required. The format is strictly:
///   - proxyset: alphanumeric only (no hyphens)
///   - minutes: numeric only, 0..=1440
///   - sessionkey: alphanumeric only (no hyphens)
///
/// Password (after the colon) is unused/empty.
fn parse_proxy_auth_value(header_val: &str) -> Result<ProxyAuth, String> {
    let b64 = header_val
        .strip_prefix("Basic ")
        .ok_or("Proxy-Authorization must be Basic auth")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "Invalid base64 in Proxy-Authorization")?;
    let decoded_str =
        String::from_utf8(decoded).map_err(|_| "Invalid UTF-8 in Proxy-Authorization")?;

    // Standard Basic auth: split on first ':' to get the username part.
    let username = match decoded_str.find(':') {
        Some(idx) => &decoded_str[..idx],
        None => decoded_str.as_str(),
    };

    if username.is_empty() {
        return Err("Empty username in Proxy-Authorization".to_string());
    }

    // Split username on '-' — must have exactly 3 parts: proxyset-minutes-sessionkey
    let parts: Vec<&str> = username.splitn(3, '-').collect();
    if parts.len() != 3 {
        return Err(format!(
            "Invalid username format '{}'. Expected: <proxyset>-<minutes>-<sessionkey>",
            username
        ));
    }

    let set_name = parts[0];
    let minutes_str = parts[1];
    let session_key = parts[2];

    // Validate proxyset: non-empty, alphanumeric only
    if set_name.is_empty() || !set_name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!(
            "Invalid proxy set name '{}'. Must be non-empty and alphanumeric only (no hyphens).",
            set_name
        ));
    }

    // Validate minutes: numeric only, 0..=1440
    if minutes_str.is_empty() || !minutes_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "Invalid minutes '{}'. Must be a number 0-1440.",
            minutes_str
        ));
    }
    let minutes: u16 = minutes_str.parse::<u16>().map_err(|_| {
        format!(
            "Invalid minutes '{}'. Must be a number 0-1440.",
            minutes_str
        )
    })?;
    if minutes > 1440 {
        return Err(format!(
            "Minutes {} exceeds maximum of 1440 (24 hours).",
            minutes
        ));
    }

    // Validate session key: non-empty, alphanumeric only
    if session_key.is_empty() || !session_key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!(
            "Invalid session key '{}'. Must be non-empty and alphanumeric only (no hyphens).",
            session_key
        ));
    }

    Ok(ProxyAuth {
        set_name: set_name.to_string(),
        affinity_minutes: minutes,
        session_key: session_key.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<Incoming>,
    rotator: Arc<Rotator>,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match handle_request_inner(req, rotator, peer).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!("Request handling error: {e:#}");
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                format!("Proxy error: {e:#}"),
            ))
        }
    }
}

async fn handle_request_inner(
    req: Request<Incoming>,
    rotator: Arc<Rotator>,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let client_ip = peer.ip();

    // Parse the proxy auth: <proxyset>-<minutes>-<sessionkey>
    let auth = match parse_proxy_auth(&req) {
        Ok(auth) => auth,
        Err(msg) => {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                client = %client_ip,
                "Auth error: {msg}"
            );
            return Ok(proxy_auth_error(&format!(
                "{}. Format: <proxyset>-<minutes>-<sessionkey>. Available sets: {:?}",
                msg,
                rotator.set_names()
            )));
        }
    };

    // Resolve the next upstream proxy.
    let upstream = match rotator.next_proxy(&auth.set_name, auth.affinity_minutes, &auth.session_key) {
        Some(p) => p,
        None => {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                set = %auth.set_name,
                "Unknown proxy set"
            );
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "Unknown proxy set '{}'. Available: {:?}",
                    auth.set_name,
                    rotator.set_names()
                ),
            ));
        }
    };

    info!(
        method = %req.method(),
        uri = %req.uri(),
        set = %auth.set_name,
        minutes = auth.affinity_minutes,
        session = %auth.session_key,
        upstream = %format!("{}:{}", upstream.host, upstream.port),
        client = %client_ip,
        "Routing request"
    );

    if req.method() == Method::CONNECT {
        handle_connect(req, &upstream).await
    } else {
        handle_http(req, &upstream).await
    }
}

// ---------------------------------------------------------------------------
// CONNECT
// ---------------------------------------------------------------------------

async fn handle_connect(
    req: Request<Incoming>,
    upstream: &crate::rotator::ResolvedProxy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let target_authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let upstream = upstream.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);

                if let Err(e) = tunnel::handle_connect(io, target_authority, &upstream).await {
                    error!("Tunnel error: {e:#}");
                }
            }
            Err(e) => {
                error!("Upgrade failed: {e}");
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

async fn handle_http(
    req: Request<Incoming>,
    upstream: &crate::rotator::ResolvedProxy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    // Collect headers, stripping our Proxy-Authorization.
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str() != "proxy-authorization")
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = req.collect().await?.to_bytes().to_vec();

    let response_bytes =
        tunnel::forward_http(&method, &uri, &headers, &body_bytes, upstream).await?;

    parse_raw_response(&response_bytes)
}

fn parse_raw_response(raw: &[u8]) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());

    let header_section = &raw[..header_end];
    let body_start = std::cmp::min(header_end + 4, raw.len());
    let body = &raw[body_start..];

    let header_str = String::from_utf8_lossy(header_section);
    let mut lines = header_str.lines();

    let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code = parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY));

    for line in lines {
        if let Some((key, value)) = line.split_once(": ") {
            builder = builder.header(key, value);
        } else if let Some((key, value)) = line.split_once(':') {
            builder = builder.header(key.trim(), value.trim());
        }
    }

    let body = Full::new(Bytes::copy_from_slice(body))
        .map_err(|never| match never {})
        .boxed();

    Ok(builder.body(body).unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: StatusCode, message: String) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from(message))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn proxy_auth_error(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic realm=\"proxy-rotator\"")
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a Basic auth header value from a username.
    fn auth_header(username: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:"));
        format!("Basic {encoded}")
    }

    #[test]
    fn test_valid_username() {
        let auth = parse_proxy_auth_value(&auth_header("residential-5-abc123")).unwrap();
        assert_eq!(auth.set_name, "residential");
        assert_eq!(auth.affinity_minutes, 5);
        assert_eq!(auth.session_key, "abc123");
    }

    #[test]
    fn test_zero_minutes() {
        let auth = parse_proxy_auth_value(&auth_header("datacenter-0-sess1")).unwrap();
        assert_eq!(auth.set_name, "datacenter");
        assert_eq!(auth.affinity_minutes, 0);
        assert_eq!(auth.session_key, "sess1");
    }

    #[test]
    fn test_max_minutes() {
        let auth = parse_proxy_auth_value(&auth_header("residential-1440-mykey")).unwrap();
        assert_eq!(auth.affinity_minutes, 1440);
    }

    #[test]
    fn test_minutes_too_high() {
        assert!(parse_proxy_auth_value(&auth_header("residential-1441-mykey")).is_err());
    }

    #[test]
    fn test_missing_parts() {
        // Only one part (no hyphens)
        assert!(parse_proxy_auth_value(&auth_header("residential")).is_err());
        // Only two parts
        assert!(parse_proxy_auth_value(&auth_header("residential-5")).is_err());
    }

    #[test]
    fn test_hyphen_in_proxyset() {
        // splitn(3, '-') → ["resi", "dential", "5-abc123"]
        // "dential" is not numeric → error
        assert!(parse_proxy_auth_value(&auth_header("resi-dential-5-abc123")).is_err());
    }

    #[test]
    fn test_hyphen_in_session_key() {
        // splitn(3, '-') → ["residential", "5", "abc-123"]
        // "abc-123" has a hyphen → not alphanumeric → error
        assert!(parse_proxy_auth_value(&auth_header("residential-5-abc-123")).is_err());
    }

    #[test]
    fn test_non_alphanumeric_proxyset() {
        assert!(parse_proxy_auth_value(&auth_header("resi_dential-5-abc123")).is_err());
    }

    #[test]
    fn test_non_alphanumeric_session_key() {
        assert!(parse_proxy_auth_value(&auth_header("residential-5-abc_123")).is_err());
    }

    #[test]
    fn test_non_numeric_minutes() {
        assert!(parse_proxy_auth_value(&auth_header("residential-abc-sess1")).is_err());
    }

    #[test]
    fn test_empty_proxyset() {
        assert!(parse_proxy_auth_value(&auth_header("-5-sess1")).is_err());
    }

    #[test]
    fn test_empty_session_key() {
        assert!(parse_proxy_auth_value(&auth_header("residential-5-")).is_err());
    }

    #[test]
    fn test_empty_minutes() {
        assert!(parse_proxy_auth_value(&auth_header("residential--sess1")).is_err());
    }

    #[test]
    fn test_not_basic_auth() {
        assert!(parse_proxy_auth_value("Bearer token123").is_err());
    }

    #[test]
    fn test_empty_username() {
        assert!(parse_proxy_auth_value(&auth_header("")).is_err());
    }
}
