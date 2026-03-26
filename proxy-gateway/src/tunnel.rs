use crate::rotator::ResolvedProxy;

use anyhow::{Context, Result};
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Establish a CONNECT tunnel through an upstream proxy, then relay bidirectionally.
pub async fn handle_connect<IO>(
    client_io: IO,
    target_authority: String,
    upstream: &ResolvedProxy,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let proxy_addr = format!("{}:{}", upstream.host, upstream.port);
    debug!("CONNECT tunnel: connecting to upstream proxy {proxy_addr}");

    let mut tcp = TcpStream::connect(&proxy_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream proxy {proxy_addr}"))?;

    // Send CONNECT request to upstream proxy.
    send_connect_request(&mut tcp, &target_authority, upstream).await?;

    let via = &proxy_addr;
    info!("Tunnel established: {target_authority} via {via}");

    // Bidirectional relay.
    bidirectional_copy(client_io, tcp).await;
    Ok(())
}

/// Forward a plain HTTP request through an upstream proxy.
pub async fn forward_http(
    method: &str,
    uri: &str,
    headers: &[(String, String)],
    body: &[u8],
    upstream: &ResolvedProxy,
) -> Result<Vec<u8>> {
    let proxy_addr = format!("{}:{}", upstream.host, upstream.port);
    let mut tcp = TcpStream::connect(&proxy_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream proxy {proxy_addr}"))?;

    // Build HTTP request to send through the proxy (absolute URI).
    let mut req = format!("{method} {uri} HTTP/1.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(auth) = proxy_auth_header(upstream) {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");

    tcp.write_all(req.as_bytes()).await?;
    if !body.is_empty() {
        tcp.write_all(body).await?;
    }

    read_full_response(&mut tcp).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn proxy_auth_header(upstream: &ResolvedProxy) -> Option<String> {
    let username = upstream.username.as_deref()?;
    let password = upstream.password.as_deref().unwrap_or("");
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    Some(format!("Basic {encoded}"))
}

async fn send_connect_request<S>(
    stream: &mut S,
    target_authority: &str,
    upstream: &ResolvedProxy,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\n");
    if let Some(auth) = proxy_auth_header(upstream) {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");

    debug!("Sending CONNECT to upstream:\n{req}");
    stream.write_all(req.as_bytes()).await?;

    // Read until the full HTTP response is received (ends with \r\n\r\n).
    // Some upstream proxies (e.g. Bottingtools residential) send the status
    // line and headers in separate TCP packets. A single read() would only
    // get the first packet and miss the terminal \r\n\r\n, causing the
    // leftover bytes to corrupt the subsequent TLS handshake.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("Upstream proxy closed connection without response");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let resp = String::from_utf8_lossy(&buf);
    debug!("Upstream CONNECT response: {resp}");

    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
        error!("Upstream proxy rejected CONNECT: {resp}");
        anyhow::bail!("Upstream proxy rejected CONNECT: {resp}");
    }

    Ok(())
}

/// Bidirectional copy between two async streams.
async fn bidirectional_copy<A, B>(a: A, b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a2b = async {
        let r = tokio::io::copy(&mut a_read, &mut b_write).await;
        debug!("client→upstream finished: {:?}", r);
        let _ = b_write.shutdown().await;
        r
    };

    let b2a = async {
        let r = tokio::io::copy(&mut b_read, &mut a_write).await;
        debug!("upstream→client finished: {:?}", r);
        let _ = a_write.shutdown().await;
        r
    };

    let _ = tokio::join!(a2b, b2a);
}

async fn read_full_response<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
    }
    Ok(response)
}
