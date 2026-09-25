//! The WebSocket opening handshake.
//!
//! RFC 6455 turns one HTTP request into a WebSocket by echoing the client's
//! `Sec-WebSocket-Key` through SHA-1 and base64 into a `Sec-WebSocket-Accept`.
//! Both primitives are codec's, standard library only, which keeps this
//! crate cross-compiling to every target in the deployment model. SHA-1 here
//! guards a protocol handshake, not a secret; its cryptographic weakness is
//! irrelevant to that job, which is the same reason RFC 6455 still
//! specifies it. Until 2026-09-24 both were written here by hand.

use std::io::Write;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use codec::{base64, sha1};
use net::head::header;
use transport::error::{Result, classify, protocol_error};

/// The GUID RFC 6455 fixes for the accept computation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The accept token a server returns for a client's key: base64 of the SHA-1 of
/// the key concatenated with the fixed GUID.
#[must_use]
pub fn accept_key(client_key: &str) -> String {
    let mut input = client_key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID.as_bytes());

    base64::encode(&sha1::digest(&input))
}

/// The path from the request line: `GET /feed HTTP/1.1`.
#[must_use]
pub fn request_path(head: &[String]) -> String {
    head.first()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string()
}

/// The client's key out of the request headers.
///
/// # Errors
///
/// Where the request carried no `Sec-WebSocket-Key`.
pub fn client_key_of(head: &[String]) -> Result<String> {
    header(head, "sec-websocket-key")
        .map(str::to_string)
        .ok_or_else(|| protocol_error("a websocket request with no Sec-WebSocket-Key"))
}

/// A fresh client key: sixteen bytes, base64-encoded, as RFC 6455 asks.
#[must_use]
pub fn client_key() -> String {
    base64::encode(&pseudo_random(16))
}

/// Write the client's upgrade request.
///
/// # Errors
///
/// Where the request could not be written.
pub fn send_request(stream: &mut TcpStream, host: &str, path: &str, key: &str) -> Result<()> {
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );

    write_all(stream, request.as_bytes(), "sending the upgrade request")
}

/// Check the server accepted with the token our key implies.
///
/// # Errors
///
/// Where the response was not `101`, or the accept token did not match.
pub fn verify_response(head: &[String], key: &str) -> Result<()> {
    let status = head.first().map_or("", String::as_str);
    if !status.contains("101") {
        return Err(protocol_error(format!(
            "the server did not switch: {status}"
        )));
    }

    let accept = header(head, "sec-websocket-accept")
        .ok_or_else(|| protocol_error("a 101 with no Sec-WebSocket-Accept"))?;

    if accept != accept_key(key) {
        return Err(protocol_error(
            "the server's accept token did not match the key",
        ));
    }

    Ok(())
}

/// Write the server's `101 Switching Protocols`.
///
/// # Errors
///
/// Where the response could not be written.
pub fn accept(stream: &mut TcpStream, client_key: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(client_key)
    );

    write_all(stream, response.as_bytes(), "accepting the upgrade")
}

fn write_all(stream: &mut TcpStream, bytes: &[u8], step: &str) -> Result<()> {
    stream.write_all(bytes).map_err(|e| classify(step, &e))?;
    stream.flush().map_err(|e| classify(step, &e))
}

/// Sixteen or four bytes of non-secret nonce, from the clock through an LCG. Not
/// cryptographic randomness — a masking key and a handshake nonce need to vary,
/// not to be unguessable, and the std library carries no RNG.
fn pseudo_random(n: usize) -> Vec<u8> {
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x9E37_79B9_7F4A_7C15, |elapsed| {
            elapsed.as_secs() ^ u64::from(elapsed.subsec_nanos())
        });

    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33).to_le_bytes()[0]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_matches_the_rfc_6455_example() {
        // The exact key and accept from RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
