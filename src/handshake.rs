//! The WebSocket opening handshake.
//!
//! RFC 6455 turns one HTTP request into a WebSocket by echoing the client's
//! `Sec-WebSocket-Key` through SHA-1 and base64 into a `Sec-WebSocket-Accept`.
//! Both primitives are codec's, standard library only, which keeps this
//! crate cross-compiling to every target in the deployment model. SHA-1 here
//! guards a protocol handshake, not a secret; its cryptographic weakness is
//! irrelevant to that job, which is the same reason RFC 6455 still
//! specifies it. Until 2026-09-24 both were written here by hand.
//!
//! The request and its `101` are HTTP/1.1, written and read by `net::http`
//! like every other: until 2026-09-28 this file wrote both by hand, read
//! the path off the request line itself and took any status line with
//! `101` anywhere in it for a switch.

use std::io::{BufRead, Write};

use codec::{base64, random, sha1};
use net::http::{Request, Response, read_request, read_response, write_request, write_response};
use transport::error::{Result, protocol_error};

/// The GUID RFC 6455 fixes for the accept computation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The status a server switches protocols with.
const SWITCHING: u16 = 101;

/// The accept token a server returns for a client's key: base64 of the SHA-1 of
/// the key concatenated with the fixed GUID.
#[must_use]
fn accept_key(client_key: &str) -> String {
    let mut input = client_key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID.as_bytes());

    base64::encode(&sha1::digest(&input))
}

/// A fresh client key: sixteen random bytes, base64-encoded, as RFC 6455
/// section 4.1 asks.
#[must_use]
pub fn client_key() -> String {
    base64::encode(&random::array::<16>())
}

/// Write the client's upgrade request for `path` at `host` with `key`.
///
/// # Errors
///
/// Where the request could not be written.
pub fn send_request(writer: &mut impl Write, host: &str, path: &str, key: &str) -> Result<()> {
    let request = Request::new("GET", path)
        .header("Host", host)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", key)
        .header("Sec-WebSocket-Version", "13");

    Ok(write_request(writer, &request)?)
}

/// Read the server's answer, and check it switched with the token our key
/// implies.
///
/// # Errors
///
/// Where the answer could not be read, was not `101`, or its accept token
/// did not match.
pub fn verify_response(reader: &mut impl BufRead, key: &str) -> Result<()> {
    let answer = read_response(reader)?;
    if answer.status != SWITCHING {
        return Err(protocol_error(format!(
            "the server did not switch: {} {}",
            answer.status, answer.reason
        )));
    }

    let accept = answer
        .header_value("sec-websocket-accept")
        .ok_or_else(|| protocol_error("a 101 with no Sec-WebSocket-Accept"))?;

    if accept != accept_key(key) {
        return Err(protocol_error(
            "the server's accept token did not match the key",
        ));
    }

    Ok(())
}

/// Read a client's upgrade request, and answer it with the server's
/// `101 Switching Protocols`: the request's target, path and query as it
/// travelled.
///
/// # Errors
///
/// Where the request could not be read, carried no `Sec-WebSocket-Key`,
/// or the answer could not be written.
pub fn accept(reader: &mut impl BufRead, writer: &mut impl Write) -> Result<String> {
    let request = read_request(reader)?
        .ok_or_else(|| protocol_error("the connection closed before an upgrade request"))?;
    let key = request
        .header_value("sec-websocket-key")
        .ok_or_else(|| protocol_error("a websocket request with no Sec-WebSocket-Key"))?;
    let switching = Response::new(SWITCHING)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", &accept_key(key));

    write_response(writer, &switching)?;
    Ok(request.target())
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

    #[test]
    fn the_handshake_is_one_http_request_and_its_101() {
        let key = client_key();
        let mut request = Vec::new();
        send_request(&mut request, "feed.example", "/feed?x=1", &key).expect("request");

        let mut answer = Vec::new();
        let path = accept(&mut &request[..], &mut answer).expect("accepted");
        assert_eq!(path, "/feed?x=1");
        assert!(answer.starts_with(b"HTTP/1.1 101 Switching Protocols"));
        verify_response(&mut &answer[..], &key).expect("switched");
    }

    #[test]
    fn an_answer_that_does_not_switch_is_refused_even_saying_101() {
        let refused = verify_response(&mut &b"HTTP/1.1 200 101\r\n\r\n"[..], "key")
            .expect_err("not a switch");
        assert!(refused.message.contains("did not switch"), "{refused}");
        let mut answer = Vec::new();
        write_response(&mut answer, &Response::new(SWITCHING)).expect("written");
        assert!(
            verify_response(&mut &answer[..], "key").is_err(),
            "no accept"
        );
    }
}
