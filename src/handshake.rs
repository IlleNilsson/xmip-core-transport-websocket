//! The WebSocket opening handshake, and the two primitives it needs.
//!
//! RFC 6455 turns one HTTP request into a WebSocket by echoing the client's
//! `Sec-WebSocket-Key` through SHA-1 and base64 into a `Sec-WebSocket-Accept`.
//! Both are implemented here by hand, because `xmip-core-transport` is
//! standard-library only — that is what lets it cross-compile to every target
//! in the deployment model with no cross-compilation story, and one transport
//! is not worth trading that for a crypto dependency. SHA-1 here guards a
//! protocol handshake, not a secret; its cryptographic weakness is irrelevant
//! to that job, which is the same reason RFC 6455 still specifies it.

use std::io::Write;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use transport::error::{Result, classify, protocol_error};
use transport::wire::header;

/// The GUID RFC 6455 fixes for the accept computation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The accept token a server returns for a client's key: base64 of the SHA-1 of
/// the key concatenated with the fixed GUID.
#[must_use]
pub fn accept_key(client_key: &str) -> String {
    let mut input = client_key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID.as_bytes());

    base64(&sha1(&input))
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
    base64(&pseudo_random(16))
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

/// SHA-1 (RFC 3174) of a message. The working variables a..e and the round
/// index are the algorithm's own single-letter notation, so the lint is off for
/// this one function rather than renaming maths that everyone reads letter for
/// letter.
#[allow(clippy::many_single_char_names)]
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let bit_len = u64::try_from(message.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut data = message.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for block in data.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        for (slot, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_mut(4).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// One base64 digit: the low six bits of `bits` through the alphabet.
fn sextet(bits: u32, table: &[u8; 64]) -> char {
    table[(bits & 0x3F) as usize] as char
}

/// Standard base64 (RFC 4648) with padding.
fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(sextet(triple >> 18, TABLE));
        out.push(sextet(triple >> 12, TABLE));
        out.push(if chunk.len() > 1 {
            sextet(triple >> 6, TABLE)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            sextet(triple, TABLE)
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_known_abc_digest() {
        // RFC 3174's own test vector.
        use std::fmt::Write;

        let digest = sha1(b"abc");
        let hex = digest.iter().fold(String::new(), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        });
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn accept_matches_the_rfc_6455_example() {
        // The exact key and accept from RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
