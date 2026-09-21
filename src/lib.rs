#![forbid(unsafe_code)]

//! Streams that arrive over a WebSocket. One frame is one Stream.
//!
//! The upgraded case of HTTP: the caller opens with an HTTP request, both sides
//! switch protocols, and from then on it is framed messages over the same TCP
//! connection. Xmip drives one message each way and closes — a request/response
//! shape, like http, but over the WebSocket framing a browser or a streaming
//! partner speaks.
//!
//! ```text
//! handshake.rs  the opening upgrade, and the SHA-1/base64 it needs
//! frame.rs      one data frame, masked or not
//! ```
//!
//! Standard library only, hand-rolled crypto and framing included, so this
//! transport cross-compiles with every other one — see `handshake.rs`.

pub mod frame;
pub mod handshake;

use std::io::BufReader;
use std::net::TcpListener;
use std::time::Duration;

use transport::Arrived;
use transport::Directions;
use transport::Transport;
use transport::error::{Result, classify, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::wire::{host_of, read_head, with_default_port};

#[derive(Clone)]
pub struct WebSocketTransport {
    bind: String,
    accept_timeout: Option<Duration>,
}

impl WebSocketTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            accept_timeout: None,
        }
    }

    /// Give up on a connection that does not arrive, or stops sending, as
    /// `TcpTransport` does.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.accept_timeout = Some(timeout);
        self
    }

    /// Bind and report the address actually assigned.
    ///
    /// # Errors
    ///
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Take one connection, complete the upgrade, and read one frame.
    ///
    /// # Errors
    ///
    /// Where the connection failed, the handshake was malformed, or the frame
    /// could not be read.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        // The wait for the connection is bounded as well as the reads. This
        // did a bare accept until 2026-09-21, so a far end whose near end
        // never connected waited for good, and a hang has no verdict.
        let (mut stream, peer) = socket::accept_tcp(listener, self.accept_timeout)?;

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| classify("cloning the connection", &e))?,
        );

        let head = read_head(&mut reader)?;
        let path = handshake::request_path(&head);
        let key = handshake::client_key_of(&head)?;
        handshake::accept(&mut stream, &key)?;

        let payload = frame::read(&mut reader)?;

        Ok(Arrived::new(format!("ws://{peer}{path}"), payload))
    }
}

impl Transport for WebSocketTransport {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;

        Ok(vec![self.accept_one(&listener)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (authority, path) = split_target(target)?;
        let address = with_default_port(authority, 80);

        // The connect is bounded as well as the reads. This was a bare
        // connect until 2026-09-21, which waits on the operating system's
        // schedule, and longer still on a machine out of ephemeral ports.
        let mut stream = socket::connect_tcp(&address, self.accept_timeout)?;

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| classify("cloning the connection", &e))?,
        );

        let key = handshake::client_key();
        handshake::send_request(&mut stream, host_of(authority), path, &key)?;

        let head = read_head(&mut reader)?;
        handshake::verify_response(&head, &key)?;

        frame::write(&mut stream, bytes, true)
    }
}

/// Split `ws://host:port/path` into its authority and path.
fn split_target(target: &str) -> Result<(&str, &str)> {
    let rest = target
        .strip_prefix("ws://")
        .ok_or_else(|| protocol_error(format!("not a ws:// target: {target}")))?;

    match rest.find('/') {
        Some(cut) => Ok((&rest[..cut], &rest[cut..])),
        None => Ok((rest, "/")),
    }
}

impl WebSocketTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on the accept, the connect and the reads.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for WebSocketTransport {
    fn take_one(&self, listener: &TcpListener) -> Result<Arrived> {
        self.accept_one(listener)
    }
}

impl Loopback for WebSocketTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening::new(self.clone(), listener, address)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::loopback().send(&format!("ws://{address}/round-trip"), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    #[test]
    fn websocket_round_trip_carries_the_body_and_the_path() {
        let arrived = WebSocketTransport::loopback()
            .round(b"<order/>")
            .expect("round");

        assert_eq!(arrived.bytes, b"<order/>");
        assert!(arrived.origin_uri.starts_with("ws://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/round-trip"));
    }

    #[test]
    fn websocket_carries_binary_unharmed() {
        let arrived = WebSocketTransport::loopback()
            .round(&[0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff])
            .expect("round");

        assert_eq!(arrived.bytes, [0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff]);
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let websocket = WebSocketTransport::loopback();
        assert!(websocket.ceiling().is_none());
        for (name, bytes) in edge_payloads() {
            assert!(websocket.refuses(&bytes).is_none(), "{name}");
            assert_eq!(websocket.round(&bytes).expect(name).bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_target_without_ws_scheme_is_refused() {
        assert!(split_target("http://host/x").is_err());
    }
}
