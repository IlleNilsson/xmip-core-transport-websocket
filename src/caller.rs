//! A caller's upgraded connection, kept open at a Receive Location between
//! its frames.
//!
//! The opening handshake is the connection's first turn
//! (`transport::serving::Turn::Nothing`); every data frame after it is one
//! turn of its own, handed up as a Stream carrying what the upgrade request
//! said — its target and headers. A ping is answered with its pong, and a
//! close with a close, which ends the connection. Until 2026-10-21 a
//! receive accepted a connection, upgraded it and read one frame, and the
//! caller upgraded a connection for every frame it sent.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};

use net::http::Request;
use transport::error::{Result, classify};
use transport::serving::{Open, Turn};
use transport::{Acknowledgement, Arrived, Headers};

use crate::frame::{self, Received};
use crate::{AT_MOST_ONCE, handshake};

/// One caller's connection, upgraded on its first turn.
pub struct Caller {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    /// The upgrade request, once it is answered.
    upgrade: Option<Request>,
}

impl Caller {
    /// A caller's new connection, from `peer`, not yet upgraded.
    ///
    /// # Errors
    /// Where the connection could not be cloned for its reads.
    pub fn new(stream: TcpStream, peer: SocketAddr) -> Result<Self> {
        let (reader, writer) = transport::socket::split(stream)?;
        Ok(Self {
            reader,
            writer,
            peer,
            upgrade: None,
        })
    }

    /// One turn: the upgrade, where the connection has not had it, or the
    /// next frame. A caller that closed between frames has hung up, not
    /// failed. Acceptance is at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    /// Where the handshake was malformed, or a frame could not be read or
    /// answered.
    pub fn turn(&mut self) -> Result<Turn<Arrived>> {
        let ended = self
            .reader
            .fill_buf()
            .map_err(|e| classify("reading the connection", &e))?
            .is_empty();
        if ended {
            return Ok(Turn::Closed);
        }
        let Some(upgrade) = &self.upgrade else {
            self.upgrade = Some(handshake::accept(&mut self.reader, &mut self.writer)?);
            return Ok(Turn::Nothing);
        };
        let payload = match frame::read(&mut self.reader)? {
            Received::Data(payload) => payload,
            Received::Ping(payload) => {
                frame::control(&mut self.writer, frame::PONG, &payload)?;
                return Ok(Turn::Nothing);
            }
            Received::Pong => return Ok(Turn::Nothing),
            Received::Close => {
                // Answered, and the connection is let go: the caller is
                // the one to close it (RFC 6455 section 7.1.1).
                drop(frame::control(&mut self.writer, frame::CLOSE, &[]));
                return Ok(Turn::Closed);
            }
        };
        // Who is calling is said on the upgrade request: the peer it came
        // from and its headers, HTTP's.
        let arrived = Arrived::whole(
            format!("ws://{}{}", self.peer, upgrade.target()),
            payload,
            Acknowledgement::at_most_once(AT_MOST_ONCE),
        )
        .with_headers(Headers::of("http").text(upgrade.headers.iter().cloned()))
        .from_peer(self.peer);
        Ok(Turn::Taken(arrived))
    }
}

impl Open for Caller {
    fn socket(&self) -> &TcpStream {
        &self.writer
    }

    /// A frame the last read took beside its own waits in the reader.
    fn waiting(&self) -> bool {
        !self.reader.buffer().is_empty()
    }
}
