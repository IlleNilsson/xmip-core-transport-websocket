#![forbid(unsafe_code)]

//! Streams that arrive over a WebSocket. One frame is one Stream.
//!
//! The upgraded case of HTTP: the caller opens with an HTTP request, both sides
//! switch protocols, and from then on it is framed messages over the same TCP
//! connection, the WebSocket framing a browser or a streaming Party speaks.
//!
//! **Upgraded once, kept for every frame after.** A Send Location keeps the
//! upgraded connection to each target in the capability's pool
//! (`transport::Pool`), one data frame a Message; a Receive Location keeps
//! its callers' connections beside its listener
//! (`transport::serving::Serving`), the upgrade the first turn on each and
//! every frame after it one of its own ([`caller`]). Until 2026-10-21
//! every send opened a connection and upgraded it for its one frame, and
//! every receive accepted one.
//!
//! ```text
//! handshake.rs  the opening upgrade, its accept key SHA-1 and base64 by codec
//! frame.rs      one data frame, masked or not, and the control frames
//! caller.rs     a caller's upgraded connection kept at a Receive Location
//! ```
//!
//! Standard library only, hand-rolled crypto and framing included, so this
//! transport cross-compiles with every other one — see `handshake.rs`.
//!
//! **Acceptance is at-most-once here** ([`AT_MOST_ONCE`]): the sender writes
//! its frame and goes on, and nothing is said back on the connection, so it
//! is never told how the receive cycle ended. Each frame arrives whole.

pub mod caller;
pub mod frame;
pub mod handshake;

use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

pub use caller::Caller;
use net::{Endpoint, Schemes};
use transport::ArrivalIdentity;
use transport::Configured;
use transport::Directions;
use transport::Transport;
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::pool::quiet;
use transport::serving::{Serving, Turn};
use transport::socket;
use transport::{Arrived, Taken};
use transport::{Pool, Pooled};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

/// The schemes a target is written in: `ws://`, which is `http://` for the
/// opening handshake, and `wss://`, which is `https://` and refused, this
/// transport speaking no TLS.
const SCHEMES: Schemes = Schemes {
    plain: &["ws"],
    secure: &["wss"],
};

/// Why a WebSocket frame cannot be acknowledged after the receive cycle.
pub const AT_MOST_ONCE: &str = "a WebSocket frame is answered with nothing: the sender writes \
                                it and goes on";

#[derive(Clone)]
pub struct WebSocketTransport {
    bind: String,
    accept_timeout: Option<Duration>,
    /// The upgraded connection kept to each target, shared by every clone.
    sending: Pool<Upgraded>,
    /// The listener the first receive binds, and the callers' connections
    /// kept open on it between their frames.
    receiving: Serving<Caller>,
}

/// A Send Location's upgraded connection to one target, kept between its
/// frames.
struct Upgraded {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Pooled for Upgraded {
    /// The receiver says nothing back, so a frame it sent to an idle
    /// connection — a close, a ping — or its close lets the connection go.
    fn usable(&mut self) -> bool {
        self.reader.buffer().is_empty() && quiet(&self.writer)
    }
}

impl Upgraded {
    /// A new connection to `endpoint`, upgraded.
    ///
    /// # Errors
    /// Where the endpoint could not be reached, or did not switch.
    fn open(endpoint: &Endpoint, timeout: Option<Duration>) -> Result<Self> {
        // The connect is bounded as well as the reads. This was a bare
        // connect until 2026-09-21, which waits on the operating system's
        // schedule, and longer still on a machine out of ephemeral ports.
        let stream = socket::connect_tcp(&endpoint.address(), timeout)?;
        let (mut reader, mut writer) = socket::split(stream)?;
        let key = handshake::client_key();
        handshake::send_request(&mut writer, &endpoint.authority(), endpoint.path(), &key)?;
        handshake::verify_response(&mut reader, &key)?;
        Ok(Self { reader, writer })
    }
}

impl WebSocketTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            accept_timeout: None,
            sending: Pool::new(),
            receiving: Serving::new(),
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

    /// Take one connection, complete the upgrade, and read one frame, whole.
    /// Acceptance is at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    ///
    /// Where the connection failed, the handshake was malformed, or the frame
    /// could not be read.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        // The wait for the connection is bounded as well as the reads. This
        // did a bare accept until 2026-09-21, so a far end whose near end
        // never connected waited for good, and a hang has no verdict.
        let (stream, peer) = socket::accept_tcp(listener, self.accept_timeout)?;
        let mut caller = Caller::new(stream, peer)?;
        loop {
            match caller.turn()? {
                Turn::Taken(arrived) | Turn::Last(arrived) => return Ok(arrived),
                Turn::Nothing => {}
                Turn::Closed => {
                    return Err(protocol_error("the caller closed before its frame"));
                }
            }
        }
    }
}

impl Transport for WebSocketTransport {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("each frame is its own, at-most-once")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Waits("the listener and the kept connections wait for a frame")
    }

    /// One message, from whichever caller sends first: one new on the
    /// listener the first receive bound and kept, upgraded, or one whose
    /// connection is kept. Acceptance is at-most-once here: nothing is said
    /// back on the connection ([`AT_MOST_ONCE`]).
    fn receive_up_to(&self, _most: usize) -> Result<Vec<Arrived>> {
        let arrived = self.receiving.next(
            || self.bind(),
            self.accept_timeout,
            Caller::new,
            Caller::turn,
        )?;
        Ok(vec![arrived])
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("one frame carries the body, its length first, as it is read")
    }

    /// One data frame on the connection kept to the target's address and
    /// path, or on a new one upgraded for it.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let endpoint = Endpoint::parse_under(target, &SCHEMES)?.plain()?;
        let key = format!("{}{}", endpoint.address(), endpoint.path());
        self.sending.exchange(
            key.as_str(),
            || Upgraded::open(&endpoint, self.accept_timeout),
            |upgraded| frame::write(&mut upgraded.writer, &outgoing, true),
        )
    }
}

impl Configured for WebSocketTransport {
    /// The address is where a Receive Location listens; a Send Location's
    /// `ws://host:port/path` is each send's target. The one setting bounds
    /// the wait for either.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[Setting {
            name: "timeout",
            kind: Kind::Duration,
            presence: Presence::Optional,
            meaning: "How long a connection is waited for, accepted or opened, and how long \
                      one that stops sending is waited on; unbounded when left out.",
            applies: Applies::Both,
        }],
    };

    /// The schemes a Location's address is entered with to choose this technology.
    const SCHEMES: &'static [&'static str] = &["ws"];

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let transport = Self::new(address);
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
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
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        self.accept_one(listener)?.taken()
    }
}

impl Loopback for WebSocketTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::PEER
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::loopback().send(&format!("ws://{address}/round-trip"), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;
    use xcore::settings::Given;

    #[test]
    fn every_receive_takes_from_the_listener_the_first_bound() {
        let receiver = WebSocketTransport::loopback();
        receiver.receiving.bound(|| receiver.bind()).expect("bound");
        let address = receiver.receiving.address().expect("address");
        transport::kept::held_across_receives(&receiver, address, 5, |at, payload| {
            WebSocketTransport::loopback().send_to(at, payload)
        });
    }

    #[test]
    fn websocket_declares_its_settings_and_reads_through_them() {
        assert_eq!(
            WebSocketTransport::SETTINGS.problems(),
            Vec::<String>::new()
        );
        let given = [("timeout".to_string(), Given::Text("250ms".to_string()))];
        let built =
            WebSocketTransport::open("0.0.0.0:8080", Applies::Receive, &given).expect("built");
        assert_eq!(built.bind, "0.0.0.0:8080");
        assert_eq!(built.accept_timeout, Some(Duration::from_millis(250)));
        let wrong = [("timeout".to_string(), Given::Integer(250))];
        let Err(refused) = WebSocketTransport::open("0.0.0.0:8080", Applies::Send, &wrong) else {
            panic!("a timeout is a duration");
        };
        assert!(refused.message.contains("timeout"), "{}", refused.message);
    }

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
    fn a_frame_says_it_is_at_most_once() {
        let receiver = WebSocketTransport::loopback();
        let (listener, address) = receiver.bind().expect("bound");
        let sender = std::thread::spawn(move || {
            WebSocketTransport::loopback().send(&format!("ws://{address}/one"), b"frame")
        });
        let arrived = receiver.accept_one(&listener).expect("accepted");
        sender.join().expect("thread").expect("sent");
        assert!(!arrived.defers(), "nothing is said back");
        assert_eq!(arrived.taken().expect("taken").bytes, b"frame");
    }

    #[test]
    fn a_hundred_frames_to_one_target_upgrade_one_connection_and_every_receive_takes_from_it() {
        // Until 2026-10-21 every send opened a connection and upgraded it
        // for its one frame.
        const ROUNDS: usize = 100;
        let receiver = WebSocketTransport::loopback();
        let address = receiver
            .receiving
            .bound(|| receiver.bind())
            .expect("bound")
            .to_string();
        let sender = std::thread::spawn(move || {
            let sender = WebSocketTransport::loopback();
            let shared = sender.clone();
            for round in 0..ROUNDS {
                let by = if round % 2 == 0 { &sender } else { &shared };
                by.send(
                    &format!("ws://{address}/feed"),
                    format!("f{round}").as_bytes(),
                )
                .expect("sent");
            }
            sender.sending.opened()
        });
        let mut origins = std::collections::BTreeSet::new();
        for round in 0..ROUNDS {
            let taken = receiver.receive().expect("received").remove(0);
            let taken = taken.taken().expect("taken");
            assert_eq!(taken.bytes, format!("f{round}").as_bytes());
            origins.insert(taken.origin_uri);
        }
        assert_eq!(sender.join().expect("sender"), 1, "one upgrade");
        assert_eq!(origins.len(), 1, "every frame on the kept connection");
        assert_eq!(receiver.receiving.open(), 1);
    }

    #[test]
    fn a_kept_connection_answers_a_ping_and_a_close_between_its_frames() {
        use std::io::Write;
        // Short: the last receive finds nothing after the close.
        let receiver =
            WebSocketTransport::new("127.0.0.1:0").timing_out_after(Duration::from_millis(200));
        let address = receiver
            .receiving
            .bound(|| receiver.bind())
            .expect("bound")
            .to_string();
        let endpoint = Endpoint::parse_under(&format!("ws://{address}/feed"), &SCHEMES)
            .and_then(Endpoint::plain)
            .expect("endpoint");
        // Upgraded while the receive waits: the upgrade is the
        // connection's first turn.
        let upgrading = std::thread::spawn(move || {
            let mut caller = Upgraded::open(&endpoint, Some(LOOPBACK_TIMEOUT)).expect("upgraded");
            let one = transport::Outgoing::held(b"one");
            frame::write(&mut caller.writer, &one, true).expect("one");
            caller
        });
        let taken = |receiver: &WebSocketTransport| {
            let arrived = receiver.receive().expect("received").remove(0);
            arrived.taken().expect("taken").bytes
        };
        assert_eq!(taken(&receiver), b"one");
        let mut caller = upgrading.join().expect("the caller");
        // A client's ping is masked, as every frame it writes is.
        let ping = [0x89, 0x80 | 2, 0, 0, 0, 0, b'h', b'i'];
        caller.writer.write_all(&ping).expect("ping");
        frame::write(&mut caller.writer, &transport::Outgoing::held(b"two"), true).expect("two");
        assert_eq!(taken(&receiver), b"two");
        let answered = frame::read(&mut caller.reader).expect("pong");
        assert_eq!(answered, frame::Received::Pong);
        caller
            .writer
            .write_all(&[0x88, 0x80, 0, 0, 0, 0])
            .expect("close");
        assert!(receiver.receive().is_err(), "nothing after the close");
        assert_eq!(
            frame::read(&mut caller.reader).expect("close"),
            frame::Received::Close
        );
        assert_eq!(receiver.receiving.open(), 0);
    }

    #[test]
    fn a_target_without_ws_scheme_is_refused() {
        assert!(Endpoint::parse_under("http://host/x", &SCHEMES).is_err());
        let refused = Endpoint::parse_under("wss://host/x", &SCHEMES)
            .and_then(Endpoint::plain)
            .expect_err("no TLS here");
        assert!(refused.message.contains("TLS"), "{refused}");
    }
}
