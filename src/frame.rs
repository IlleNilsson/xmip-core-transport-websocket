//! One WebSocket data frame, written and read.
//!
//! RFC 6455 framing, the subset Xmip needs: a single final binary frame per
//! Stream. A client MUST mask; a server MUST NOT. A connection is kept for
//! frame after frame, so the control frames a peer may send on it are told
//! apart from data ([`Received`]): a ping is answered with its pong and a
//! close with a close ([`control`], RFC 6455 section 5.5). Until 2026-10-21
//! every frame came on a connection of its own, dropped after it, and a
//! control frame was read as data.

use std::io::{self, BufWriter, Read, Write};

use net::MAX_BODY;
use net::ceiling;
use transport::Outgoing;
use transport::error::{Result, classify};

/// FIN set, opcode 2 (binary).
const FIN_BINARY: u8 = 0x82;
/// FIN set, the bit every frame written here carries.
const FIN: u8 = 0x80;
/// The opcodes of the control frames (RFC 6455 section 5.5).
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xA;
/// The most a control frame carries (RFC 6455 section 5.5).
const MAX_CONTROL: usize = 125;
const MASK_BIT: u8 = 0x80;

/// What one frame said.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A data frame's payload, unmasked.
    Data(Vec<u8>),
    /// A ping, and what its pong must carry back.
    Ping(Vec<u8>),
    /// A pong: nothing to do.
    Pong,
    /// The peer closes the connection.
    Close,
}
/// The 7-bit length field's two escape values: read a 16- or 64-bit length next.
const LEN_16: u8 = 126;
const LEN_64: u8 = 127;

/// Write `outgoing`'s body as one binary frame: its length first, as the
/// body's is known before its first byte, then the body as it is read —
/// masked as it passes where `masked` says, never whole in memory.
/// `masked` is true from a client, false from a server.
///
/// # Errors
///
/// Where the body could not be read, or the frame could not be written.
pub fn write(stream: &mut impl Write, outgoing: &Outgoing<'_>, masked: bool) -> Result<()> {
    let mut head = vec![FIN_BINARY];

    let flag = if masked { MASK_BIT } else { 0 };
    let len = outgoing.length();
    if let Ok(tiny) = u8::try_from(len)
        && tiny < LEN_16
    {
        head.push(flag | tiny);
    } else if let Ok(short) = u16::try_from(len) {
        head.push(flag | LEN_16);
        head.extend_from_slice(&short.to_be_bytes());
    } else {
        head.push(flag | LEN_64);
        head.extend_from_slice(&len.to_be_bytes());
    }

    let written = |e: &io::Error| classify("writing a websocket frame", e);
    let mut buffered = BufWriter::new(stream);
    if masked {
        // RFC 6455 section 5.3: a fresh key a frame, from a strong source of
        // entropy, so a script cannot choose the bytes a proxy sees.
        let key: [u8; 4] = codec::random::array();
        head.extend_from_slice(&key);
        buffered.write_all(&head).map_err(|e| written(&e))?;
        outgoing.write_to(&mut Masked {
            inner: &mut buffered,
            key,
            at: 0,
        })?;
    } else {
        buffered.write_all(&head).map_err(|e| written(&e))?;
        outgoing.write_to(&mut buffered)?;
    }
    buffered
        .flush()
        .map_err(|e| classify("flushing a websocket frame", &e))
}

/// A frame's payload masked as it is written (RFC 6455 section 5.3): each
/// byte exclusive-or the key's byte at its place in the payload.
struct Masked<'a, W: Write> {
    inner: &'a mut W,
    key: [u8; 4],
    at: usize,
}

impl<W: Write> Write for Masked<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut piece = [0u8; 1024];
        let taken = bytes.len().min(piece.len());
        for (place, (out, byte)) in piece.iter_mut().zip(&bytes[..taken]).enumerate() {
            *out = byte ^ self.key[(self.at + place) % 4];
        }
        self.inner.write_all(&piece[..taken])?;
        self.at += taken;
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Write a control frame with `opcode` and `payload`, unmasked, as a server
/// writes: the pong to a ping, the close that answers a close.
///
/// # Errors
///
/// Where the payload is over what a control frame carries, or the frame
/// could not be written.
pub fn control(stream: &mut impl Write, opcode: u8, payload: &[u8]) -> Result<()> {
    let length = u8::try_from(payload.len())
        .ok()
        .filter(|&length| usize::from(length) <= MAX_CONTROL)
        .ok_or_else(|| transport::error::protocol_error("a control frame over 125 bytes"))?;
    let mut frame = vec![FIN | opcode, length];
    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|e| classify("writing a websocket control frame", &e))
}

/// Read one frame, unmasking its payload if the sender masked it: a data
/// frame's payload, or the control frame it is.
///
/// # Errors
///
/// Where the frame could not be read, or claimed a payload over [`MAX_BODY`].
pub fn read(reader: &mut impl Read) -> Result<Received> {
    let mut prefix = [0u8; 2];
    read_exact(reader, &mut prefix, "reading a frame header")?;

    let opcode = prefix[0] & 0x0f;
    let masked = prefix[1] & MASK_BIT != 0;
    let length = payload_length(reader, prefix[1] & 0x7f)?;

    let mut key = [0u8; 4];
    if masked {
        read_exact(reader, &mut key, "reading the mask key")?;
    }

    let mut payload = vec![0u8; length];
    read_exact(reader, &mut payload, "reading the frame payload")?;

    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }

    Ok(match opcode {
        CLOSE => Received::Close,
        PING => Received::Ping(payload),
        PONG => Received::Pong,
        _ => Received::Data(payload),
    })
}

/// The declared payload length, reading the 16- or 64-bit extension where the
/// 7-bit field says to.
fn payload_length(reader: &mut impl Read, seven: u8) -> Result<usize> {
    let length = match seven {
        LEN_16 => {
            let mut ext = [0u8; 2];
            read_exact(reader, &mut ext, "reading the extended length")?;
            usize::from(u16::from_be_bytes(ext))
        }
        LEN_64 => {
            let mut ext = [0u8; 8];
            read_exact(reader, &mut ext, "reading the extended length")?;
            usize::try_from(u64::from_be_bytes(ext)).unwrap_or(usize::MAX)
        }
        other => usize::from(other),
    };

    ceiling::within(length, MAX_BODY, "Xmip reads in one frame")?;

    Ok(length)
}

fn read_exact(reader: &mut impl Read, buffer: &mut [u8], step: &str) -> Result<()> {
    reader.read_exact(buffer).map_err(|e| classify(step, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data frame `reader` holds next.
    fn data(reader: &mut impl Read) -> Vec<u8> {
        match read(reader).expect("reading") {
            Received::Data(payload) => payload,
            other => panic!("not data: {other:?}"),
        }
    }

    #[test]
    fn a_ping_a_pong_and_a_close_are_told_from_data() {
        let mut wire = Vec::new();
        control(&mut wire, PING, b"are you there").expect("ping");
        control(&mut wire, PONG, b"").expect("pong");
        control(&mut wire, CLOSE, b"").expect("close");
        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(
            read(&mut cursor).expect("ping"),
            Received::Ping(b"are you there".to_vec())
        );
        assert_eq!(read(&mut cursor).expect("pong"), Received::Pong);
        assert_eq!(read(&mut cursor).expect("close"), Received::Close);
        assert!(control(&mut Vec::new(), PING, &[0; 126]).is_err());
    }

    #[test]
    fn a_masked_frame_reads_back_as_it_was_written() {
        let mut wire = Vec::new();
        write(&mut wire, &Outgoing::held(b"ping over ws"), true).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(data(&mut cursor), b"ping over ws");
    }

    #[test]
    fn an_unmasked_frame_reads_back_too() {
        let mut wire = Vec::new();
        write(&mut wire, &Outgoing::held(&[0x00, 0x01, 0xfe, 0xff]), false).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(data(&mut cursor), [0x00, 0x01, 0xfe, 0xff]);
    }

    #[test]
    fn a_payload_at_the_two_byte_length_boundary_survives() {
        // 200 bytes forces the 126 extended-length path.
        let payload = vec![0x5au8; 200];
        let mut wire = Vec::new();
        write(&mut wire, &Outgoing::held(&payload), true).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(data(&mut cursor), payload);
    }

    #[test]
    fn a_body_read_in_pieces_is_masked_across_them_and_reads_back() {
        // Past 64 KiB, the 127 path, and masked across many pieces.
        let payload: Vec<u8> = (0..70_000u32)
            .map(|n| u8::try_from(n % 251).unwrap_or_default())
            .collect();
        let outgoing = Outgoing::new(payload.len() as u64, || Ok(Box::new(&payload[..])));
        let mut wire = Vec::new();
        write(&mut wire, &outgoing, true).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(data(&mut cursor), payload);
    }
}
