//! One WebSocket data frame, written and read.
//!
//! RFC 6455 framing, the subset Xmip needs: a single final binary frame per
//! Stream. A client MUST mask; a server MUST NOT. Control frames (ping, close)
//! are not written here and a received one is not expected — the exchange is one
//! frame each way and the connection is dropped after, which the playground and
//! a request/response caller both want.

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use transport::error::{Result, classify, protocol_error};
use transport::wire::MAX_BODY;

/// FIN set, opcode 2 (binary).
const FIN_BINARY: u8 = 0x82;
const MASK_BIT: u8 = 0x80;
/// The 7-bit length field's two escape values: read a 16- or 64-bit length next.
const LEN_16: u8 = 126;
const LEN_64: u8 = 127;

/// Write `payload` as one binary frame. `masked` is true from a client, false
/// from a server.
///
/// # Errors
///
/// Where the frame could not be written.
pub fn write(stream: &mut impl Write, payload: &[u8], masked: bool) -> Result<()> {
    let mut frame = vec![FIN_BINARY];

    let flag = if masked { MASK_BIT } else { 0 };
    let len = payload.len();
    if let Ok(tiny) = u8::try_from(len)
        && tiny < LEN_16
    {
        frame.push(flag | tiny);
    } else if let Ok(short) = u16::try_from(len) {
        frame.push(flag | LEN_16);
        frame.extend_from_slice(&short.to_be_bytes());
    } else {
        frame.push(flag | LEN_64);
        frame.extend_from_slice(&u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes());
    }

    if masked {
        let key = mask_key();
        frame.extend_from_slice(&key);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        frame.extend_from_slice(payload);
    }

    stream
        .write_all(&frame)
        .map_err(|e| classify("writing a websocket frame", &e))?;
    stream
        .flush()
        .map_err(|e| classify("flushing a websocket frame", &e))
}

/// Read one frame's payload, unmasking if the sender masked it.
///
/// # Errors
///
/// Where the frame could not be read, or claimed a payload over [`MAX_BODY`].
pub fn read(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    read_exact(reader, &mut prefix, "reading a frame header")?;

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

    Ok(payload)
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

    if length > MAX_BODY {
        return Err(protocol_error(format!(
            "a frame of {length} bytes, over the {MAX_BODY} byte limit"
        )));
    }

    Ok(length)
}

fn read_exact(reader: &mut impl Read, buffer: &mut [u8], step: &str) -> Result<()> {
    reader.read_exact(buffer).map_err(|e| classify(step, &e))
}

/// Four bytes of non-secret masking key from the clock. Masking exists to keep
/// intermediaries from mistaking payload for framing, not to hide anything, so
/// it need only vary — and std carries no RNG.
fn mask_key() -> [u8; 4] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x1234_5678, |elapsed| elapsed.subsec_nanos());

    nanos.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_masked_frame_reads_back_as_it_was_written() {
        let mut wire = Vec::new();
        write(&mut wire, b"ping over ws", true).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(read(&mut cursor).expect("reading"), b"ping over ws");
    }

    #[test]
    fn an_unmasked_frame_reads_back_too() {
        let mut wire = Vec::new();
        write(&mut wire, &[0x00, 0x01, 0xfe, 0xff], false).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(
            read(&mut cursor).expect("reading"),
            [0x00, 0x01, 0xfe, 0xff]
        );
    }

    #[test]
    fn a_payload_at_the_two_byte_length_boundary_survives() {
        // 200 bytes forces the 126 extended-length path.
        let payload = vec![0x5au8; 200];
        let mut wire = Vec::new();
        write(&mut wire, &payload, true).expect("writing");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(read(&mut cursor).expect("reading"), payload);
    }
}
