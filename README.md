# xmip-core-transport-websocket

WebSocket transport: one frame is one Stream, the upgraded case of HTTP. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport), which
owns the direction-neutral `Transport` trait this crate implements (ADR-0010).

Lifted out of the capability crate on 2026-09-07, where it had lived as
`src/websocket` since 2026-08-27 waiting for this repository. The capability keeps
the trait, the error vocabulary and the shared wire helpers; nothing in it names
a protocol. The head a line-oriented protocol reads — lines, then a blank
line — left it on 2026-09-25 for `net::head` in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net).

A Receive Location keeps its listener, bound on the first receive: a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

A connection is upgraded once and kept for every frame after. A Send Location keeps the upgraded connection to each target, its address and path (`transport::Pool`), one data frame a Message; a Receive Location keeps its callers' connections beside the listener (`transport::serving::Serving`, `src/caller.rs`), the upgrade the first turn on each and every frame after it one receive's turn, from whichever caller sends first. A ping between frames is answered with its pong and a close with a close, which ends the connection (RFC 6455 section 5.5). Until 2026-10-21 every send opened a connection and upgraded it for its one frame, every receive accepted one, and a control frame was read as data.

The opening handshake is HTTP/1.1, written and read by `net::http` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), and the `ws://` target is read as a `net::Endpoint` under this technology's schemes (`wss://` refused, there being no TLS here). Until 2026-09-28 the handshake wrote its request and its `101` by hand, read the path off the request line itself and took any status line with `101` in it for a switch, and the target was cut after `ws://` by hand.

## Acknowledgement

Acceptance is at-most-once here. The sender writes its frame and goes on, and
nothing is said back on the connection, so it is never told how the receive
cycle ended and a crash before the Stream is durable loses it. Each frame
arrives whole. A send writes its frame's length first, the Message's being
known before its first byte, then the Message masked as it is read from the
Ledger, a piece at a time, never whole in memory (`Sending::Streamed`,
2026-10-19).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
