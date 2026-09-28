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

A Receive Location keeps its listener, bound on the first receive (`transport::kept::Kept`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

The opening handshake is HTTP/1.1, written and read by `net::http` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), and the `ws://` target is read as a `net::Endpoint` under this technology's schemes (`wss://` refused, there being no TLS here). Until 2026-09-28 the handshake wrote its request and its `101` by hand, read the path off the request line itself and took any status line with `101` in it for a switch, and the target was cut after `ws://` by hand.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
