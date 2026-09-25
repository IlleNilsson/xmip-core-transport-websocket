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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
