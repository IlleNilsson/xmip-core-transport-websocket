//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Settings};

/// Every setting a Location takes beyond its address: where a Receive
/// Location listens; a Send Location's `ws://host:port/path` is each send's
/// target. The one setting bounds the wait for either.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[transport::configured::timeout(
        Applies::Both,
        None,
        "How long a connection is waited for, accepted or opened, and how long \
         one that stops sending is waited on; unbounded when left out.",
    )],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["ws"];
