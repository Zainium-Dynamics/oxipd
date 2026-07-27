//! Pure wire-format codecs for oxipd.
//!
//! Every module here is `#![no_std]`-friendly in spirit (no tokio, no sockets,
//! no filesystem): a codec takes bytes in, gives typed values out, or takes
//! typed values in and gives bytes out. This keeps the highest-risk code
//! (parsing attacker-controlled network input) trivially unit-testable and
//! fuzzable in isolation from I/O and privilege concerns.

pub mod dhcpv4;

pub use dhcpv4::{Message as Dhcpv4Message, MessageBuilder as Dhcpv4MessageBuilder};
