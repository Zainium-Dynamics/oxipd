//! The DHCPv4 client: a pure state machine ([`fsm`]) plus the typed lease
//! view ([`lease`]) and timing constants ([`timing`]) it's built from. The
//! async "shell" that drives this over real sockets/netlink (see PLAN.md's
//! M3 milestone) is the next increment.

pub mod fsm;
pub mod lease;
pub mod message;
pub mod timing;

pub use fsm::{Action, Dhcp4Fsm, Event, State};
pub use lease::Lease;
