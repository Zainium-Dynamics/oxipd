//! Drops the privileged helper down to the minimum Linux capabilities it
//! actually needs (`CAP_NET_ADMIN` for netlink mutations, `CAP_NET_RAW`
//! for raw packet/ICMPv6 sockets), instead of running it as full root.
//!
//! Full uid-dropping while retaining just those capabilities (via
//! `PR_SET_KEEPCAPS` + ambient capabilities, so the helper runs as a
//! non-root uid but keeps exactly these two caps) is deferred: it needs
//! root to test end-to-end, which this development environment doesn't
//! have. What's implemented here — shrinking the bounding/permitted/
//! effective/inheritable sets down to just the two needed capabilities —
//! is meaningful on its own (it blocks everything else root could do, e.g.
//! `CAP_SYS_ADMIN`, even before the uid-dropping step lands) and is safe
//! to exercise now.

use std::collections::HashSet;

use caps::{CapSet, Capability};

const KEEP: &[Capability] = &[Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("capability operation failed: {0}")]
    Caps(#[from] caps::errors::CapsError),
}

/// Shrink every capability set down to at most [`KEEP`].
///
/// If the process holds no capabilities to begin with (e.g. this
/// project's current dev/test environment, or a deployment that already
/// starts the helper unprivileged via file capabilities instead of
/// root-then-drop), this is a verified no-op rather than an error: you can
/// only set Effective/Permitted/Inheritable to a *subset* of what's
/// currently in the Permitted set, so intersecting `KEEP` with whatever is
/// actually held first is what makes this safe to call unconditionally.
pub fn drop_to_minimum() -> Result<(), Error> {
    let wanted: HashSet<Capability> = KEEP.iter().copied().collect();
    let permitted = caps::read(None, CapSet::Permitted)?;
    let keep: HashSet<Capability> = wanted.intersection(&permitted).copied().collect();

    // Bounding set gates what a process can ever re-acquire, so shrink it
    // too: drop every capability not in `keep`. Modifying it at all
    // requires CAP_SETPCAP, which an already-unprivileged process won't
    // have — that failure is expected and not fatal here, since
    // Effective/Permitted below is what actually enforces the policy.
    for cap in caps::all() {
        if !keep.contains(&cap) {
            if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                tracing::debug!("privileges: could not drop {cap:?} from bounding set: {e}");
            }
        }
    }

    caps::set(None, CapSet::Inheritable, &keep)?;
    caps::set(None, CapSet::Permitted, &keep)?;
    caps::set(None, CapSet::Effective, &keep)?;

    Ok(())
}

/// Read back the effective capability set, for logging/tests.
pub fn effective() -> Result<HashSet<Capability>, Error> {
    Ok(caps::read(None, CapSet::Effective)?)
}
