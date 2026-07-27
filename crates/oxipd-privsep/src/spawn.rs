//! Forks the privileged helper process. Must be called before any tokio
//! runtime (or any other thread) exists in this process: `fork()` in a
//! multi-threaded process only duplicates the calling thread, which is
//! generally unsafe to build a whole new process's runtime state on top
//! of. Calling this from the very top of `main`, before `#[tokio::main]`
//! or `Builder::new_current_thread()` ever runs, keeps that invariant.

use std::os::fd::OwnedFd;

use crate::channel::{self, BlockingChannel};
use crate::helper;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("channel setup failed: {0}")]
    Channel(#[from] channel::Error),
    #[error("fork(2) failed: {0}")]
    Fork(#[source] std::io::Error),
}

/// The engine-side handle to a spawned helper: its process id and its end
/// of the privsep channel (still a raw, non-blocking-not-yet-set fd; wrap
/// with [`crate::client::PrivsepClient::new`] once inside a tokio runtime).
pub struct Helper {
    pub pid: libc::pid_t,
    pub channel_fd: OwnedFd,
}

/// Fork the privileged helper. In the parent, returns immediately with a
/// [`Helper`] handle. In the child, this function never returns: it drops
/// privileges to the minimum needed (see [`crate::privileges`]) and runs
/// [`helper::run`] until the engine disconnects, then calls
/// `std::process::exit`.
///
/// # Safety-relevant preconditions
/// Must be called before spawning any other thread (including starting a
/// tokio runtime) in this process.
pub fn spawn() -> Result<Helper, Error> {
    let (engine_end, helper_end) = channel::socketpair()?;

    // SAFETY: fork(2) itself is safe to call; the safety burden documented
    // on this function is about *what runs after* fork in a
    // multi-threaded process, which is the caller's responsibility (see
    // this function's doc comment).
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(Error::Fork(std::io::Error::last_os_error())),
        0 => {
            // Child: drop the engine's end, keep only ours.
            drop(engine_end);
            child_main(helper_end);
        }
        _ => {
            // Parent: drop the helper's end, keep only ours.
            drop(helper_end);
            Ok(Helper {
                pid,
                channel_fd: engine_end,
            })
        }
    }
}

fn child_main(helper_end: OwnedFd) -> ! {
    if let Err(e) = crate::privileges::drop_to_minimum() {
        tracing::error!("privsep helper: failed to drop privileges, exiting: {e}");
        std::process::exit(1);
    }

    helper::run(BlockingChannel::new(helper_end));
    std::process::exit(0);
}
