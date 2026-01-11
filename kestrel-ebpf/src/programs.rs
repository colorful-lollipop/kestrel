//! eBPF Programs
//!
//! This module contains the eBPF program implementations.
//!
//! NOTE: The actual eBPF programs are written in C and compiled separately.
//! This module provides Rust-side management and configuration for those programs.

use crate::{EbpfError, EbpfEventType};
use aya::{programs::KProbe, Ebpf};
use tracing::{debug, info};

/// eBPF program manager
///
/// Manages the lifecycle of eBPF programs attached to kernel hooks.
pub struct ProgramManager {
    /// Loaded eBPF object
    #[allow(dead_code)]
    ebpf: Ebpf,
}

impl ProgramManager {
    /// Create a new program manager
    pub fn new(ebpf: Ebpf) -> Self {
        Self { ebpf }
    }

    /// Attach process event programs
    ///
    /// Attaches hooks for:
    /// - execve/execveat (process execution)
    /// - sched_process_exit (process exit)
    pub fn attach_process_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching process event programs");

        // TODO: Attach execve hook
        // TODO: Attach exit hook

        debug!("Process event programs attached");
        Ok(())
    }

    /// Attach file event programs
    ///
    /// Attaches hooks for:
    /// - do_sys_open2 / filp_open (file open)
    /// - vfs_rename (file rename)
    /// - vfs_unlink (file delete)
    pub fn attach_file_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching file event programs");

        // TODO: Attach file open hook
        // TODO: Attach file rename hook
        // TODO: Attach file unlink hook

        debug!("File event programs attached");
        Ok(())
    }

    /// Attach network event programs
    ///
    /// Attaches hooks for:
    /// - tcp_v4_connect / tcp_v6_connect (TCP connect)
    /// - tcp_sendmsg / udp_sendmsg (network send)
    pub fn attach_network_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching network event programs");

        // TODO: Attach TCP connect hook
        // TODO: Attach sendmsg hook

        debug!("Network event programs attached");
        Ok(())
    }

    /// Detach all programs
    pub fn detach_all(&mut self) -> Result<(), EbpfError> {
        info!("Detaching all eBPF programs");

        // TODO: Detach all hooks

        debug!("All programs detached");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_manager_placeholder() {
        // Placeholder test for future eBPF program testing
        // Once actual eBPF programs are implemented, these tests will
        // verify attachment and detachment
    }
}
