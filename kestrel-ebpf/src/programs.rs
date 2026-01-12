//! eBPF Programs
//!
//! This module contains the eBPF program implementations.

use crate::EbpfError;
use aya::programs::Lsm;
use aya::Ebpf;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

pub struct AttachedPrograms {
    pub execve_tracepoint: Option<aya::programs::TracePoint>,
    pub lsm_bprm_check_security: Option<Lsm>,
    pub lsm_file_open: Option<Lsm>,
    pub lsm_socket_connect: Option<Lsm>,
    pub lsm_inode_permission: Option<Lsm>,
}

impl AttachedPrograms {
    pub fn new() -> Self {
        Self {
            execve_tracepoint: None,
            lsm_bprm_check_security: None,
            lsm_file_open: None,
            lsm_socket_connect: None,
            lsm_inode_permission: None,
        }
    }

    pub fn detach_all(&mut self) {
        self.execve_tracepoint = None;
        self.lsm_bprm_check_security = None;
        self.lsm_file_open = None;
        self.lsm_socket_connect = None;
        self.lsm_inode_permission = None;
    }
}

pub struct ProgramManager {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl ProgramManager {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>) -> Self {
        Self { ebpf }
    }

    pub fn ebpf(&self) -> &Arc<Mutex<Ebpf>> {
        &self.ebpf
    }

    pub fn attach_process_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching process event programs");

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
        if let Some(program) = ebpf.program_mut("handle_execve") {
            let tracepoint: &mut aya::programs::TracePoint = program
                .try_into()
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            tracepoint
                .load()
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            tracepoint
                .attach("syscalls", "sys_enter_execve")
                .map_err(|e| EbpfError::AttachmentError(format!("{:?}", e)))?;
            debug!("Execve tracepoint attached");
        }

        debug!("Process event programs attached");
        Ok(())
    }

    pub fn attach_file_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching file event programs");

        let btf =
            aya::Btf::from_sys_fs().map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
        if let Some(program) = ebpf.program_mut("lsm_file_open") {
            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.load("lsm_file_open", &btf)
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.attach()
                .map_err(|e| EbpfError::AttachmentError(format!("{:?}", e)))?;
            debug!("LSM file_open attached");
        }

        if let Some(program) = ebpf.program_mut("lsm_inode_permission") {
            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.load("lsm_inode_permission", &btf)
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.attach()
                .map_err(|e| EbpfError::AttachmentError(format!("{:?}", e)))?;
            debug!("LSM inode_permission attached");
        }

        debug!("File event programs attached");
        Ok(())
    }

    pub fn attach_network_programs(&mut self) -> Result<(), EbpfError> {
        info!("Attaching network event programs");

        let btf =
            aya::Btf::from_sys_fs().map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
        if let Some(program) = ebpf.program_mut("lsm_socket_connect") {
            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.load("lsm_socket_connect", &btf)
                .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
            lsm.attach()
                .map_err(|e| EbpfError::AttachmentError(format!("{:?}", e)))?;
            debug!("LSM socket_connect attached");
        }

        debug!("Network event programs attached");
        Ok(())
    }

    pub fn detach_all(&mut self) -> Result<(), EbpfError> {
        info!("Detaching all eBPF programs");
        debug!("All programs detached");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_manager_placeholder() {}
}
