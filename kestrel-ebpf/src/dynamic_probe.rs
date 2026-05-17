use aya::Ebpf;
use aya::programs::{KProbe, Lsm, TracePoint};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Unique identifier for a probe
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeType {
    Kprobe,
    Kretprobe,
    Tracepoint,
    Lsm,
    Uprobe,
    Uretprobe,
}

#[derive(Debug, Clone)]
pub enum ProbeTarget {
    Kprobe { function: String },
    Tracepoint { category: String, name: String },
    Lsm { hook: String },
    Uprobe { binary: String, function: String },
}

#[derive(Debug, Clone)]
pub struct ProbeMetadata {
    pub id: ProbeId,
    pub probe_type: ProbeType,
    pub target: ProbeTarget,
    pub attached_at: std::time::SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("Program not found: {0}")]
    ProgramNotFound(String),
    #[error("Attach failed: {0}")]
    AttachFailed(String),
    #[error("Detach failed: {0}")]
    DetachFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Conflict with existing probe: {0}")]
    Conflict(String),
}

/// Core trait for dynamic probe management
#[async_trait::async_trait]
pub trait DynamicProbeManager: Send + Sync {
    async fn attach(
        &self,
        id: ProbeId,
        probe_type: ProbeType,
        target: ProbeTarget,
    ) -> Result<ProbeMetadata, ProbeError>;

    async fn detach(&self, id: &ProbeId) -> Result<(), ProbeError>;

    async fn list_probes(&self) -> Vec<ProbeMetadata>;

    async fn shutdown(&self) -> Result<(), ProbeError>;
}

/// Production implementation using aya
pub struct AyaProbeManager {
    ebpf: Arc<RwLock<Ebpf>>,
    probes: Arc<RwLock<HashMap<ProbeId, LoadedProbe>>>,
}

struct LoadedProbe {
    metadata: ProbeMetadata,
    // Program handle - dropped to detach
}

impl AyaProbeManager {
    pub fn new(ebpf: Arc<RwLock<Ebpf>>) -> Self {
        Self {
            ebpf,
            probes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl DynamicProbeManager for AyaProbeManager {
    async fn attach(
        &self,
        id: ProbeId,
        probe_type: ProbeType,
        target: ProbeTarget,
    ) -> Result<ProbeMetadata, ProbeError> {
        let mut ebpf = self.ebpf.write().await;

        // Load the program from the eBPF object
        let program = ebpf
            .program_mut(&id.0)
            .ok_or_else(|| ProbeError::ProgramNotFound(id.0.clone()))?;

        match probe_type {
            ProbeType::Kprobe => {
                if let ProbeTarget::Kprobe { function } = &target {
                    let prog: &mut KProbe = program
                        .try_into()
                        .map_err(|e| ProbeError::AttachFailed(format!("{:?}", e)))?;
                    prog.load()
                        .map_err(|e| ProbeError::AttachFailed(format!("Load: {}", e)))?;
                    prog.attach(function, 0)
                        .map_err(|e| ProbeError::AttachFailed(format!("Attach: {}", e)))?;
                }
            },
            ProbeType::Tracepoint => {
                if let ProbeTarget::Tracepoint { category, name } = &target {
                    let prog: &mut TracePoint = program
                        .try_into()
                        .map_err(|e| ProbeError::AttachFailed(format!("{:?}", e)))?;
                    prog.load()
                        .map_err(|e| ProbeError::AttachFailed(format!("Load: {}", e)))?;
                    prog.attach(category, name)
                        .map_err(|e| ProbeError::AttachFailed(format!("Attach: {}", e)))?;
                }
            },
            ProbeType::Lsm => {
                if let ProbeTarget::Lsm { hook } = &target {
                    let prog: &mut Lsm = program
                        .try_into()
                        .map_err(|e| ProbeError::AttachFailed(format!("{:?}", e)))?;
                    prog.load(hook)
                        .map_err(|e| ProbeError::AttachFailed(format!("Load: {}", e)))?;
                    // LSM auto-attaches on load
                }
            },
            _ => {
                return Err(ProbeError::AttachFailed("Unsupported probe type".to_string()));
            },
        }

        let metadata = ProbeMetadata {
            id: id.clone(),
            probe_type,
            target: target.clone(),
            attached_at: std::time::SystemTime::now(),
        };

        self.probes.write().await.insert(
            id,
            LoadedProbe {
                metadata: metadata.clone(),
            },
        );

        info!(probe_id = %metadata.id.0, "Probe attached");
        Ok(metadata)
    }

    async fn detach(&self, id: &ProbeId) -> Result<(), ProbeError> {
        let mut probes = self.probes.write().await;
        if probes.remove(id).is_some() {
            info!(probe_id = %id.0, "Probe detached");
            Ok(())
        } else {
            Err(ProbeError::DetachFailed(format!("Probe {} not found", id.0)))
        }
    }

    async fn list_probes(&self) -> Vec<ProbeMetadata> {
        let probes = self.probes.read().await;
        probes.values().map(|p| p.metadata.clone()).collect()
    }

    async fn shutdown(&self) -> Result<(), ProbeError> {
        let ids: Vec<_> = self.probes.read().await.keys().cloned().collect();
        for id in ids {
            let _ = self.detach(&id).await;
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[test]
    fn test_probe_id_creation() {
        let id = ProbeId("test_probe".to_string());
        assert_eq!(id.0, "test_probe");
    }

    #[test]
    fn test_probe_id_clone_and_eq() {
        let id1 = ProbeId("probe_a".to_string());
        let id2 = id1.clone();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_probe_type_equality() {
        assert_eq!(ProbeType::Kprobe, ProbeType::Kprobe);
        assert_ne!(ProbeType::Kprobe, ProbeType::Lsm);
        assert_ne!(ProbeType::Tracepoint, ProbeType::Uprobe);
    }

    #[test]
    fn test_probe_target_kprobe() {
        let target = ProbeTarget::Kprobe {
            function: "do_sys_open".to_string(),
        };
        match target {
            ProbeTarget::Kprobe { function } => {
                assert_eq!(function, "do_sys_open");
            },
            _ => panic!("Expected Kprobe target"),
        }
    }

    #[test]
    fn test_probe_target_tracepoint() {
        let target = ProbeTarget::Tracepoint {
            category: "syscalls".to_string(),
            name: "sys_enter_open".to_string(),
        };
        match target {
            ProbeTarget::Tracepoint { category, name } => {
                assert_eq!(category, "syscalls");
                assert_eq!(name, "sys_enter_open");
            },
            _ => panic!("Expected Tracepoint target"),
        }
    }

    #[test]
    fn test_probe_target_lsm() {
        let target = ProbeTarget::Lsm {
            hook: "bprm_check_security".to_string(),
        };
        match target {
            ProbeTarget::Lsm { hook } => {
                assert_eq!(hook, "bprm_check_security");
            },
            _ => panic!("Expected Lsm target"),
        }
    }

    #[test]
    fn test_probe_target_uprobe() {
        let target = ProbeTarget::Uprobe {
            binary: "/bin/bash".to_string(),
            function: "main".to_string(),
        };
        match target {
            ProbeTarget::Uprobe { binary, function } => {
                assert_eq!(binary, "/bin/bash");
                assert_eq!(function, "main");
            },
            _ => panic!("Expected Uprobe target"),
        }
    }

    #[test]
    fn test_probe_error_display() {
        let err = ProbeError::ProgramNotFound("prog_x".to_string());
        assert_eq!(err.to_string(), "Program not found: prog_x");

        let err = ProbeError::AttachFailed("load failed".to_string());
        assert_eq!(err.to_string(), "Attach failed: load failed");

        let err = ProbeError::DetachFailed("not found".to_string());
        assert_eq!(err.to_string(), "Detach failed: not found");
    }

    #[test]
    fn test_probe_metadata_fields() {
        let metadata = ProbeMetadata {
            id: ProbeId("test".to_string()),
            probe_type: ProbeType::Kprobe,
            target: ProbeTarget::Kprobe {
                function: "foo".to_string(),
            },
            attached_at: std::time::SystemTime::now(),
        };
        assert_eq!(metadata.id.0, "test");
        assert_eq!(metadata.probe_type, ProbeType::Kprobe);
    }
}
