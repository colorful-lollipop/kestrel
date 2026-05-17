//! IoT/OT Security Tests
//!
//! IoT和OT安全场景测试 - 检测工业控制系统和物联网设备的安全威胁

use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use std::sync::Arc;

struct TestPredicateEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for TestPredicateEvaluator {
    async fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_event::PredicateResult<bool> {
        Ok(true)
    }
    fn get_required_fields(&self, _id: &str) -> kestrel_event::PredicateResult<Vec<u32>> {
        Ok(vec![])
    }
    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

fn create_iot_engine() -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_iot_event(event_type: u16, entity: u128, timestamp_ns: u64) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .build()
        .unwrap()
}

// =============================================================================
// SCADA/ICS 攻击检测
// =============================================================================

#[test]
fn test_scada_modbus_exploit() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "modbus-exploit".to_string(),
        sequence: NfaSequence::new(
            "modbus-exploit".to_string(),
            300,
            vec![SeqStep::new(0, "modbus-func-90".to_string(), 30001)],
            Some(30000),
            None,
        ),
        rule_id: "modbus-detect".to_string(),
        rule_name: "Modbus Exploit".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30001, 0xD001u128, 1_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_dnp3_manipulation() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "dnp3-manip".to_string(),
        sequence: NfaSequence::new(
            "dnp3-manip".to_string(),
            301,
            vec![
                SeqStep::new(0, "dnp3-cold-restart".to_string(), 30001),
                SeqStep::new(1, "dnp3-unauth-write".to_string(), 30002),
            ],
            Some(60000),
            None,
        ),
        rule_id: "dnp3-detect".to_string(),
        rule_name: "DNP3 Manipulation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30001, 0xD002u128, 2_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30002, 0xD002u128, 2_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_icmp_redirect_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "icmp-redirect".to_string(),
        sequence: NfaSequence::new(
            "icmp-redirect".to_string(),
            302,
            vec![SeqStep::new(0, "icmp-redirect".to_string(), 30003)],
            Some(30000),
            None,
        ),
        rule_id: "icmp-detect".to_string(),
        rule_name: "ICMP Redirect Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30003, 0xD003u128, 3_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_s7comm_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "s7comm-attack".to_string(),
        sequence: NfaSequence::new(
            "s7comm-attack".to_string(),
            303,
            vec![SeqStep::new(0, "s7-download-block".to_string(), 30004)],
            Some(30000),
            None,
        ),
        rule_id: "s7comm-detect".to_string(),
        rule_name: "S7comm Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30004, 0xD004u128, 4_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_opcua_exploit() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "opcuua-exploit".to_string(),
        sequence: NfaSequence::new(
            "opcuua-exploit".to_string(),
            304,
            vec![
                SeqStep::new(0, "opcua-anon-login".to_string(), 30005),
                SeqStep::new(1, "opcua-write-tag".to_string(), 30006),
            ],
            Some(60000),
            None,
        ),
        rule_id: "opcua-detect".to_string(),
        rule_name: "OPC UA Exploit".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30005, 0xD005u128, 5_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30006, 0xD005u128, 5_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_ethernet_ip_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "ethernetip-attack".to_string(),
        sequence: NfaSequence::new(
            "ethernetip-attack".to_string(),
            305,
            vec![SeqStep::new(0, "cip-forward-open".to_string(), 30007)],
            Some(30000),
            None,
        ),
        rule_id: "ethernetip-detect".to_string(),
        rule_name: "EtherNet/IP Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30007, 0xD006u128, 6_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_profinet_manipulation() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "profinet-manip".to_string(),
        sequence: NfaSequence::new(
            "profinet-manip".to_string(),
            306,
            vec![SeqStep::new(0, "profinet-name-change".to_string(), 30008)],
            Some(30000),
            None,
        ),
        rule_id: "profinet-detect".to_string(),
        rule_name: "PROFINET Manipulation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30008, 0xD007u128, 7_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_scada_bacnet_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "bacnet-attack".to_string(),
        sequence: NfaSequence::new(
            "bacnet-attack".to_string(),
            307,
            vec![SeqStep::new(0, "bacnet-write-prop".to_string(), 30009)],
            Some(30000),
            None,
        ),
        rule_id: "bacnet-detect".to_string(),
        rule_name: "BACnet Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30009, 0xD008u128, 8_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 工业蠕虫和恶意软件检测
// =============================================================================

#[test]
fn test_stuxnet_style_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "stuxnet-style".to_string(),
        sequence: NfaSequence::new(
            "stuxnet-style".to_string(),
            310,
            vec![
                SeqStep::new(0, "usb-autorun".to_string(), 30010),
                SeqStep::new(1, "step7-freq-change".to_string(), 30011),
            ],
            Some(3600000),
            None,
        ),
        rule_id: "stuxnet-detect".to_string(),
        rule_name: "Stuxnet Style Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30010, 0xD010u128, 10_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30011, 0xD010u128, 10_600_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_havex_ics_scan() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "havex-scan".to_string(),
        sequence: NfaSequence::new(
            "havex-scan".to_string(),
            311,
            vec![SeqStep::new(0, "opc-enum-servers".to_string(), 30012)],
            Some(30000),
            None,
        ),
        rule_id: "havex-detect".to_string(),
        rule_name: "Havex ICS Scan".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30012, 0xD011u128, 11_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_industroyer_crashoverride() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "industroyer".to_string(),
        sequence: NfaSequence::new(
            "industroyer".to_string(),
            312,
            vec![
                SeqStep::new(0, "iec104-ioa-change".to_string(), 30013),
                SeqStep::new(1, "iec104-switch-cmd".to_string(), 30014),
            ],
            Some(60000),
            None,
        ),
        rule_id: "industroyer-detect".to_string(),
        rule_name: "Industroyer Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30013, 0xD012u128, 12_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30014, 0xD012u128, 12_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_triton_trisis_attack() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "triton-attack".to_string(),
        sequence: NfaSequence::new(
            "triton-attack".to_string(),
            313,
            vec![SeqStep::new(0, "tristation-upload".to_string(), 30015)],
            Some(30000),
            None,
        ),
        rule_id: "triton-detect".to_string(),
        rule_name: "Triton/TRISIS Attack".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30015, 0xD013u128, 13_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// IoT 设备安全检测
// =============================================================================

#[test]
fn test_iot_mirai_botnet() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "mirai-botnet".to_string(),
        sequence: NfaSequence::new(
            "mirai-botnet".to_string(),
            320,
            vec![
                SeqStep::new(0, "telnet-login-attempt".to_string(), 30016),
                SeqStep::new(1, "telnet-bruteforce".to_string(), 30017),
            ],
            Some(600000),
            None,
        ),
        rule_id: "mirai-detect".to_string(),
        rule_name: "Mirai Botnet".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30016, 0xD020u128, 20_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30017, 0xD020u128, 20_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_iot_default_credentials() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "iot-default-creds".to_string(),
        sequence: NfaSequence::new(
            "iot-default-creds".to_string(),
            321,
            vec![SeqStep::new(0, "default-login".to_string(), 30018)],
            Some(30000),
            None,
        ),
        rule_id: "iot-creds-detect".to_string(),
        rule_name: "IoT Default Credentials".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30018, 0xD021u128, 21_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_iot_firmware_vulnerability() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "iot-firmware-vuln".to_string(),
        sequence: NfaSequence::new(
            "iot-firmware-vuln".to_string(),
            322,
            vec![
                SeqStep::new(0, "upnp-soap-action".to_string(), 30019),
                SeqStep::new(1, "cmd-injection".to_string(), 30020),
            ],
            Some(60000),
            None,
        ),
        rule_id: "iot-firmware-detect".to_string(),
        rule_name: "IoT Firmware Vulnerability".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30019, 0xD022u128, 22_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30020, 0xD022u128, 22_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_iot_botnet_c2_communication() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "iot-c2-comms".to_string(),
        sequence: NfaSequence::new(
            "iot-c2-comms".to_string(),
            323,
            vec![
                SeqStep::new(0, "port23-scan".to_string(), 30021),
                SeqStep::new(1, "syn-flood".to_string(), 30022),
            ],
            Some(300000000),
            None,
        ),
        rule_id: "iot-c2-detect".to_string(),
        rule_name: "IoT Botnet C2".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30021, 0xD023u128, 23_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30022, 0xD023u128, 23_300_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_iot_unauthorized_access() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "iot-unauthorized".to_string(),
        sequence: NfaSequence::new(
            "iot-unauthorized".to_string(),
            324,
            vec![
                SeqStep::new(0, "config-read".to_string(), 30023),
                SeqStep::new(1, "unauthorized-write".to_string(), 30024),
            ],
            Some(60000),
            None,
        ),
        rule_id: "iot-unauth-detect".to_string(),
        rule_name: "IoT Unauthorized Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30023, 0xD024u128, 24_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30024, 0xD024u128, 24_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 工业网络异常检测
// =============================================================================

#[test]
fn test_ics_network_scan() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "ics-net-scan".to_string(),
        sequence: NfaSequence::new(
            "ics-net-scan".to_string(),
            330,
            vec![
                SeqStep::new(0, "port-scan-start".to_string(), 30025),
                SeqStep::new(1, "rapid-port-probe".to_string(), 30026),
            ],
            Some(30000),
            None,
        ),
        rule_id: "ics-scan-detect".to_string(),
        rule_name: "ICS Network Scan".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30025, 0xD030u128, 30_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30026, 0xD030u128, 30_050_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_ics_protocol_anomaly() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "ics-proto-anomaly".to_string(),
        sequence: NfaSequence::new(
            "ics-proto-anomaly".to_string(),
            331,
            vec![SeqStep::new(0, "malformed-packet".to_string(), 30027)],
            Some(30000),
            None,
        ),
        rule_id: "ics-proto-detect".to_string(),
        rule_name: "ICS Protocol Anomaly".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30027, 0xD031u128, 31_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_ics_unauthorized_device() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "ics-unauth-device".to_string(),
        sequence: NfaSequence::new(
            "ics-unauth-device".to_string(),
            332,
            vec![SeqStep::new(0, "new-device-arp".to_string(), 30028)],
            Some(30000),
            None,
        ),
        rule_id: "ics-device-detect".to_string(),
        rule_name: "ICS Unauthorized Device".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30028, 0xD032u128, 32_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_ics_command_sequence_anomaly() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "ics-cmd-anomaly".to_string(),
        sequence: NfaSequence::new(
            "ics-cmd-anomaly".to_string(),
            333,
            vec![
                SeqStep::new(0, "emergency-stop".to_string(), 30029),
                SeqStep::new(1, "emergency-stop".to_string(), 30029),
                SeqStep::new(2, "emergency-stop".to_string(), 30029),
            ],
            Some(30000),
            None,
        ),
        rule_id: "ics-cmd-detect".to_string(),
        rule_name: "ICS Command Sequence Anomaly".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30029, 0xD033u128, 33_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30029, 0xD033u128, 33_010_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30029, 0xD033u128, 33_020_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 物理安全集成检测
// =============================================================================

#[test]
fn test_physical_access_breach() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "physical-breach".to_string(),
        sequence: NfaSequence::new(
            "physical-breach".to_string(),
            340,
            vec![
                SeqStep::new(0, "after-hours-access".to_string(), 30030),
                SeqStep::new(1, "forced-door-open".to_string(), 30031),
            ],
            Some(60000),
            None,
        ),
        rule_id: "physical-breach-detect".to_string(),
        rule_name: "Physical Access Breach".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30030, 0xD040u128, 40_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30031, 0xD040u128, 40_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_cctv_tampering() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "cctv-tamper".to_string(),
        sequence: NfaSequence::new(
            "cctv-tamper".to_string(),
            341,
            vec![SeqStep::new(0, "video-signal-loss".to_string(), 30032)],
            Some(30000),
            None,
        ),
        rule_id: "cctv-detect".to_string(),
        rule_name: "CCTV Tampering".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30032, 0xD041u128, 41_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_environmental_sensor_anomaly() {
    let mut nfa = create_iot_engine();
    let seq = CompiledSequence {
        id: "env-sensor-anomaly".to_string(),
        sequence: NfaSequence::new(
            "env-sensor-anomaly".to_string(),
            342,
            vec![SeqStep::new(0, "temp-critical-high".to_string(), 30033)],
            Some(30000),
            None,
        ),
        rule_id: "env-sensor-detect".to_string(),
        rule_name: "Environmental Sensor Anomaly".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_iot_event(30033, 0xD042u128, 42_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}
