//! Event Simulator for End-to-End Testing
//!
//! 模拟真实的系统事件，包括进程、文件、网络等操作

use kestrel_event::{Event, EventBuilder};
use kestrel_schema::{EventTypeId, FieldId, TypedValue};
use std::time::SystemTime;

/// 事件类型定义
#[derive(Debug, Clone, Copy)]
pub enum SimulatedEventType {
    ProcessStart,
    ProcessExit,
    FileCreate,
    FileDelete,
    FileModify,
    NetworkConnect,
    NetworkAccept,
}

/// 事件模拟器
pub struct EventSimulator {
    next_event_id: u64,
    base_timestamp: u64,
}

impl EventSimulator {
    /// 创建新的事件模拟器
    pub fn new() -> Self {
        Self {
            next_event_id: 1,
            base_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }

    /// 生成下一个事件ID
    fn next_id(&mut self) -> u64 {
        let id = self.next_event_id;
        self.next_event_id += 1;
        id
    }

    /// 生成下一个时间戳（递增1ms）
    fn next_timestamp(&mut self) -> u64 {
        let ts = self.base_timestamp;
        self.base_timestamp += 1_000_000; // +1ms
        ts
    }

    /// 模拟进程启动事件
    pub fn process_start(&mut self, pid: u32, ppid: u32, name: &str, cmdline: &str) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(1) // PROCESS_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(((pid as u128) << 32) | (ppid as u128))
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(2, TypedValue::U32(ppid)) // FIELD_PPID
            .field(3, TypedValue::String(name.to_string())) // FIELD_NAME
            .field(4, TypedValue::String(cmdline.to_string())) // FIELD_CMDLINE
            .build()
            .unwrap()
    }

    /// 模拟进程退出事件
    pub fn process_exit(&mut self, pid: u32, exit_code: i32) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(2) // PROCESS_EXIT_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(pid as u128)
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(5, TypedValue::I32(exit_code)) // FIELD_EXIT_CODE
            .build()
            .unwrap()
    }

    /// 模拟文件创建事件
    pub fn file_create(&mut self, pid: u32, path: &str) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(3) // FILE_CREATE_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(((pid as u128) << 32) | (std::ptr::hash(path) as u128))
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(10, TypedValue::String(path.to_string())) // FIELD_PATH
            .build()
            .unwrap()
    }

    /// 模拟文件修改事件
    pub fn file_modify(&mut self, pid: u32, path: &str) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(4) // FILE_MODIFY_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(((pid as u128) << 32) | (std::ptr::hash(path) as u128))
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(10, TypedValue::String(path.to_string())) // FIELD_PATH
            .build()
            .unwrap()
    }

    /// 模拟文件删除事件
    pub fn file_delete(&mut self, pid: u32, path: &str) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(5) // FILE_DELETE_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(((pid as u128) << 32) | (std::ptr::hash(path) as u128))
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(10, TypedValue::String(path.to_string())) // FIELD_PATH
            .build()
            .unwrap()
    }

    /// 模拟网络连接事件
    pub fn network_connect(&mut self, pid: u32, dest_ip: &str, dest_port: u16) -> Event {
        EventBuilder::default()
            .event_id(self.next_id())
            .event_type(6) // NETWORK_CONNECT_TYPE
            .ts_mono(self.next_timestamp())
            .ts_wall(self.base_timestamp)
            .entity_key(((pid as u128) << 32) | (dest_port as u128))
            .field(1, TypedValue::U32(pid)) // FIELD_PID
            .field(20, TypedValue::String(dest_ip.to_string())) // FIELD_DEST_IP
            .field(21, TypedValue::U16(dest_port)) // FIELD_DEST_PORT
            .build()
            .unwrap()
    }

    /// 生成可疑的 PowerShell 执行场景
    pub fn scenario_powershell_suspicious(&mut self) -> Vec<Event> {
        let mut events = Vec::new();

        // 1. 进程启动：powershell.exe
        events.push(self.process_start(
            1234,
            100,
            "powershell.exe",
            "powershell.exe -EncodedCommand XYZ",
        ));

        // 2. 文件创建：下载脚本
        events.push(self.file_create(1234, "/tmp/script.ps1"));

        // 3. 文件修改：写入内容
        events.push(self.file_modify(1234, "/tmp/script.ps1"));

        // 4. 网络连接：连接到可疑IP
        events.push(self.network_connect(1234, "192.168.1.100", 4444));

        events
    }

    /// 生成文件篡改场景
    pub fn scenario_file_tampering(&mut self) -> Vec<Event> {
        let mut events = Vec::new();

        // 1. 启动编辑器
        events.push(self.process_start(5678, 100, "vim", "vim /etc/passwd"));

        // 2. 打开文件
        events.push(self.file_create(5678, "/etc/passwd"));

        // 3. 修改文件
        events.push(self.file_modify(5678, "/etc/passwd"));

        // 4. 再次修改（多次篡改）
        events.push(self.file_modify(5678, "/etc/passwd"));

        events
    }

    /// 生成正常进程场景（不应触发告警）
    pub fn scenario_normal_process(&mut self) -> Vec<Event> {
        let mut events = Vec::new();

        // 正常启动进程
        events.push(self.process_start(
            9999,
            100,
            "bash",
            "bash -c 'echo hello'",
        ));

        // 正常退出
        events.push(self.process_exit(9999, 0));

        events
    }
}

impl Default for EventSimulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulator_creation() {
        let mut sim = EventSimulator::new();
        let event = sim.process_start(100, 1, "test", "test");

        assert_eq!(event.event_id, 1);
        assert_eq!(event.fields.len(), 4);
    }

    #[test]
    fn test_powershell_scenario() {
        let mut sim = EventSimulator::new();
        let events = sim.scenario_powershell_suspicious();

        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_id, 1);
        assert_eq!(events[3].event_id, 4);
    }
}
