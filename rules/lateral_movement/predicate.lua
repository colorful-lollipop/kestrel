--[[
  Lateral Movement Detection Rule
  
  Detects lateral movement through:
  1. SSH connection followed by command execution patterns
  2. Remote service execution (psexec-style patterns)
  3. Credential reuse indicators
  4. Unusual authentication patterns
  5. Network share mounting and access
  
  MITRE ATT&CK:
  - T1021: Remote Services
  - T1077: Windows Admin Shares (Linux equivalent: NFS/SMB)
  - T1550: Use Alternate Authentication Material
--]]

-- Remote execution tools
local REMOTE_EXEC_TOOLS = {
  -- SSH-based tools
  ["ssh"] = "ssh_remote_access",
  ["scp"] = "scp_file_transfer",
  ["sftp"] = "sftp_file_transfer",
  ["rsync"] = "rsync_remote_sync",
  
  -- Remote execution frameworks
  ["pssh"] = "parallel_ssh",
  ["pdsh"] = "parallel_distributed_shell",
  ["mussh"] = "multi_host_ssh",
  ["cssh"] = "cluster_ssh",
  ["ansible"] = "ansible_automation",
  ["ansible-playbook"] = "ansible_playbook",
  
  -- Remote management tools (often abused)
  ["salt"] = "saltstack",
  ["salt-call"] = "saltstack_call",
  ["puppet"] = "puppet_agent",
  ["chef-client"] = "chef_client",
  ["fabric"] = "python_fabric",
  
  -- File sharing protocols
  ["mount"] = "filesystem_mount",
  ["mount.cifs"] = "cifs_mount",
  ["mount.nfs"] = "nfs_mount",
  ["smbclient"] = "smb_client",
  ["rpcclient"] = "rpc_client",
  
  -- Remote desktop (Linux variants)
  ["xfreerdp"] = "rdp_client",
  ["rdesktop"] = "rdp_client",
  ["vncviewer"] = "vnc_client",
  ["remmina"] = "remote_desktop_client"
}

-- Suspicious SSH arguments indicating lateral movement
local SUSPICIOUS_SSH_PATTERNS = {
  -- Key-based auth without password
  { pattern = "-i%s+.*id_rsa", desc = "ssh_key_auth" },
  { pattern = "-i%s+.*id_dsa", desc = "ssh_key_auth" },
  { pattern = "-i%s+.*id_ecdsa", desc = "ssh_key_auth" },
  { pattern = "-i%s+.*id_ed25519", desc = "ssh_key_auth" },
  
  -- Command execution without interactive shell
  { pattern = "ssh%s+.*%s+%%-t?%s+[%w_-]+%s+", desc = "ssh_remote_command" },
  { pattern = "ssh%s+.*['\"].*['\"]", desc = "ssh_quoted_command" },
  
  -- Port forwarding (tunneling)
  { pattern = "%-L%s+%d+", desc = "ssh_local_forward" },
  { pattern = "%-R%s+%d+", desc = "ssh_remote_forward" },
  { pattern = "%-D%s+%d+", desc = "ssh_dynamic_forward" },
  
  -- Agent forwarding
  { pattern = "%-A", desc = "ssh_agent_forward" },
  { pattern = "%-o%s+ForwardAgent", desc = "ssh_agent_forward" }
}

-- Services commonly used for lateral movement
local LATERAL_SERVICES = {
  ["sshd"] = "ssh_service",
  ["smbd"] = "smb_service",
  ["nmbd"] = "netbios_service",
  ["rpcbind"] = "rpc_service",
  ["nfsd"] = "nfs_service",
  ["telnetd"] = "telnet_service"  -- Highly suspicious
}

-- Suspicious network ports for lateral movement
local SUSPICIOUS_PORTS = {
  [23] = "telnet",
  [135] = "msrpc",
  [139] = "netbios_ssn",
  [445] = "microsoft_ds",
  [3389] = "rdp",
  [5985] = "winrm_http",
  [5986] = "winrm_https",
  [5900] = "vnc",
  [5901] = "vnc_1",
  [5902] = "vnc_2"
}

-- State tracking
local process_lateral_ops = {}
local ssh_connections = {}
local TIME_WINDOW_NS = 60 * 1000000000  -- 60 seconds

function pred_init()
  process_lateral_ops = {}
  ssh_connections = {}
  return 0
end

-- Helper: Check if executable is remote execution tool
local function check_remote_tool(executable)
  if not executable then return nil end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  if name then
    return REMOTE_EXEC_TOOLS[name]
  end
  return nil
end

-- Helper: Check for suspicious SSH patterns
local function check_ssh_patterns(args)
  if not args then return nil end
  
  for _, pattern_info in ipairs(SUSPICIOUS_SSH_PATTERNS) do
    if string.find(args, pattern_info.pattern) then
      return pattern_info.desc
    end
  end
  return nil
end

-- Helper: Check if service is lateral movement service
local function check_service(service_name)
  if not service_name then return nil end
  
  return LATERAL_SERVICES[string.lower(service_name)]
end

-- Helper: Check if port is suspicious
local function check_port(port)
  if not port then return nil end
  return SUSPICIOUS_PORTS[port]
end

function pred_eval(event)
  local event_type = kestrel.event_get_i64(event, 1)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local args = kestrel.event_get_str(event, 5)
  local ppid = kestrel.event_get_i64(event, 6)
  local now = kestrel.event_get_i64(event, 100)
  
  if not process_pid then return false end
  
  local pid = tostring(process_pid)
  
  -- Initialize tracking
  if not process_lateral_ops[pid] then
    process_lateral_ops[pid] = {
      pid = process_pid,
      lateral_ops = 0,
      detection_reasons = {},
      remote_connections = {},
      first_op_time = now
    }
  end
  
  local proc_state = process_lateral_ops[pid]
  local is_suspicious = false
  local detection_reason = nil
  
  -- Check 1: Remote execution tool usage
  if event_type == 1001 then
    local tool_type = check_remote_tool(executable)
    if tool_type then
      is_suspicious = true
      detection_reason = tool_type
      proc_state.lateral_ops = proc_state.lateral_ops + 1
    end
    
    -- SSH-specific pattern analysis
    if string.find(string.lower(executable or ""), "ssh") then
      local ssh_pattern = check_ssh_patterns(args)
      if ssh_pattern then
        is_suspicious = true
        detection_reason = ssh_pattern
        proc_state.lateral_ops = proc_state.lateral_ops + 1
      end
      
      -- Track SSH connection attempt
      if args then
        -- Extract destination host
        local host = string.match(args, "^%s*([%w%.%-_]+)")
        if host then
          ssh_connections[pid] = {
            time = now,
            pid = process_pid,
            host = host,
            args = args
          }
        end
      end
    end
  end
  
  -- Check 2: Network connections to suspicious ports
  if event_type == 4001 then  -- connect
    local dest_ip = kestrel.event_get_str(event, 50)
    local dest_port = kestrel.event_get_i64(event, 51)
    local src_port = kestrel.event_get_i64(event, 53)
    
    local port_service = check_port(dest_port)
    if port_service then
      is_suspicious = true
      detection_reason = "connection_to_" .. port_service
      proc_state.lateral_ops = proc_state.lateral_ops + 1
      table.insert(proc_state.remote_connections, {
        ip = dest_ip,
        port = dest_port,
        service = port_service,
        time = now
      })
    end
    
    -- Track SSH connections specifically
    if dest_port == 22 then
      ssh_connections[pid] = {
        time = now,
        pid = process_pid,
        ip = dest_ip,
        port = dest_port
      }
    end
  end
  
  -- Check 3: Service starts (SSH, SMB, etc.)
  if event_type == 5001 then  -- service start
    local service_name = kestrel.event_get_str(event, 60)
    local service_type = check_service(service_name)
    if service_type then
      is_suspicious = true
      detection_reason = service_type .. "_started"
      proc_state.lateral_ops = proc_state.lateral_ops + 1
    end
  end
  
  -- Check 4: Authentication events
  if event_type == 6001 then  -- authentication
    local auth_type = kestrel.event_get_str(event, 70)
    local auth_result = kestrel.event_get_str(event, 71)
    local src_ip = kestrel.event_get_str(event, 72)
    
    -- Successful auth from external source
    if auth_result == "success" and src_ip then
      -- Check if IP is not local
      if not string.find(src_ip, "^127%.") and
         not string.find(src_ip, "^192%.168%.") and
         not string.find(src_ip, "^10%.") and
         not string.find(src_ip, "^172%.1[6-9]%.") and
         not string.find(src_ip, "^172%.2[0-9]%.") and
         not string.find(src_ip, "^172%.3[0-1]%.") then
        is_suspicious = true
        detection_reason = "remote_authentication_success"
        proc_state.lateral_ops = proc_state.lateral_ops + 1
      end
    end
    
    -- Multiple failed authentications
    if auth_result == "failure" then
      proc_state.failed_auths = (proc_state.failed_auths or 0) + 1
      if proc_state.failed_auths >= 5 then
        is_suspicious = true
        detection_reason = "multiple_auth_failures"
      end
    end
  end
  
  -- Update detection reasons
  if is_suspicious and detection_reason then
    proc_state.detection_reasons[detection_reason] = true
  end
  
  -- Cleanup old SSH connections
  local cutoff = now - TIME_WINDOW_NS
  for stored_pid, conn in pairs(ssh_connections) do
    if conn.time < cutoff then
      ssh_connections[stored_pid] = nil
    end
  end
  
  -- Check threshold
  if proc_state.lateral_ops >= 2 then
    return true
  end
  
  -- Immediate alert on specific patterns
  if detection_reason == "telnet" or
     detection_reason == "multiple_auth_failures" then
    return true
  end
  
  return false
end

function pred_capture(event)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local args = kestrel.event_get_str(event, 5)
  local uid = kestrel.event_get_i64(event, 10)
  
  local pid = tostring(process_pid or 0)
  local proc_state = process_lateral_ops[pid] or {
    lateral_ops = 0,
    detection_reasons = {},
    remote_connections = {},
    failed_auths = 0
  }
  
  -- Build detection reasons list
  local reasons = {}
  for reason, _ in pairs(proc_state.detection_reasons) do
    table.insert(reasons, reason)
  end
  
  -- Get last connection info
  local last_conn = proc_state.remote_connections[#proc_state.remote_connections] or {}
  
  return {
    pid = process_pid or 0,
    process_name = process_name or "unknown",
    executable = executable or "unknown",
    command_line = args or "",
    uid = uid or -1,
    lateral_operations = proc_state.lateral_ops,
    detection_reasons = table.concat(reasons, ", "),
    last_remote_ip = last_conn.ip or "",
    last_remote_port = last_conn.port or 0,
    failed_auth_attempts = proc_state.failed_auths or 0,
    mitre_technique = "T1021/T1550"
  }
end
