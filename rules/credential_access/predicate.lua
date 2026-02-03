--[[
  Credential Access Detection Rule
  
  Detects credential theft through:
  1. Direct access to credential files (/etc/shadow, etc.)
  2. Memory dump attempts (proc filesystem access patterns)
  3. Keylogging indicators (input device access)
  4. Browser credential database access
  5. SSH key harvesting
  
  MITRE ATT&CK:
  - T1003: OS Credential Dumping
  - T1005: Data from Local System
  - T1056: Input Capture
--]]

-- Credential files and paths
local CREDENTIAL_FILES = {
  -- System credential stores
  ["/etc/shadow"] = "system_shadow",
  ["/etc/passwd"] = "system_passwd",
  ["/etc/master.passwd"] = "bsd_master_passwd",
  ["/etc/security/passwd"] = "aix_security_passwd",
  ["/etc/tcb/"] = "tcb_files",
  
  -- SSH keys
  [".ssh/id_rsa"] = "ssh_private_key",
  [".ssh/id_dsa"] = "ssh_private_key",
  [".ssh/id_ecdsa"] = "ssh_private_key",
  [".ssh/id_ed25519"] = "ssh_private_key",
  [".ssh/authorized_keys"] = "ssh_authorized_keys",
  [".ssh/known_hosts"] = "ssh_known_hosts",
  ["/etc/ssh/sshd_config"] = "ssh_config",
  ["/root/.ssh/"] = "root_ssh_keys",
  
  -- Browser credential databases
  ["Login Data"] = "chrome_login_data",
  ["Cookies"] = "chrome_cookies",
  ["Web Data"] = "chrome_web_data",
  ["places.sqlite"] = "firefox_places",
  ["logins.json"] = "firefox_logins",
  ["key3.db"] = "firefox_key_db",
  ["key4.db"] = "firefox_key_db",
  [".mozilla/firefox/"] = "firefox_profile",
  [".config/google-chrome/"] = "chrome_profile",
  [".config/chromium/"] = "chromium_profile",
  
  -- Application credentials
  [".netrc"] = "netrc_credentials",
  [".my.cnf"] = "mysql_config",
  ["pgpass"] = "postgres_pass",
  [".docker/config.json"] = "docker_config",
  [".aws/credentials"] = "aws_credentials",
  [".azure/"] = "azure_credentials",
  [".kube/config"] = "kubernetes_config",
  
  -- Kerberos
  ["/etc/krb5.keytab"] = "kerberos_keytab",
  ["/tmp/krb5cc_"] = "kerberos_ticket_cache",
  ["/var/lib/sss/db/"] = "sss_cache"
}

-- Memory/proc paths indicating credential dumping
local MEMORY_DUMP_PATHS = {
  ["/proc/"] = "proc_access",
  ["/proc/kcore"] = "kernel_memory_dump",
  ["/proc/kmem"] = "kernel_memory_access",
  ["/proc/mem"] = "memory_access",
  ["/dev/mem"] = "dev_memory_access",
  ["/dev/kmem"] = "dev_kernel_memory_access",
  ["/dev/port"] = "dev_port_access"
}

-- Tools commonly used for credential extraction
local CREDENTIAL_TOOLS = {
  -- Memory dumpers
  ["mimipenguin"] = "memory_credential_dump",
  ["linpeas"] = "privilege_escalation_script",
  ["linux-exploit-suggester"] = "exploit_suggester",
  ["pspy"] = "process_monitor",
  
  -- Hash dumpers
  ["unshadow"] = "password_hash_combiner",
  ["john"] = "password_cracker",
  ["johntheripper"] = "password_cracker",
  ["hashcat"] = "password_cracker",
  
  -- Keyloggers
  ["logkeys"] = "keylogger",
  ["keylogger"] = "keylogger",
  ["lkl"] = "linux_keylogger",
  
  -- Sniffers
  ["tcpdump"] = "packet_sniffer",
  ["wireshark"] = "packet_sniffer",
  ["tshark"] = "packet_sniffer",
  ["dumpcap"] = "packet_capture",
  
  -- Browser password extractors
  ["hackbrowserdata"] = "browser_data_theft",
  ["mimikittenz"] = "browser_credential_theft",
  ["browser-dump"] = "browser_data_dump"
}

-- Input devices (keylogger indicators)
local INPUT_DEVICES = {
  ["/dev/input/event"] = "input_event_device",
  ["/dev/input/mice"] = "mouse_input",
  ["/dev/input/mouse"] = "mouse_input",
  ["/dev/input/kbd"] = "keyboard_input"
}

-- State tracking
local process_credential_ops = {}
local ALERT_THRESHOLD = 2

function pred_init()
  process_credential_ops = {}
  return 0
end

-- Helper: Check if path is credential file
local function check_credential_file(path)
  if not path then return nil end
  
  for cred_path, cred_type in pairs(CREDENTIAL_FILES) do
    if string.find(path, cred_path, 1, true) then
      return cred_type
    end
  end
  return nil
end

-- Helper: Check if path is memory/proc dump
local function check_memory_path(path)
  if not path then return nil end
  
  for mem_path, mem_type in pairs(MEMORY_DUMP_PATHS) do
    if string.find(path, mem_path, 1, true) then
      return mem_type
    end
  end
  return nil
end

-- Helper: Check if executable is credential tool
local function check_credential_tool(executable)
  if not executable then return nil end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  if name then
    return CREDENTIAL_TOOLS[name]
  end
  return nil
end

-- Helper: Check if path is input device
local function check_input_device(path)
  if not path then return nil end
  
  for dev_path, dev_type in pairs(INPUT_DEVICES) do
    if string.find(path, dev_path, 1, true) then
      return dev_type
    end
  end
  return nil
end

function pred_eval(event)
  local event_type = kestrel.event_get_i64(event, 1)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  
  if not process_pid then return false end
  
  local pid = tostring(process_pid)
  local now = kestrel.event_get_i64(event, 100)
  
  -- Initialize tracking
  if not process_credential_ops[pid] then
    process_credential_ops[pid] = {
      credential_ops = 0,
      files_accessed = {},
      detection_reasons = {},
      first_op_time = now
    }
  end
  
  local proc_state = process_credential_ops[pid]
  local is_suspicious = false
  local detection_reason = nil
  
  -- Check 1: Process execution of known credential tools
  if event_type == 1001 then
    local tool_type = check_credential_tool(executable)
    if tool_type then
      is_suspicious = true
      detection_reason = tool_type
    end
  end
  
  -- Check 2: File operations on credential files
  if event_type == 3001 or event_type == 3002 or event_type == 3003 or event_type == 3004 then
    local file_path = kestrel.event_get_str(event, 20)
    
    -- Check credential files
    local cred_type = check_credential_file(file_path)
    if cred_type then
      is_suspicious = true
      detection_reason = cred_type
      table.insert(proc_state.files_accessed, file_path)
    end
    
    -- Check memory/proc access (potential dump)
    local mem_type = check_memory_path(file_path)
    if mem_type then
      is_suspicious = true
      detection_reason = mem_type
      table.insert(proc_state.files_accessed, file_path)
      
      -- Check for suspicious proc access patterns (accessing other process memory)
      if string.find(file_path, "/proc/%d+/") and not string.find(file_path, "/proc/self/") then
        if string.find(file_path, "/maps") or string.find(file_path, "/mem") then
          is_suspicious = true
          detection_reason = "process_memory_dump"
        end
      end
    end
    
    -- Check input device access (keylogger)
    local input_type = check_input_device(file_path)
    if input_type then
      is_suspicious = true
      detection_reason = input_type
    end
  end
  
  -- Update state
  if is_suspicious then
    proc_state.credential_ops = proc_state.credential_ops + 1
    if detection_reason then
      proc_state.detection_reasons[detection_reason] = true
    end
  end
  
  -- Check threshold
  if proc_state.credential_ops >= ALERT_THRESHOLD then
    return true
  end
  
  -- Immediate alert on critical detections
  if detection_reason == "system_shadow" or
     detection_reason == "memory_credential_dump" or
     detection_reason == "keylogger" or
     detection_reason == "process_memory_dump" then
    return true
  end
  
  return false
end

function pred_capture(event)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local uid = kestrel.event_get_i64(event, 10)
  
  local pid = tostring(process_pid or 0)
  local proc_state = process_credential_ops[pid] or {
    credential_ops = 0,
    files_accessed = {},
    detection_reasons = {}
  }
  
  -- Build detection reasons list
  local reasons = {}
  for reason, _ in pairs(proc_state.detection_reasons) do
    table.insert(reasons, reason)
  end
  
  return {
    pid = process_pid or 0,
    process_name = process_name or "unknown",
    executable = executable or "unknown",
    uid = uid or -1,
    credential_operations = proc_state.credential_ops,
    detection_reasons = table.concat(reasons, ", "),
    files_accessed = table.concat(proc_state.files_accessed, ", "),
    mitre_technique = "T1003/T1056"
  }
end
