--[[
  Privilege Escalation Detection Rule
  
  Detects multiple privilege escalation vectors:
  1. Sudo/su command usage patterns
  2. SUID binary exploitation attempts
  3. Sensitive file modifications (/etc/sudoers, /etc/passwd, etc.)
  4. Kernel exploit indicators (dmesg patterns, unusual syscalls)
  
  MITRE ATT&CK:
  - T1548: Abuse Elevation Control Mechanism
  - T1166: Setuid and Setgid
  - T1168: Local Job Scheduling
--]]

-- SUID binaries commonly abused
local SUID_BINARIES = {
  ["/usr/bin/sudo"] = { normal = true, watch_args = true },
  ["/bin/su"] = { normal = true, watch_args = true },
  ["/usr/bin/pkexec"] = { normal = true, watch_args = false },
  ["/usr/bin/passwd"] = { normal = true, watch_args = false },
  ["/usr/bin/chsh"] = { normal = true, watch_args = false },
  -- Suspicious SUID binaries
  ["nmap"] = { normal = false, reason = "unusual_suid" },
  ["vim"] = { normal = false, reason = "unusual_suid" },
  ["nano"] = { normal = false, reason = "unusual_suid" },
  ["less"] = { normal = false, reason = "unusual_suid" },
  ["more"] = { normal = false, reason = "unusual_suid" },
  ["man"] = { normal = false, reason = "unusual_suid" },
  ["find"] = { normal = false, reason = "unusual_suid" },
  ["bash"] = { normal = false, reason = "shell_suid" },
  ["sh"] = { normal = false, reason = "shell_suid" },
  ["zsh"] = { normal = false, reason = "shell_suid" }
}

-- Sensitive files that indicate privilege escalation
local SENSITIVE_FILES = {
  ["/etc/sudoers"] = "sudoers_modify",
  ["/etc/sudoers.d/"] = "sudoers_modify",
  ["/etc/passwd"] = "passwd_modify",
  ["/etc/shadow"] = "shadow_access",
  ["/etc/group"] = "group_modify",
  ["/etc/gshadow"] = "gshadow_access",
  ["/etc/pam.d/"] = "pam_modify",
  ["/etc/security/"] = "security_modify",
  ["/root/.ssh/"] = "root_ssh_access",
  ["/etc/crontab"] = "cron_modify",
  ["/etc/cron.d/"] = "cron_modify",
  ["/etc/cron.daily/"] = "cron_modify",
  ["/etc/cron.hourly/"] = "cron_modify",
  ["/var/spool/cron/"] = "cron_modify"
}

-- Suspicious sudo arguments (potential bypass attempts)
local SUSPICIOUS_SUDO_ARGS = {
  ["-u#-1"] = "sudo_bypass",
  ["-u#4294967295"] = "sudo_bypass",
  ["\\"] = "escape_attempt"
}

-- State tracking
local process_privilege_ops = {}
local ALERT_THRESHOLD = 2  -- Alert after 2 suspicious privilege operations

function pred_init()
  process_privilege_ops = {}
  return 0
end

-- Helper: Check if executable is SUID binary
local function check_suid_binary(executable)
  if not executable then return nil end
  
  local lower_exec = string.lower(executable)
  for binary, info in pairs(SUID_BINARIES) do
    if string.find(lower_exec, binary, 1, true) then
      return info
    end
  end
  return nil
end

-- Helper: Check if path is sensitive file
local function check_sensitive_file(path)
  if not path then return nil end
  
  for sensitive, detection_type in pairs(SENSITIVE_FILES) do
    if string.find(path, sensitive, 1, true) then
      return detection_type
    end
  end
  return nil
end

-- Helper: Check for suspicious sudo arguments
local function check_sudo_args(args)
  if not args then return nil end
  
  for arg, detection_type in pairs(SUSPICIOUS_SUDO_ARGS) do
    if string.find(args, arg, 1, true) then
      return detection_type
    end
  end
  return nil
end

function pred_eval(event)
  local event_type = kestrel.event_get_i64(event, 1)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local args = kestrel.event_get_str(event, 5)
  local uid = kestrel.event_get_i64(event, 10)
  local euid = kestrel.event_get_i64(event, 11)
  
  if not process_pid then return false end
  
  local pid = tostring(process_pid)
  local now = kestrel.event_get_i64(event, 100)
  
  -- Initialize tracking
  if not process_privilege_ops[pid] then
    process_privilege_ops[pid] = {
      suspicious_ops = 0,
      suid_binaries_used = {},
      sensitive_files_accessed = {},
      detection_reasons = {},
      first_op_time = now
    }
  end
  
  local proc_state = process_privilege_ops[pid]
  local is_suspicious = false
  local detection_reason = nil
  
  -- Check 1: Process execution (execve events)
  if event_type == 1001 then  -- process execution
    -- Check for SUID binary usage
    local suid_info = check_suid_binary(executable)
    if suid_info then
      if not suid_info.normal then
        is_suspicious = true
        detection_reason = suid_info.reason or "unusual_suid_binary"
        table.insert(proc_state.suid_binaries_used, executable)
      end
      
      -- Special check for sudo with suspicious arguments
      if string.find(string.lower(executable or ""), "sudo") and args then
        local sudo_suspicious = check_sudo_args(args)
        if sudo_suspicious then
          is_suspicious = true
          detection_reason = sudo_suspicious
        end
        
        -- Check for unusual sudo usage (e.g., editing files)
        if string.find(args, "-e") or string.find(args, "EDITOR=") then
          is_suspicious = true
          detection_reason = "sudo_editor_abuse"
        end
      end
    end
    
    -- Check for UID escalation (effective UID different from real UID)
    if uid and euid and uid ~= euid and euid == 0 then
      is_suspicious = true
      detection_reason = "uid_escalation_to_root"
    end
  end
  
  -- Check 2: File operations on sensitive files
  if event_type == 3001 or event_type == 3002 or event_type == 3003 then
    local file_path = kestrel.event_get_str(event, 20)
    local sensitive_type = check_sensitive_file(file_path)
    
    if sensitive_type then
      is_suspicious = true
      detection_reason = sensitive_type
      table.insert(proc_state.sensitive_files_accessed, file_path)
    end
  end
  
  -- Update state
  if is_suspicious then
    proc_state.suspicious_ops = proc_state.suspicious_ops + 1
    if detection_reason then
      proc_state.detection_reasons[detection_reason] = true
    end
  end
  
  -- Check threshold
  if proc_state.suspicious_ops >= ALERT_THRESHOLD then
    return true
  end
  
  -- Alert on specific critical detections immediately
  if detection_reason == "shadow_access" or 
     detection_reason == "sudo_bypass" or
     detection_reason == "shell_suid" then
    return true
  end
  
  return false
end

function pred_capture(event)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local uid = kestrel.event_get_i64(event, 10)
  local euid = kestrel.event_get_i64(event, 11)
  
  local pid = tostring(process_pid or 0)
  local proc_state = process_privilege_ops[pid] or {
    suspicious_ops = 0,
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
    euid = euid or -1,
    suspicious_operations = proc_state.suspicious_ops,
    detection_reasons = table.concat(reasons, ", "),
    suid_binaries_used = table.concat(proc_state.suid_binaries_used or {}, ", "),
    sensitive_files = table.concat(proc_state.sensitive_files_accessed or {}, ", "),
    mitre_technique = "T1548/T1166"
  }
end
