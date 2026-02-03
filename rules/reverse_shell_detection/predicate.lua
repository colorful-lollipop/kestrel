--[[
  Reverse Shell Detection Rule
  
  Detects reverse shells through:
  1. Sequence: Network connection (outbound) -> Shell execution
  2. Suspicious command patterns (bash -i, nc -e, etc.)
  3. Unusual parent-child relationships (network process spawning shell)
  4. File descriptor redirection patterns (/dev/tcp/)
  
  MITRE ATT&CK:
  - T1059: Command and Scripting Interpreter
  - T1071: Application Layer Protocol
  - T1505: Server Software Component
--]]

-- Suspicious shell arguments indicating reverse shell
local REVSHELL_PATTERNS = {
  -- bash/sh reverse shells
  { pattern = "bash%s+%-i", description = "bash_interactive" },
  { pattern = "sh%s+%-i", description = "sh_interactive" },
  { pattern = "/dev/tcp/", description = "bash_dev_tcp" },
  { pattern = "/dev/udp/", description = "bash_dev_udp" },
  
  -- netcat reverse shells
  { pattern = "nc%s+%-e%s+", description = "nc_execute" },
  { pattern = "ncat%s+%-e%s+", description = "ncat_execute" },
  { pattern = "nc%s+%-c%s+", description = "nc_command" },
  { pattern = "netcat.*exec", description = "netcat_exec" },
  
  -- Python reverse shells
  { pattern = "python.*socket.*connect", description = "python_socket" },
  { pattern = "python3.*socket.*connect", description = "python3_socket" },
  { pattern = "python.*subprocess.*call", description = "python_subprocess" },
  { pattern = "import%s+socket.*connect", description = "python_import_socket" },
  { pattern = "pty%.spawn", description = "python_pty" },
  
  -- Perl reverse shells
  { pattern = "perl%s+-e.*socket", description = "perl_socket" },
  { pattern = "perl%s+-MIO::Socket", description = "perl_io_socket" },
  
  -- Ruby reverse shells
  { pattern = "ruby%s+-rsocket", description = "ruby_socket" },
  { pattern = "ruby.*TCPSocket", description = "ruby_tcp_socket" },
  
  -- PHP reverse shells
  { pattern = "php%s+-r.*sockopen", description = "php_sockopen" },
  { pattern = "php.*fsockopen", description = "php_fsockopen" },
  
  -- PowerShell (for Windows compatibility notes)
  { pattern = "powershell.*New%-Object.*Net%.Sockets", description = "powershell_socket" },
  
  -- mkfifo/fifo based
  { pattern = "mkfifo.*tmp", description = "mkfifo_reverse" },
  { pattern = "mkfifo.*backpipe", description = "mkfifo_backpipe" }
}

-- Programs that commonly spawn shells (parent processes to watch)
local NETWORK_PROGRAMS = {
  ["nc"] = true,
  ["ncat"] = true,
  ["netcat"] = true,
  ["curl"] = true,
  ["wget"] = true,
  ["python"] = true,
  ["python2"] = true,
  ["python3"] = true,
  ["perl"] = true,
  ["ruby"] = true,
  ["php"] = true,
  ["openssl"] = true
}

-- Shell programs
local SHELLS = {
  ["bash"] = true,
  ["sh"] = true,
  ["dash"] = true,
  ["zsh"] = true,
  ["csh"] = true,
  ["tcsh"] = true,
  ["ksh"] = true
}

-- State tracking for process relationships
local process_state = {}
local network_connections = {}
local TIME_WINDOW_NS = 10 * 1000000000  -- 10 seconds

function pred_init()
  process_state = {}
  network_connections = {}
  return 0
end

-- Helper: Check for reverse shell patterns in command
local function check_revshell_patterns(executable, args)
  if not executable and not args then return nil end
  
  local cmd = (executable or "") .. " " .. (args or "")
  
  for _, pattern_info in ipairs(REVSHELL_PATTERNS) do
    if string.find(cmd, pattern_info.pattern) then
      return pattern_info.description
    end
  end
  
  return nil
end

-- Helper: Check if program is network program
local function is_network_program(executable)
  if not executable then return false end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  return name and NETWORK_PROGRAMS[name] or false
end

-- Helper: Check if program is shell
local function is_shell(executable)
  if not executable then return false end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  return name and SHELLS[name] or false
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
  local parent_pid = ppid and tostring(ppid) or nil
  
  -- Initialize tracking for this process
  if not process_state[pid] then
    process_state[pid] = {
      pid = process_pid,
      ppid = ppid,
      executable = executable,
      args = args,
      network_connect = false,
      shell_spawn = false,
      suspicious_pattern = nil,
      detection_time = nil
    }
  end
  
  local proc = process_state[pid]
  
  -- Check 1: Process execution with reverse shell patterns
  if event_type == 1001 then
    -- Direct reverse shell pattern detection
    local pattern_match = check_revshell_patterns(executable, args)
    if pattern_match then
      proc.suspicious_pattern = pattern_match
      proc.detection_time = now
      return true
    end
    
    -- Check if shell spawned by network program (parent relationship)
    if is_shell(executable) and parent_pid and process_state[parent_pid] then
      local parent = process_state[parent_pid]
      
      -- Check if parent made network connection
      if parent.network_connect then
        -- Shell spawned by network program = potential reverse shell
        local time_diff = now - (parent.connection_time or now)
        if time_diff <= TIME_WINDOW_NS then
          proc.shell_spawn = true
          proc.suspicious_pattern = "shell_from_network_parent"
          return true
        end
      end
    end
    
    -- Mark network programs
    if is_network_program(executable) then
      proc.is_network_program = true
    end
  end
  
  -- Check 2: Network connection events
  if event_type == 4001 or event_type == 4002 then  -- connect/send
    local dest_ip = kestrel.event_get_str(event, 50)
    local dest_port = kestrel.event_get_i64(event, 51)
    
    proc.network_connect = true
    proc.connection_time = now
    proc.dest_ip = dest_ip
    proc.dest_port = dest_port
    
    -- If this network program later spawns a shell, it's suspicious
    network_connections[pid] = {
      time = now,
      pid = process_pid,
      dest_ip = dest_ip,
      dest_port = dest_port
    }
    
    -- Cleanup old connections
    local cutoff = now - TIME_WINDOW_NS
    for stored_pid, conn in pairs(network_connections) do
      if conn.time < cutoff then
        network_connections[stored_pid] = nil
      end
    end
  end
  
  -- Check 3: File operations that indicate reverse shell (e.g., /dev/tcp writes)
  if event_type == 3003 then  -- file write
    local file_path = kestrel.event_get_str(event, 20)
    if file_path and string.find(file_path, "/dev/tcp/") then
      proc.suspicious_pattern = "dev_tcp_write"
      return true
    end
  end
  
  return false
end

function pred_capture(event)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)
  local executable = kestrel.event_get_str(event, 4)
  local args = kestrel.event_get_str(event, 5)
  local ppid = kestrel.event_get_i64(event, 6)
  local uid = kestrel.event_get_i64(event, 10)
  
  local pid = tostring(process_pid or 0)
  local proc = process_state[pid] or {}
  
  -- Get parent info
  local parent_info = ""
  if ppid then
    local parent = process_state[tostring(ppid)]
    if parent then
      parent_info = string.format("%s(%d)", parent.executable or "unknown", ppid)
    end
  end
  
  return {
    pid = process_pid or 0,
    process_name = process_name or "unknown",
    executable = executable or "unknown",
    command_line = args or "",
    parent_process = parent_info,
    uid = uid or -1,
    detection_pattern = proc.suspicious_pattern or "unknown",
    network_connected = proc.network_connect or false,
    dest_ip = proc.dest_ip or "",
    dest_port = proc.dest_port or 0,
    mitre_technique = "T1059/T1071"
  }
end
