--[[
  Ransomware Behavior Detection Rule
  
  Detects ransomware by monitoring:
  1. High-frequency file rename operations (potential encryption)
  2. Target file extensions changing to known ransomware extensions
  3. Large number of files modified in short time window
  
  MITRE ATT&CK: T1486 (Data Encrypted for Impact)
--]]

-- Ransomware-related file extensions
local SUSPICIOUS_EXTENSIONS = {
  [".encrypted"] = true,
  [".locked"] = true,
  [".crypto"] = true,
  [".vault"] = true,
  [".ransom"] = true,
  [".crypt"] = true,
  [".crypted"] = true,
  [".enc"] = true,
  [".locked3"] = true,
  [". Crypto"] = true
}

-- Target file types commonly encrypted by ransomware
local HIGH_VALUE_EXTENSIONS = {
  [".doc"] = true,
  [".docx"] = true,
  [".xls"] = true,
  [".xlsx"] = true,
  [".ppt"] = true,
  [".pptx"] = true,
  [".pdf"] = true,
  [".txt"] = true,
  [".jpg"] = true,
  [".jpeg"] = true,
  [".png"] = true,
  [".mp3"] = true,
  [".mp4"] = true,
  [".zip"] = true,
  [".rar"] = true,
  [".sql"] = true,
  [".db"] = true,
  [".mdb"] = true
}

-- State tracking per process
local process_file_ops = {}
local ALERT_THRESHOLD = 10  -- Alert after 10 suspicious operations
local TIME_WINDOW_MS = 5000  -- Within 5 seconds

function pred_init()
  process_file_ops = {}
  return 0
end

-- Helper: Check if path has suspicious extension
local function has_suspicious_extension(path)
  if not path then return false end
  local lower_path = string.lower(path)
  for ext, _ in pairs(SUSPICIOUS_EXTENSIONS) do
    if string.sub(lower_path, -#ext) == ext then
      return true
    end
  end
  return false
end

-- Helper: Check if path has high-value extension
local function has_high_value_extension(path)
  if not path then return false end
  local lower_path = string.lower(path)
  for ext, _ in pairs(HIGH_VALUE_EXTENSIONS) do
    if string.sub(lower_path, -#ext) == ext then
      return true
    end
  end
  return false
end

-- Helper: Get file extension
local function get_extension(path)
  if not path then return nil end
  local dot_pos = string.match(path, "^.+()%.%w+$")
  if dot_pos then
    return string.sub(path, dot_pos)
  end
  return nil
end

function pred_eval(event)
  -- Get event type and process info
  local event_type = kestrel.event_get_i64(event, 1)  -- event_type_id
  local process_pid = kestrel.event_get_i64(event, 2)  -- process.pid
  
  if not process_pid then
    return false
  end
  
  local pid = tostring(process_pid)
  local now = kestrel.event_get_i64(event, 100)  -- ts_mono_ns
  
  -- Initialize process tracking if needed
  if not process_file_ops[pid] then
    process_file_ops[pid] = {
      operations = {},
      suspicious_count = 0,
      high_value_accessed = 0,
      first_op_time = now
    }
  end
  
  local proc_state = process_file_ops[pid]
  
  -- Check if this is a file operation event
  -- Event types: file_rename (3002), file_write (3003), file_create (3001)
  if event_type == 3001 or event_type == 3002 or event_type == 3003 then
    local file_path = kestrel.event_get_str(event, 20)  -- file.path
    local new_path = kestrel.event_get_str(event, 21)   -- file.new_path (for rename)
    
    local is_suspicious = false
    
    -- Check for rename to suspicious extension
    if event_type == 3002 and new_path then  -- file_rename
      -- Check if renaming from high-value file to suspicious extension
      if has_high_value_extension(file_path) and has_suspicious_extension(new_path) then
        is_suspicious = true
        proc_state.high_value_accessed = proc_state.high_value_accessed + 1
      end
      
      -- Check if new path has ransomware extension
      if has_suspicious_extension(new_path) then
        is_suspicious = true
      end
    end
    
    -- Check for write operations on high-value files
    if event_type == 3003 and file_path then  -- file_write
      if has_high_value_extension(file_path) then
        proc_state.high_value_accessed = proc_state.high_value_accessed + 1
      end
    end
    
    -- Record operation
    table.insert(proc_state.operations, {
      time = now,
      type = event_type,
      path = file_path,
      new_path = new_path,
      suspicious = is_suspicious
    })
    
    -- Count suspicious operations
    if is_suspicious then
      proc_state.suspicious_count = proc_state.suspicious_count + 1
    end
    
    -- Cleanup old operations outside time window
    local cutoff_time = now - (TIME_WINDOW_MS * 1000000)  -- Convert to nanoseconds
    local i = 1
    while i <= #proc_state.operations do
      if proc_state.operations[i].time < cutoff_time then
        if proc_state.operations[i].suspicious then
          proc_state.suspicious_count = proc_state.suspicious_count - 1
        end
        table.remove(proc_state.operations, i)
      else
        i = i + 1
      end
    end
    
    -- Check if threshold exceeded
    if proc_state.suspicious_count >= ALERT_THRESHOLD then
      return true
    end
    
    -- Additional heuristic: many high-value files accessed
    if proc_state.high_value_accessed >= 20 and #proc_state.operations >= 15 then
      return true
    end
  end
  
  return false
end

function pred_capture(event)
  local process_pid = kestrel.event_get_i64(event, 2)
  local process_name = kestrel.event_get_str(event, 3)  -- process.name
  local file_path = kestrel.event_get_str(event, 20)
  
  local pid = tostring(process_pid or 0)
  local proc_state = process_file_ops[pid] or {
    suspicious_count = 0,
    high_value_accessed = 0
  }
  
  return {
    pid = process_pid or 0,
    process_name = process_name or "unknown",
    file_path = file_path or "unknown",
    suspicious_operations = proc_state.suspicious_count,
    high_value_files_accessed = proc_state.high_value_accessed,
    detection_method = "behavioral_heuristics",
    mitre_technique = "T1486"
  }
end
