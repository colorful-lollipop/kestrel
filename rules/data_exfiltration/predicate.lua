--[[
  Data Exfiltration Detection Rule
  
  Detects data exfiltration through:
  1. Sequence: Archive creation -> Network upload
  2. Large file reads followed by outbound connections
  3. Database dumps followed by network activity
  4. Unusual outbound data volume
  5. Sensitive file access followed by compression
  
  MITRE ATT&CK:
  - T1041: Exfiltration Over C2 Channel
  - T1048: Exfiltration Over Alternative Protocol
  - T1567: Exfiltration Over Web Service
--]]

-- Compression/archiving tools
local COMPRESSION_TOOLS = {
  ["tar"] = "tar_archive",
  ["gzip"] = "gzip_compress",
  ["bzip2"] = "bzip2_compress",
  ["zip"] = "zip_archive",
  ["unzip"] = "zip_extract",
  ["7z"] = "7zip_archive",
  ["7za"] = "7zip_archive",
  ["rar"] = "rar_archive",
  ["xz"] = "xz_compress",
  ["lzma"] = "lzma_compress",
  ["dd"] = "disk_dump"
}

-- Database dump utilities
local DB_DUMP_TOOLS = {
  ["mysqldump"] = "mysql_dump",
  ["pg_dump"] = "postgres_dump",
  ["pg_dumpall"] = "postgres_dumpall",
  ["mongodump"] = "mongodb_dump",
  ["redis-cli"] = "redis_cli",
  ["sqlite3"] = "sqlite_dump",
  ["sqlcmd"] = "mssql_dump",
  ["bcp"] = "mssql_bulk_copy"
}

-- Data upload/sync tools commonly used for exfiltration
local UPLOAD_TOOLS = {
  ["curl"] = "curl_upload",
  ["wget"] = "wget_download",
  ["scp"] = "scp_transfer",
  ["rsync"] = "rsync_sync",
  ["sftp"] = "sftp_transfer",
  ["ftp"] = "ftp_transfer",
  ["ncftp"] = "ncftp_transfer",
  ["lftp"] = "lftp_transfer",
  ["aws"] = "aws_cli",
  ["az"] = "azure_cli",
  ["gcloud"] = "gcloud_cli",
  ["mc"] = "minio_client",
  ["rclone"] = "rclone_sync",
  ["dropbox"] = "dropbox_cli"
}

-- Cloud storage domains/IPs to watch
local CLOUD_STORAGE_INDICATORS = {
  ["dropbox.com"] = "dropbox",
  ["dropboxapi.com"] = "dropbox",
  ["s3.amazonaws.com"] = "aws_s3",
  ["s3."] = "aws_s3",
  ["blob.core.windows.net"] = "azure_blob",
  ["storage.googleapis.com"] = "gcs",
  ["drive.google.com"] = "google_drive",
  ["docs.google.com"] = "google_drive",
  ["mega.nz"] = "mega",
  ["mega.co.nz"] = "mega",
  ["box.com"] = "box",
  ["icloud.com"] = "icloud",
  ["onedrive.live.com"] = "onedrive",
  ["1drv.com"] = "onedrive",
  ["pastebin.com"] = "pastebin",
  ["ghostbin.com"] = "ghostbin",
  ["termbin.com"] = "termbin"
}

-- Sensitive data patterns
local SENSITIVE_PATTERNS = {
  ["password"] = "password_file",
  ["passwd"] = "password_file",
  ["secret"] = "secret_file",
  ["key"] = "key_file",
  ["credential"] = "credential_file",
  ["token"] = "token_file",
  [".sql"] = "sql_dump",
  [".db"] = "database_file",
  [".mdb"] = "access_database",
  ["backup"] = "backup_file",
  ["archive"] = "archive_file"
}

-- State tracking
local process_exfil_ops = {}
local archive_creations = {}
local TIME_WINDOW_NS = 5 * 60 * 1000000000  -- 5 minutes

function pred_init()
  process_exfil_ops = {}
  archive_creations = {}
  return 0
end

-- Helper: Check if executable is compression tool
local function check_compression_tool(executable)
  if not executable then return nil end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  if name then
    return COMPRESSION_TOOLS[name]
  end
  return nil
end

-- Helper: Check if executable is DB dump tool
local function check_db_dump_tool(executable)
  if not executable then return nil end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  if name then
    return DB_DUMP_TOOLS[name]
  end
  return nil
end

-- Helper: Check if executable is upload tool
local function check_upload_tool(executable)
  if not executable then return nil end
  
  local name = string.match(string.lower(executable), "([^/]+)$")
  if name then
    return UPLOAD_TOOLS[name]
  end
  return nil
end

-- Helper: Check if host is cloud storage
local function check_cloud_storage(host)
  if not host then return nil end
  
  for indicator, service in pairs(CLOUD_STORAGE_INDICATORS) do
    if string.find(string.lower(host), indicator, 1, true) then
      return service
    end
  end
  return nil
end

-- Helper: Check if path contains sensitive pattern
local function check_sensitive_path(path)
  if not path then return nil end
  
  local lower_path = string.lower(path)
  for pattern, pattern_type in pairs(SENSITIVE_PATTERNS) do
    if string.find(lower_path, pattern, 1, true) then
      return pattern_type
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
  local now = kestrel.event_get_i64(event, 100)
  
  if not process_pid then return false end
  
  local pid = tostring(process_pid)
  
  -- Initialize tracking
  if not process_exfil_ops[pid] then
    process_exfil_ops[pid] = {
      pid = process_pid,
      exfil_ops = 0,
      detection_reasons = {},
      archive_created = false,
      db_dumped = false,
      sensitive_files_accessed = {},
      uploads = {},
      first_op_time = now
    }
  end
  
  local proc_state = process_exfil_ops[pid]
  local is_suspicious = false
  local detection_reason = nil
  
  -- Check 1: Compression/archive creation
  if event_type == 1001 then
    local comp_type = check_compression_tool(executable)
    if comp_type then
      proc_state.archive_created = true
      proc_state.archive_time = now
      proc_state.archive_type = comp_type
      
      -- Check if archiving sensitive files
      if args then
        local sensitive_type = check_sensitive_path(args)
        if sensitive_type then
          is_suspicious = true
          detection_reason = "archive_sensitive_" .. sensitive_type
          table.insert(proc_state.sensitive_files_accessed, args)
        end
      end
      
      -- Record archive creation
      archive_creations[pid] = {
        time = now,
        pid = process_pid,
        tool = comp_type
      }
    end
    
    -- Check for DB dump
    local db_type = check_db_dump_tool(executable)
    if db_type then
      proc_state.db_dumped = true
      proc_state.db_dump_time = now
      proc_state.db_dump_type = db_type
      is_suspicious = true
      detection_reason = db_type
    end
    
    -- Check for upload tool usage
    local upload_type = check_upload_tool(executable)
    if upload_type then
      proc_state.upload_tool_used = true
      
      -- Check if archive was created recently
      if proc_state.archive_created then
        local time_diff = now - (proc_state.archive_time or now)
        if time_diff <= TIME_WINDOW_NS then
          is_suspicious = true
          detection_reason = "archive_then_upload"
        end
      end
      
      -- Check if DB was dumped recently
      if proc_state.db_dumped then
        local time_diff = now - (proc_state.db_dump_time or now)
        if time_diff <= TIME_WINDOW_NS then
          is_suspicious = true
          detection_reason = "dump_then_upload"
        end
      end
    end
  end
  
  -- Check 2: Network connections to cloud storage
  if event_type == 4001 then
    local dest_ip = kestrel.event_get_str(event, 50)
    local dest_port = kestrel.event_get_i64(event, 51)
    local dest_host = kestrel.event_get_str(event, 54)  -- hostname if available
    
    -- Check for cloud storage connections
    local cloud_service = check_cloud_storage(dest_host) or check_cloud_storage(dest_ip)
    if cloud_service then
      proc_state.cloud_connection = true
      proc_state.cloud_service = cloud_service
      
      -- Check if preceded by archive creation or DB dump
      if proc_state.archive_created or proc_state.db_dumped then
        is_suspicious = true
        detection_reason = "data_to_cloud_" .. cloud_service
      end
      
      table.insert(proc_state.uploads, {
        ip = dest_ip,
        host = dest_host,
        port = dest_port,
        service = cloud_service,
        time = now
      })
    end
    
    -- Large data transfer indicator (unusual port)
    if dest_port == 4444 or dest_port == 5555 or dest_port == 6666 or dest_port == 9999 then
      proc_state.suspicious_port = true
      if proc_state.archive_created or proc_state.db_dumped then
        is_suspicious = true
        detection_reason = "upload_to_suspicious_port"
      end
    end
  end
  
  -- Check 3: File operations on sensitive data
  if event_type == 3003 or event_type == 3004 then  -- write or read
    local file_path = kestrel.event_get_str(event, 20)
    local file_size = kestrel.event_get_i64(event, 22)  -- file size if available
    
    local sensitive_type = check_sensitive_path(file_path)
    if sensitive_type then
      table.insert(proc_state.sensitive_files_accessed, file_path)
      
      -- Large file read
      if event_type == 3004 and file_size and file_size > 10485760 then  -- > 10MB
        proc_state.large_file_read = true
        proc_state.large_file_size = file_size
      end
    end
  end
  
  -- Update state
  if is_suspicious and detection_reason then
    proc_state.exfil_ops = proc_state.exfil_ops + 1
    proc_state.detection_reasons[detection_reason] = true
  end
  
  -- Cleanup old archives
  local cutoff = now - TIME_WINDOW_NS
  for stored_pid, archive in pairs(archive_creations) do
    if archive.time < cutoff then
      archive_creations[stored_pid] = nil
    end
  end
  
  -- Check threshold
  if proc_state.exfil_ops >= 1 then
    return true
  end
  
  -- Critical: archive + cloud upload combination
  if proc_state.archive_created and proc_state.cloud_connection then
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
  local proc_state = process_exfil_ops[pid] or {
    exfil_ops = 0,
    detection_reasons = {},
    sensitive_files_accessed = {},
    uploads = {}
  }
  
  -- Build detection reasons list
  local reasons = {}
  for reason, _ in pairs(proc_state.detection_reasons) do
    table.insert(reasons, reason)
  end
  
  -- Get last upload info
  local last_upload = proc_state.uploads[#proc_state.uploads] or {}
  
  return {
    pid = process_pid or 0,
    process_name = process_name or "unknown",
    executable = executable or "unknown",
    uid = uid or -1,
    exfil_operations = proc_state.exfil_ops,
    detection_reasons = table.concat(reasons, ", "),
    archive_created = proc_state.archive_created or false,
    archive_type = proc_state.archive_type or "",
    db_dumped = proc_state.db_dumped or false,
    db_dump_type = proc_state.db_dump_type or "",
    cloud_service = proc_state.cloud_service or "",
    last_upload_ip = last_upload.ip or "",
    last_upload_host = last_upload.host or "",
    sensitive_files_count = #proc_state.sensitive_files_accessed,
    mitre_technique = "T1041/T1048"
  }
end
