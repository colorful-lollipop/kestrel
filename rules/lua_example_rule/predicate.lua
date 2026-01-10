-- Kestrel Lua Predicate Example
-- This rule demonstrates a simple Lua predicate for Kestrel
--
-- Rule: High PID Detection
-- Description: Detects processes with PID > 1000 (user-space processes)
-- Severity: Low

-- pred_init: Initialize the predicate
-- Called once when the rule is loaded
--
-- Returns:
--   0 for success, < 0 for error
function pred_init()
    -- Initialize any rule-specific state here
    return 0
end

-- pred_eval: Evaluate an event
-- Called for each event
--
-- Parameters:
--   event - Event to evaluate (currently a placeholder)
--
-- Returns:
--   true if match, false otherwise
function pred_eval(event)
    -- For this simple example, we always return true
    -- In a real implementation, you would:
    -- 1. Call kestrel.event_get_i64(event, field_id) to get field values
    -- 2. Compare values to thresholds
    -- 3. Return true if conditions match

    -- Example (when event handling is fully implemented):
    -- local pid = kestrel.event_get_i64(event, 1)  -- Get process.pid field
    -- if pid > 1000 then
    --     kestrel.alert_emit(event)  -- Emit alert
    --     return true
    -- end
    -- return false

    -- For now, just return true to demonstrate matching
    return true
end

-- pred_capture: Capture fields from matching event (optional)
-- Called when event matches to extract fields for alert
--
-- Parameters:
--   event - Event that matched
--
-- Returns:
--   Table with captured fields
function pred_capture(event)
    -- Return a table with fields to include in alert
    return {
        pid = 0,
        process_name = "example"
    }
end
