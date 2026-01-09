;; Example Wasm Rule: Detect High PID Processes
;; This rule matches processes with PID > 1000
;;
;; Build with: wat2wasm rule.wat -o rule.wasm
;; Verify with: wasm-objdump -d rule.wasm

(module
  ;; Import Host API v1 functions
  (import "kestrel" "event_get_i64"
    (func $event_get_i64 (param i32 i32) (result i64)))

  ;; pred_init: Initialize the predicate
  ;; Called once when the rule is loaded
  (func (export "pred_init") (result i32)
    (i32.const 0)  ; Return 0 = success
  )

  ;; pred_eval: Evaluate an event
  ;; Called for each event
  ;;
  ;; Parameters:
  ;;   $event_handle: i32 - Handle to the event
  ;;
  ;; Returns:
  ;;   i32 - 1 if match, 0 if no match, < 0 if error
  (func (export "pred_eval") (param $event_handle i32) (result i32)
    ;; Get process.pid field (assuming field_id = 1)
    (call $event_get_i64
      (local.get $event_handle)
      (i32.const 1))  ; field_id for process.pid

    ;; Convert i64 result to i32 for comparison
    (i32.wrap_i64)

    ;; Check if pid > 1000 (user process threshold)
    (i32.const 1000)
    (i32.gt_u)

    ;; Return 1 if pid > 1000 (match), 0 otherwise
    (if (result i32)
      (then (i32.const 1))  ; Match
      (else (i32.const 0))  ; No match
    )
  )

  ;; Optional: pred_capture function for alert generation
  ;; Not implemented in this simple example
)
