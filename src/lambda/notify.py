"""Terminal notifications for rejected and failed investigations."""
import json

from common import append_history, now_iso, publish, update_case


def rejected_handler(state, _context):
    append_history(state, "approval_rejected", decision=state.get("approval"))
    update_case(state["case_id"], "REJECTED", decided_at=now_iso(), approval=state.get("approval", {}))
    publish(
        "NOTIFY_TOPIC_ARN",
        f"[Forensics] Request rejected: {state['case_id']}",
        f"The investigation of {state['instance_id']} was rejected. No evidence was collected.",
    )
    return state


def failure_handler(state, _context):
    error = state.get("error", {})
    cause = error.get("Cause", "")
    try:
        cause = json.loads(cause).get("errorMessage", cause)
    except (ValueError, AttributeError):
        pass
    case_id = state.get("case_id") or state.get("input", {}).get("case_id") or "UNKNOWN"
    if case_id != "UNKNOWN":
        update_case(case_id, "FAILED", error=error.get("Error", "Unknown"), cause=str(cause)[:1000])
    publish(
        "NOTIFY_TOPIC_ARN",
        f"[Forensics] Investigation failed: {case_id}",
        (
            f"Case: {case_id}\nInstance: {state.get('instance_id') or state.get('input', {}).get('instance_id')}\n"
            f"Error: {error.get('Error')}\nCause: {str(cause)[:2000]}\n\n"
            f"Cleanup: {state.get('cleanup', 'not run')}\n"
            "Evidence snapshots that were already completed are retained."
        ),
    )
    return state
