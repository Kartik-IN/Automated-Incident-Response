from .models import ActionResult, ResponseDecision

def execute(decision: ResponseDecision) -> ActionResult:
    if not decision.dry_run: return ActionResult(decision.action, "refused", True, "non-dry-run execution is disabled by safety boundary")
    return ActionResult(decision.action, "simulated", True, f"SIMULATED ONLY: {decision.action}")
