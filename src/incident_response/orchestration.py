"""Auditable, simulation-only response orchestration."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from .audit import AppendOnlyAuditLog
from .models import ActionResult, Alert, ResponseDecision
SAFE_ACTIONS = {"create_case", "enrich_indicator", "mark_for_review", "generate_report", "simulated_block_indicator"}
@dataclass(frozen=True)
class ResponsePlan:
    plan_id: str; alert_id: str; actions: tuple[str, ...]; decision_status: str; dry_run: bool; created_at: str
class ResponseOrchestrator:
    def __init__(self, audit_log: AppendOnlyAuditLog, timeout_seconds: float = 5.0): self.audit_log, self.timeout_seconds, self._completed = audit_log, timeout_seconds, set()
    def create_plan(self, alert: Alert, decision: ResponseDecision) -> ResponsePlan:
        actions = ("create_case", "enrich_indicator", "mark_for_review", "generate_report")
        if decision.action == "containment_review": actions += ("simulated_block_indicator",)
        plan = ResponsePlan(f"{alert.alert_id}:{decision.action}", alert.alert_id, actions, decision.status, True, datetime.now(timezone.utc).isoformat())
        self.audit_log.append("plan_created", {"plan": asdict(plan), "reason": decision.reason, "evidence": decision.evidence}); return plan
    def run(self, plan: ResponsePlan, decision: ResponseDecision, allowlisted=False, approval=False) -> list[ActionResult]:
        if not decision.dry_run: return [ActionResult("orchestration", "refused", True, "plan refused: dry-run must remain enabled")]
        if decision.status == "approval_required" and not approval: return [ActionResult("orchestration", "refused", True, "approval required")]
        if allowlisted: return [ActionResult("orchestration", "refused", True, "allowlisted indicator cannot be acted on")]
        results=[]
        for action in plan.actions:
            key=f"{plan.plan_id}:{action}"
            if key in self._completed: result=ActionResult(action,"idempotent_skip",True,"already simulated")
            elif action not in SAFE_ACTIONS: result=ActionResult(action,"refused",True,f"unknown action denied: {action}")
            else: result=ActionResult(action,"simulated",True,f"SIMULATED ONLY: {action}")
            self._completed.add(key); self.audit_log.append("action_result", {"plan_id":plan.plan_id,"action":action,"status":result.status,"simulated":result.simulated}); results.append(result)
        return results
