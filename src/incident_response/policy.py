import json
from pathlib import Path
from typing import Any
from .models import Alert, EnrichmentResult, ResponseDecision
class PolicyError(ValueError): pass
def load_policy(path: str | Path) -> dict:
    try: policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise PolicyError(str(exc)) from exc
    for key in ("severity_threshold", "confidence_threshold", "action_mappings", "dry_run", "analyst_approval_required"):
        if key not in policy: raise PolicyError(f"missing policy field: {key}")
    if not isinstance(policy["dry_run"], bool): raise PolicyError("dry_run must be boolean")
    return policy
def decide(alert: Alert, policy: dict, enrichments: list[EnrichmentResult] | None = None, duplicate=False) -> ResponseDecision:
    enrichments = enrichments or []; order = {"low": 0, "medium": 1, "high": 2, "critical": 3}; allowlisted = any(e.attributes.get("allowlisted", False) for e in enrichments)
    evidence: dict[str, Any] = {"severity": alert.severity, "confidence": alert.confidence, "duplicate": duplicate, "indicator_statuses": [e.status for e in enrichments], "allowlisted": allowlisted}
    met_severity = order[alert.severity] >= order[policy["severity_threshold"]]; met_confidence = alert.confidence >= policy["confidence_threshold"]
    evidence.update({"severity_threshold_met": met_severity, "confidence_threshold_met": met_confidence})
    if allowlisted: return ResponseDecision("log_only", True, policy.get("dry_run", True), "indicator is explicitly allowlisted", "monitor", evidence)
    if duplicate: return ResponseDecision("log_only", True, policy.get("dry_run", True), "duplicate alert is monitored without escalation", "monitor", evidence)
    if not met_severity or not met_confidence: return ResponseDecision("log_only", True, policy.get("dry_run", True), "severity or confidence is below configured threshold", "monitor", evidence)
    action = policy["action_mappings"].get(alert.severity, "log_only")
    if action in policy.get("analyst_approval_required", []): return ResponseDecision(action, False, policy.get("dry_run", True), "thresholds met; analyst approval is required before simulation", "approval_required", evidence)
    return ResponseDecision(action, True, policy.get("dry_run", True), "configured severity and confidence thresholds are met", "eligible_for_simulation", evidence)
