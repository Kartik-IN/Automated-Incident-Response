from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]

@dataclass(frozen=True)
class Alert:
    alert_id: str
    title: str
    severity: Severity
    confidence: float
    source: str
    timestamp: str
    indicators: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False

@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str
    source: str = "alert"
    context: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class EnrichmentResult:
    indicator: Indicator
    attributes: dict[str, Any]
    provider: str = "local_metadata"
    status: str = "unknown"

@dataclass(frozen=True)
class ResponseDecision:
    action: str
    approved: bool
    dry_run: bool
    reason: str
    status: str = "monitor"
    evidence: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ActionResult:
    action: str
    status: str
    simulated: bool
    message: str

@dataclass
class IncidentRecord:
    alert: Alert
    fingerprint: str
    enrichments: list[EnrichmentResult] = field(default_factory=list)
    decision: ResponseDecision | None = None
    action_result: ActionResult | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
