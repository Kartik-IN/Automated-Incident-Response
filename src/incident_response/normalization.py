import hashlib, json
from .models import Alert

def normalize(alert: Alert) -> Alert:
    return Alert(alert.alert_id.strip(), " ".join(alert.title.split()), alert.severity.lower(), alert.confidence, alert.source.strip().lower(), alert.timestamp.strip(), tuple(sorted(set(i.strip().lower() for i in alert.indicators if i.strip()))), alert.raw, alert.synthetic)

def fingerprint(alert: Alert) -> str:
    payload = {"title": alert.title.lower().strip(), "source": alert.source.lower().strip(), "severity": alert.severity, "indicators": sorted(alert.indicators)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

def deduplicate(alerts: list[Alert]) -> list[Alert]:
    seen: set[str] = set(); result = []
    for alert in alerts:
        key = fingerprint(alert)
        if key not in seen: seen.add(key); result.append(alert)
    return result
