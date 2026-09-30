import json
from pathlib import Path
from typing import Any, Protocol
from .models import Alert

class IngestionError(ValueError): pass

class AlertAdapter(Protocol):
    def load(self) -> list[Alert]: ...

def _required(obj: dict[str, Any], key: str) -> Any:
    if key not in obj or obj[key] in (None, ""): raise IngestionError(f"missing required field: {key}")
    return obj[key]

def validate_alert(obj: Any) -> None:
    if not isinstance(obj, dict): raise IngestionError("alert must be an object")
    for key in ("id", "title", "severity", "confidence", "source", "timestamp"): _required(obj, key)
    if obj["severity"] not in {"low", "medium", "high", "critical"}: raise IngestionError("invalid severity")
    if not isinstance(obj["confidence"], (int, float)) or not 0 <= obj["confidence"] <= 1: raise IngestionError("confidence must be between 0 and 1")

def alert_from_dict(obj: dict[str, Any]) -> Alert:
    validate_alert(obj)
    return Alert(str(obj["id"]), str(obj["title"]), obj["severity"], float(obj["confidence"]), str(obj["source"]), str(obj["timestamp"]), tuple(map(str, obj.get("indicators", []))), obj, bool(obj.get("synthetic", False)))

class JsonFileAdapter:
    def __init__(self, path: str | Path): self.path = Path(path)
    def load(self) -> list[Alert]:
        try: data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc: raise IngestionError(f"unable to load alerts: {exc}") from exc
        if not isinstance(data, list): raise IngestionError("alert file must contain a JSON array")
        return [alert_from_dict(item) for item in data]
