import json
from dataclasses import asdict
from pathlib import Path
from .models import IncidentRecord

def write_report(records: list[IncidentRecord], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")
