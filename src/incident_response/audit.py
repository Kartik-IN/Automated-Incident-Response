import json
from datetime import datetime, timezone
from pathlib import Path
class AppendOnlyAuditLog:
    def __init__(self, path): self.path=Path(path)
    def append(self,event,details):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a",encoding="utf-8") as handle: handle.write(json.dumps({"timestamp":datetime.now(timezone.utc).isoformat(),"event":event,"details":details},sort_keys=True)+"\n")
    def read(self): return [] if not self.path.exists() else [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
def write_event(path,event,details): AppendOnlyAuditLog(path).append(event,details)
