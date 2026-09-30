"""Optional Wazuh adapter; disabled unless explicitly enabled."""
import json, os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
class WazuhError(RuntimeError): pass
class WazuhAdapter:
    def __init__(self, base_url=None, enabled=False, timeout=5.0, verify_tls=True): self.base_url=(base_url or os.getenv("WAZUH_API_URL", "")).rstrip("/"); self.enabled=enabled; self.timeout=min(max(timeout,.1),30); self.verify_tls=verify_tls
    def fetch_alerts(self):
        if not self.enabled: return []
        if not self.base_url or not self.verify_tls: raise WazuhError("Wazuh adapter requires URL and TLS verification")
        token=os.getenv("WAZUH_API_TOKEN")
        if not token: raise WazuhError("Wazuh credentials are unavailable")
        try:
            with urlopen(Request(f"{self.base_url}/security_alerts", headers={"Authorization":"Bearer "+token}), timeout=self.timeout) as response: payload=json.load(response)
        except HTTPError as exc: raise WazuhError(f"Wazuh API error: HTTP {exc.code}") from exc
        except (URLError,OSError,ValueError) as exc: raise WazuhError(f"Wazuh service unavailable: {exc}") from exc
        return payload if isinstance(payload,list) else []
