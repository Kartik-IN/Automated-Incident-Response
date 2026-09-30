"""Offline-first indicator extraction and enrichment adapters."""
import json, re, time
from typing import Any, Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen
from .models import Alert, EnrichmentResult, Indicator

_PATTERNS = {"ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "hash": re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"), "hostname": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b")}
class EnrichmentError(ValueError): pass
class EnrichmentAdapter(Protocol):
    def lookup(self, indicator: Indicator) -> EnrichmentResult: ...

def extract_indicators(alert: Alert) -> list[Indicator]:
    text = json.dumps(alert.raw, sort_keys=True); found = []
    for kind, pattern in _PATTERNS.items(): found.extend(Indicator(v, kind, "alert", {"field_scope": "raw"}) for v in pattern.findall(text))
    for value in alert.indicators:
        kind = "ip" if _PATTERNS["ip"].fullmatch(value) else "hash" if _PATTERNS["hash"].fullmatch(value) else "hostname" if _PATTERNS["hostname"].fullmatch(value) else "unknown"
        found.append(Indicator(value, kind, "alert", {"field_scope": "explicit"}))
    return list({(i.kind, i.value.lower()): i for i in found}.values())

def extract_event_context(alert: Alert) -> dict[str, Any]:
    return {key: alert.raw[key] for key in ("username", "user", "rule_id", "rule", "event_type", "host", "hostname", "asset_id", "asset_criticality", "timestamp") if key in alert.raw}

class OfflineEnricher:
    def __init__(self, inventory=None, allowlists=None, fixtures=None): self.inventory, self.allowlists, self.fixtures = inventory or {}, allowlists or {}, fixtures or {}
    def lookup(self, indicator):
        if indicator.value in {v for values in self.allowlists.values() for v in values}: return EnrichmentResult(indicator, {"allowlisted": True, "source_type": "locally_configured_context"}, "local_config", "verified")
        if indicator.value in self.fixtures: return EnrichmentResult(indicator, {**self.fixtures[indicator.value], "source_type": "synthetic_fixture"}, "synthetic_fixture", "synthetic")
        if indicator.value in self.inventory: return EnrichmentResult(indicator, {**self.inventory[indicator.value], "source_type": "locally_configured_context"}, "asset_inventory", "configured")
        return EnrichmentResult(indicator, {"source_type": "unknown", "known": False}, "offline", "unknown")

class RestEnrichmentAdapter:
    def __init__(self, base_url, timeout=3.0, min_interval=1.0, enabled=False): self.base_url, self.timeout, self.min_interval, self.enabled, self._last_call = base_url.rstrip("/"), timeout, min_interval, enabled, 0.0
    def lookup(self, indicator):
        if not self.enabled: return EnrichmentResult(indicator, {"source_type": "unknown", "reason": "adapter disabled"}, "rest", "unknown")
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0: time.sleep(wait)
        self._last_call = time.monotonic()
        try:
            with urlopen(Request(f"{self.base_url}/lookup?value={indicator.value}"), timeout=self.timeout) as response: data = json.load(response)
            return EnrichmentResult(indicator, {**data, "source_type": "verified_external"}, "rest", "verified")
        except (OSError, URLError, ValueError) as exc: return EnrichmentResult(indicator, {"source_type": "unknown", "error": str(exc)}, "rest", "unknown")

def enrich(alert: Alert, enabled=True): return [] if not enabled else [OfflineEnricher().lookup(i) for i in extract_indicators(alert)]
