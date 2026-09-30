import unittest
from src.incident_response.ingestion import alert_from_dict
from src.incident_response.enrichment import OfflineEnricher, RestEnrichmentAdapter, extract_event_context, extract_indicators
from src.incident_response.policy import decide

POLICY = {"severity_threshold":"medium","confidence_threshold":0.7,"action_mappings":{"medium":"notify","high":"containment_review"},"dry_run":True,"analyst_approval_required":["containment_review"]}
def alert(**changes):
    value={"id":"x","title":"x","severity":"high","confidence":0.7,"source":"test","timestamp":"2026-01-01T00:00:00Z","indicators":["203.0.113.77"],"username":"alice","rule_id":"R-1","event_type":"login","host":"host.example","synthetic":True}; value.update(changes); return alert_from_dict(value)

class EnrichmentPolicyTests(unittest.TestCase):
    def test_extraction_and_context(self):
        a=alert(); kinds={i.kind for i in extract_indicators(a)}; self.assertTrue({"ip","hostname"}.issubset(kinds)); self.assertEqual(extract_event_context(a)["rule_id"],"R-1")
    def test_offline_sources_and_unknown(self):
        e=OfflineEnricher({"203.0.113.77":{"criticality":"high"}}, {"ips":["192.0.2.1"]}, {"203.0.113.77":{"classification":"synthetic"}})
        self.assertEqual(e.lookup(extract_indicators(alert())[0]).status,"synthetic")
        self.assertEqual(e.lookup(extract_indicators(alert(indicators=["198.51.100.5"]))[0]).status,"unknown")
        self.assertEqual(RestEnrichmentAdapter("http://invalid", enabled=False).lookup(extract_indicators(alert())[0]).status,"unknown")
    def test_allowlist_threshold_and_explanations(self):
        indicator=extract_indicators(alert())[0]; allowed=OfflineEnricher(allowlists={"ips":[indicator.value]}).lookup(indicator)
        self.assertEqual(decide(alert(),POLICY,[allowed]).status,"monitor")
        self.assertEqual(decide(alert(confidence=0.69),POLICY).status,"monitor")
        decision=decide(alert(),POLICY,duplicate=True); self.assertEqual(decision.status,"monitor"); self.assertIn("duplicate",decision.reason); self.assertIn("confidence",decision.evidence)
    def test_approval_required(self): self.assertEqual(decide(alert(),POLICY).status,"approval_required")

if __name__ == "__main__": unittest.main()
