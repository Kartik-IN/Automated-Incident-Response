import json
import tempfile
import unittest
from pathlib import Path
from src.incident_response.ingestion import IngestionError, alert_from_dict
from src.incident_response.models import Alert
from src.incident_response.normalization import deduplicate, fingerprint, normalize
from src.incident_response.policy import decide, load_policy, PolicyError
from src.incident_response.response import execute

def sample(**changes):
    value = {"id":"a1","title":"  Test  alert ","severity":"high","confidence":0.9,"source":" SENSOR ","timestamp":"now","indicators":["192.0.2.1"]}; value.update(changes); return value

class FoundationTests(unittest.TestCase):
    def test_valid_and_invalid_input(self):
        self.assertEqual(alert_from_dict(sample()).alert_id, "a1")
        with self.assertRaises(IngestionError): alert_from_dict(sample(confidence=2))
        with self.assertRaises(IngestionError): alert_from_dict({})

    def test_normalization_and_duplicate_detection(self):
        a = normalize(alert_from_dict(sample())); b = normalize(alert_from_dict(sample(id="different")))
        self.assertEqual(a.title, "Test alert"); self.assertEqual(fingerprint(a), fingerprint(b)); self.assertEqual(len(deduplicate([a, b])), 1)

    def test_policy_parsing_and_safe_defaults(self):
        policy = load_policy("config/response_policy.json"); decision = decide(alert_from_dict(sample()), policy)
        self.assertTrue(decision.dry_run); self.assertFalse(decision.approved); self.assertEqual(execute(decision).status, "simulated")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"dry_run": True}, f); path = f.name
        with self.assertRaises(PolicyError): load_policy(path)

if __name__ == "__main__": unittest.main()
