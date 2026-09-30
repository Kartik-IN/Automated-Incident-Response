import json, tempfile, unittest
from pathlib import Path
from src.incident_response.audit import AppendOnlyAuditLog
from src.incident_response.ingestion import alert_from_dict
from src.incident_response.models import ResponseDecision
from src.incident_response.orchestration import ResponseOrchestrator
from src.incident_response.wazuh import WazuhAdapter, WazuhError
class OrchestrationTests(unittest.TestCase):
    def setUp(self): self.alert=alert_from_dict({"id":"a","title":"test","severity":"high","confidence":.9,"source":"test","timestamp":"now"}); self.decision=ResponseDecision("containment_review",False,True,"approval required","approval_required",{"severity":"high"})
    def test_plan_simulation_idempotency_and_audit(self):
        path=Path("reports/.test-audit.jsonl"); path.unlink(missing_ok=True)
        log=AppendOnlyAuditLog(path); runner=ResponseOrchestrator(log); plan=runner.create_plan(self.alert,self.decision); self.assertEqual(runner.run(plan,self.decision)[0].status,"refused"); results=runner.run(plan,self.decision,approval=True); self.assertTrue(all(r.simulated for r in results)); self.assertEqual(runner.run(plan,self.decision,approval=True)[0].status,"idempotent_skip"); self.assertEqual(len(log.read()),11); path.unlink(missing_ok=True)
    def test_unknown_action_and_dry_run_gate(self):
        log=AppendOnlyAuditLog("reports/.test-unknown-audit.jsonl"); runner=ResponseOrchestrator(log); plan=runner.create_plan(self.alert,ResponseDecision("unknown",True,True,"x")); plan=plan.__class__(plan.plan_id,plan.alert_id,("unknown",),plan.decision_status,True,plan.created_at); self.assertEqual(runner.run(plan,ResponseDecision("unknown",True,False,"x"))[0].status,"refused"); Path(log.path).unlink(missing_ok=True)
    def test_wazuh_disabled_and_auth_failure(self):
        self.assertEqual(WazuhAdapter().fetch_alerts(),[])
        with self.assertRaises(WazuhError): WazuhAdapter("https://placeholder.invalid",enabled=True).fetch_alerts()
        self.assertNotIn("token", json.dumps(WazuhAdapter().__dict__).lower())
if __name__ == "__main__": unittest.main()
