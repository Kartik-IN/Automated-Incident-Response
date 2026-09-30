import argparse
from .audit import AppendOnlyAuditLog, write_event
from .enrichment import enrich
from .ingestion import JsonFileAdapter
from .normalization import deduplicate, fingerprint, normalize
from .policy import decide, load_policy
from .reporting import write_report
from .response import execute
from .models import IncidentRecord
from .orchestration import ResponseOrchestrator

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--input", required=True); parser.add_argument("--report", required=True); parser.add_argument("--policy", default="config/response_policy.json"); args = parser.parse_args()
    policy = load_policy(args.policy); alerts = deduplicate([normalize(a) for a in JsonFileAdapter(args.input).load()]); records = []
    orchestrator = ResponseOrchestrator(AppendOnlyAuditLog("reports/audit.jsonl"))
    for alert in alerts:
        enrichments = enrich(alert); decision = decide(alert, policy, enrichments); plan = orchestrator.create_plan(alert, decision); results = orchestrator.run(plan, decision, any(e.attributes.get("allowlisted") for e in enrichments), decision.status == "eligible_for_simulation"); result = results[-1] if results else execute(decision); records.append(IncidentRecord(alert, fingerprint(alert), enrichments, decision, result))
    write_report(records, args.report); write_event("reports/audit.jsonl", "simulation_completed", {"incidents": len(records), "actions_simulated": True})
    print(f"Processed {len(records)} incident(s); all actions are SIMULATED ONLY.")

if __name__ == "__main__": main()
