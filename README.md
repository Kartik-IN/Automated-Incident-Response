# Automated Incident Response

Safety-first Python 3.11+ portfolio foundation for ingesting, normalizing, enriching, evaluating, and simulating responses to security alerts.

## Architecture and features

JSON ingestion is isolated behind an adapter interface. Alerts are validated, normalized, fingerprinted, and deduplicated. Offline enrichment extracts indicators and context, then consults local inventory, allowlists, and synthetic fixtures. The policy engine emits evidence-backed decisions. The orchestration layer creates plans, enforces approval and dry-run gates, simulates safe actions, and appends audit events. Wazuh is an optional disabled-by-default adapter.

## Setup and verified commands

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m src.incident_response --input sample-data/alerts.json --report reports/demo.json
.\scripts\run_demo.ps1
```

Linux/macOS uses `python3` and `source .venv/bin/activate`; the test and CLI commands are otherwise the same. In this environment, Python 3.14.3 was available and the test suite completed successfully with 10 tests.

## Sample output

The CLI prints `Processed 2 incident(s); all actions are SIMULATED ONLY.` Reports contain enrichment provenance, policy evidence, decision status, and simulated action results. `reports/audit.jsonl` contains plan and action events.

## Safety and limitations

Dry-run is always the default. Unknown actions are denied. `simulated_block_indicator` never blocks anything. There is no real network blocking, endpoint isolation, account disabling, process termination, firewall modification, or live response capability. Wazuh is not required or assumed reachable; tests do not make external requests. Unknown or failed lookups never imply maliciousness. The append-only audit file is application-level append-only and requires filesystem protection for stronger immutability.

## Future improvements

Sandboxed Wazuh integration tests, distributed idempotency, external immutable audit storage, secret-manager integration, stronger schema validation, analyst workflow integration, and production-grade authorization/observability should precede any operational use.

See [docs/incident-response-playbook.md](docs/incident-response-playbook.md), [docs/security-review.md](docs/security-review.md), [docs/project-walkthrough.md](docs/project-walkthrough.md), and [docs/interview-questions.md](docs/interview-questions.md).
