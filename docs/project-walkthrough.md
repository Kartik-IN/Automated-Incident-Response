# Five-minute walkthrough

1. Show `config/response_policy.json` and point out `dry_run: true` and approval mappings.
2. Run `python -m unittest discover -s tests -v` and explain that Wazuh tests are disabled/mocked.
3. Run `python -m src.incident_response --input sample-data/alerts.json --report reports/demo.json`.
4. Open `reports/demo.json` to show decision status, evidence, enrichment provenance, and simulated action.
5. Open `reports/audit.jsonl` to show plan and action events.
6. Explain that no live block, isolation, process, account, or firewall operation exists, and that Wazuh is opt-in only.
