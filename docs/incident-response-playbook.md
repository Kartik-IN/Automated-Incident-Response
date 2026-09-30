# Incident response playbook

This project is a training and portfolio foundation. It does not perform live containment.

## Triage

1. Confirm the alert source, timestamp, rule ID, affected user/host, and extracted indicators.
2. Check normalization and duplicate status.
3. Review offline enrichment provenance: allowlist, asset inventory, synthetic fixture, verified external, or unknown.
4. Treat unknown values and lookup failures as insufficient evidence, never as maliciousness.

## Decision criteria

Severity and confidence must meet configured thresholds. Allowlists and duplicate status suppress escalation. High-impact mappings become `approval_required`; only explicitly eligible decisions may be simulated. Asset criticality and event context are evidence for analyst review, not automatic proof of compromise.

## Approval and escalation

An analyst must validate evidence, scope, business impact, and false-positive risk before approving a simulation. Escalate high/critical alerts, privileged-account activity, conflicting enrichment, or material production impact to the incident commander and asset owner. Never approve a real disruptive action through this project.

## Closure checklist

- Record decision reason and evidence.
- Confirm simulated actions and audit entries.
- Attach report and relevant alert identifiers.
- Document unknowns, assumptions, and follow-up enrichment.
- Obtain analyst/incident-commander closure acknowledgement.
