# Interview questions and answers

1. **Why is dry-run the default?** It prevents accidental operational impact while policy and evidence are reviewed.
2. **What is an adapter interface?** A stable contract that lets JSON and future Wazuh sources share downstream processing.
3. **How are duplicates detected?** A stable SHA-256 fingerprint of normalized title, source, severity, and indicators.
4. **Why normalize before fingerprinting?** Equivalent formatting should produce the same identity.
5. **What does unknown enrichment mean?** Evidence is unavailable; it is not a malicious verdict.
6. **Which indicator types are extracted?** IPs, hostnames, hashes, and explicit values; event context includes users, rules, hosts, and timestamps.
7. **How are allowlists used?** They suppress escalation and are recorded as evidence.
8. **What is provenance?** The source classification for an enrichment result, such as local configuration or synthetic fixture.
9. **Why use synthetic fixtures?** They make demonstrations deterministic without external services or real threat data.
10. **What happens at the confidence boundary?** A value equal to the configured threshold meets it.
11. **What happens at the severity boundary?** Severities at or above the configured level meet it.
12. **Why require approval?** High-impact simulations need human validation of scope and business impact.
13. **What are decision statuses?** Monitor, approval required, and eligible for simulation communicate workflow state.
14. **How are unknown actions handled?** They are denied by default.
15. **What makes actions idempotent?** Plan/action keys prevent repeating an already simulated action.
16. **What does simulated blocking do?** It emits an auditable simulation result and never changes network state.
17. **How are actions audited?** Plans and action results are appended as JSONL events.
18. **Can the audit file be rewritten by the application?** The application only appends; filesystem controls are still required.
19. **Where are Wazuh secrets stored?** Only in environment variables supplied by the operator or secret manager.
20. **Are secrets logged?** No; authorization headers are never included in errors or audit details.
21. **How is TLS handled?** Wazuh requires TLS verification unless an unsafe configuration is rejected.
22. **How are API calls bounded?** Explicit timeout limits and adapter-level enablement are required.
23. **What happens when Wazuh is unavailable?** A safe typed error is raised; the project does not assume Wazuh exists.
24. **Do tests contact Wazuh?** No. Tests use disabled adapters or mocked/failure paths.
25. **Why is standard library usage useful here?** It reduces dependency and supply-chain surface for a small foundation.
26. **What is a policy evidence field?** Structured facts supporting a decision, such as threshold results and enrichment statuses.
27. **How is conflicting context handled?** It remains evidence for review; the system does not silently resolve it as malicious.
28. **What is the response plan?** An auditable list of safe actions derived from an alert and policy decision.
29. **What is not production-ready?** Live containment, durable distributed idempotency, external immutable audit shipping, and live Wazuh validation.
30. **How would production hardening proceed?** Threat-model review, integration tests in a sandbox, secret-manager integration, authorization design, observability, and staged approvals.
31. **Why keep reports separate from audit logs?** Reports summarize incidents; audit logs record execution events.
32. **How should analysts close an incident?** Record evidence, decisions, simulations, unknowns, follow-ups, and approvals.
