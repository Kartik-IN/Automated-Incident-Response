# Security review

## Threat model

Inputs may be malformed, duplicated, misleading, or attacker-controlled. The system therefore validates JSON, normalizes fields, keeps provenance, denies unknown actions, requires approval for high-impact simulations, and defaults to dry-run.

## Secrets and API security

Wazuh credentials are read only from `WAZUH_API_TOKEN`; they are not stored in configuration or written to logs. `WAZUH_API_URL` is optional. TLS verification is required by default and timeouts are bounded. The adapter is disabled unless explicitly enabled.

## Failure handling and limitations

Unavailable services, authentication failures, malformed responses, and missing enrichment return safe errors/unknown status. No failure makes an indicator malicious. The REST/Wazuh paths are not live-validated here; tests are mocked or disabled.

## Safe operation

The only response implementation is simulation. `simulated_block_indicator` is a label, not a network operation. There are no integrations for endpoint isolation, account disabling, process termination, or firewall changes. The append-only JSONL audit log records plans and action results, but should be protected with filesystem permissions and shipped to an external immutable store in a future production design.
