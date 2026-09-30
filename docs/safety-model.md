# Safety model

The default is dry-run. The response module always returns `simulated`; non-dry-run requests are refused. No module contains integrations for blocking, isolation, process termination, account disabling, or firewall changes. Actions requiring analyst approval remain unapproved until a future explicit workflow is designed.

The orchestration layer creates an append-only JSONL audit trail and denies unknown actions. `simulated_block_indicator` is a label only; it never performs network blocking. Wazuh integration is disabled by default, validates TLS, bounds timeouts, and never logs credentials.
