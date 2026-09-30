# Architecture

`AlertAdapter` isolates ingestion from future Wazuh API integration. JSON alerts are validated, normalized, fingerprinted and deduplicated, then enriched with local metadata, evaluated against policy, and passed to a simulation-only response executor. Reporting and append-only audit logging are separate concerns.
