# Setup guide

Windows PowerShell: `python -m venv .venv`, `\.venv\Scripts\Activate.ps1`, `python -m pip install -r requirements.txt`, then `python -m unittest discover -s tests -v`.

Linux/macOS: `python3 -m venv .venv`, `source .venv/bin/activate`, then run the same install and test commands. Run the demo with `python -m src.incident_response --input sample-data/alerts.json --report reports/run.json`.

Optional Wazuh configuration uses placeholders only: set `WAZUH_API_URL=https://wazuh.example.invalid` and `WAZUH_API_TOKEN=<token-from-secret-store>`, then explicitly construct `WazuhAdapter(enabled=True)`. The project does not assume Wazuh is installed or reachable.
