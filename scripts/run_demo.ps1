$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
python -m src.incident_response --input sample-data/alerts.json --report reports/demo.json
Write-Host 'Demo completed. Review reports/demo.json and reports/audit.jsonl.'
