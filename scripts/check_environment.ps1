$ErrorActionPreference = 'Stop'
python --version
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required' }
Write-Host 'Environment check complete.'
