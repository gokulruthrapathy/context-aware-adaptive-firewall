# Use the already-created isolated environment in this task, or a new .venv.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$taskRoot = Split-Path -Parent (Split-Path -Parent $projectRoot)
$pythonCandidates = @(
    (Join-Path $projectRoot '.venv\Scripts\python.exe'),
    (Join-Path $taskRoot 'work\firewall-venv\Scripts\python.exe')
)
$studyPython = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $studyPython) { throw 'No isolated environment found. Follow the installation commands in README.md.' }
Push-Location -LiteralPath $projectRoot
try {
    & $studyPython -m adaptive_firewall.cli @args
    if ($LASTEXITCODE -ne 0) { throw "Study command failed with exit code $LASTEXITCODE" }
}
finally { Pop-Location }
