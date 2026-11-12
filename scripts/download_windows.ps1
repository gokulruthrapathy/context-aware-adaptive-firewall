param([string]$Output = "data/raw/dataset.zip")
$ErrorActionPreference = "Stop"
if (Test-Path -LiteralPath $Output) { throw "Target already exists: $Output" }
$parent = Split-Path -Parent $Output
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$partial = "$Output.partial"
Invoke-WebRequest -Uri 'https://intrusion-detection.distrinet-research.be/WTMC2021/Dataset/dataset.zip' -OutFile $partial -TimeoutSec 600
$digest = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
if ($digest -ne '4d535da19795d85376ae1397d161329e3b06fc47d9a5a68cd9be2cd7ecee0f2a') { throw "Dataset SHA-256 mismatch" }
Move-Item -LiteralPath $partial -Destination $Output
Write-Output $Output
