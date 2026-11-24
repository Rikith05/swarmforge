$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([scriptblock]$Cmd)
    & $Cmd
    if ($LASTEXITCODE -ne 0) {
        throw "Verification step failed with exit code $LASTEXITCODE"
    }
}

Write-Host "1/4 Syntax-checking frontend JS modules..." -ForegroundColor Cyan
Invoke-Checked { node --check swarmforge/web/dag.js }
Invoke-Checked { node --check swarmforge/web/views.js }
Invoke-Checked { node --check swarmforge/web/app.js }

Write-Host "2/4 Running unit & API test suite..." -ForegroundColor Cyan
Invoke-Checked { python -m unittest discover -s tests -v }

Write-Host "3/4 Running strict Eval Arena benchmark gate..." -ForegroundColor Cyan
Invoke-Checked { python -m swarmforge.cli eval --policy strict --strict }

Write-Host "4/4 Running self-audit scan on SwarmForge repository..." -ForegroundColor Cyan
Invoke-Checked { python -m swarmforge.cli scan . --policy strict }

Write-Host "All SwarmForge verification gates passed." -ForegroundColor Green
