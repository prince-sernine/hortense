# Build Hortense CLI executable.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

if (-not (Test-Path .\.venv\Scripts\Activate.ps1)) {
    Write-Error "Create .venv first: py -3.12 -m venv .venv"
}

.\.venv\Scripts\Activate.ps1
pip install -e ".[exe]"
maturin develop --release

New-Item -ItemType Directory -Force -Path .\build | Out-Null
$launcher = ".\build\hortense_launcher.py"
@"
from hortense.cli import main

if __name__ == "__main__":
    main()
"@ | Set-Content -Encoding UTF8 $launcher

pyinstaller --onefile --name hortense --collect-all hortense $launcher

Write-Host "Built dist\hortense.exe"
