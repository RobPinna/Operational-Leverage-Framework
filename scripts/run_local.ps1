param(
  [string]$Host = "127.0.0.1",
  [int]$Port = 8000,
  [switch]$NoReload
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
  $pyExe = "py"
  $pyArgs = @("-3")
} else {
  $python = Get-Command python -ErrorAction SilentlyContinue
  if (-not $python) {
    throw "Python 3.11+ non trovato nel PATH"
  }
  $pyExe = "python"
  $pyArgs = @()
}

if (-not (Test-Path ".venv/Scripts/python.exe")) {
  & $pyExe @pyArgs -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

Start-Process "http://$Host`:$Port/login"

$reloadArg = if ($NoReload) { @() } else { @("--reload") }
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --host $Host --port $Port @reloadArg
