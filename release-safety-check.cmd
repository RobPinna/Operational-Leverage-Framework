@echo off
setlocal EnableExtensions

set "FAIL=0"

if exist ".env" (
  echo [WARN] .env present locally. Ensure it is not committed.
)
if exist ".venv" (
  echo [FAIL] Found .venv
  set "FAIL=1"
)
if exist "exports\rag_indexes" (
  echo [FAIL] Found exports\rag_indexes
  set "FAIL=1"
)

powershell -NoProfile -Command "$db = Get-ChildItem -Path . -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.db($|-)' }; if($db){ $db | Select-Object -ExpandProperty FullName | %% { Write-Host ('[WARN] local db artifact (ignored): ' + $_) } }; $bad = Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.pyc($|\.)' -or $_.FullName -match '\\exports\\.*\.(json|pdf)$' }; if($bad){ $bad | Select-Object -First 20 -ExpandProperty FullName | %% { Write-Host ('[FAIL] forbidden file: ' + $_) }; exit 1 } else { exit 0 }"
if errorlevel 1 set "FAIL=1"

if "%FAIL%"=="1" (
  echo.
  echo Release safety check failed.
  exit /b 1
)

echo Release safety check passed.
exit /b 0
