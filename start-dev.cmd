@echo off
setlocal EnableExtensions

REM Usage:
REM   start-dev.cmd
REM   start-dev.cmd --no-browser
REM   start-dev.cmd --help

set "OPEN_BROWSER=1"
if /I "%~1"=="--no-browser" set "OPEN_BROWSER=0"
if /I "%~1"=="--help" goto :usage
if /I "%~1"=="-h" goto :usage
if not "%~1"=="" if /I not "%~1"=="--no-browser" if /I not "%~1"=="--help" if /I not "%~1"=="-h" (
  echo Invalid argument: %~1
  goto :usage_error
)

set "ROOT_DIR=%~dp0"
set "VENV_PY=%ROOT_DIR%.venv\Scripts\python.exe"
set "APP_PORT=56461"
set "APP_HOST=127.0.0.1"
set "APP_URL=http://%APP_HOST%:%APP_PORT%"
set "PYTHON_EXE="
set "PYTHON_PRIMARY="

if not exist "%ROOT_DIR%app\main.py" (
  echo app\main.py not found. Run this script from the ExposureMapper repository root.
  exit /b 1
)
if not exist "%ROOT_DIR%requirements.txt" (
  echo requirements.txt not found. Run this script from the ExposureMapper repository root.
  exit /b 1
)

where py >nul 2>nul
if not errorlevel 1 (
  for /f "delims=" %%I in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%I"
)
for /f "delims=" %%I in ('where python 2^>nul') do (
  if not defined PYTHON_PRIMARY set "PYTHON_PRIMARY=%%I"
  echo %%I | findstr /I /C:"\\WindowsApps\\" >nul
  if errorlevel 1 if not defined PYTHON_EXE set "PYTHON_EXE=%%I"
)
if not defined PYTHON_EXE set "PYTHON_EXE=%PYTHON_PRIMARY%"
if not defined PYTHON_EXE (
  echo Could not resolve a valid Python executable path.
  echo Install Python 3.11+ and ensure either "py -3" or "python" works in PATH.
  exit /b 1
)

cd /d "%ROOT_DIR%"
if not exist "%VENV_PY%" (
  echo Creating virtual environment in .venv...
  "%PYTHON_EXE%" -m venv .venv
  if errorlevel 1 (
    echo Failed to create virtual environment.
    exit /b 1
  )
)

echo Installing dependencies from requirements.txt...
"%VENV_PY%" -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo pip install failed. Check network/package availability.
  exit /b 1
)

if not exist ".env" if exist ".env.example" (
  echo Creating .env from .env.example...
  copy /Y ".env.example" ".env" >nul
)

if "%DATABASE_URL%"=="" (
  set "DB_DIR=%TEMP%\ExposureMapper"
  if not exist "%DB_DIR%" mkdir "%DB_DIR%"
  set "DATABASE_URL=sqlite:///%DB_DIR:\=/%/exposuremapper.db"
)

if "%OPEN_BROWSER%"=="1" (
  start "ExposureMapper Homepage" powershell -NoProfile -ExecutionPolicy Bypass -Command "$health='http://%APP_HOST%:%APP_PORT%/healthz'; $targetUrl='http://%APP_HOST%:%APP_PORT%'; for ($i=0; $i -lt 60; $i++) { try { Invoke-RestMethod -Uri $health -TimeoutSec 2 | Out-Null; Start-Process $targetUrl; exit 0 } catch { Start-Sleep -Milliseconds 500 } }; Start-Process $targetUrl"
)

echo Starting ExposureMapper on http://%APP_HOST%:%APP_PORT% ...
"%VENV_PY%" -m uvicorn app.main:app --host %APP_HOST% --port %APP_PORT% --reload
exit /b %errorlevel%

:usage
echo Usage:
echo   start-dev.cmd
echo   start-dev.cmd --no-browser
echo   start-dev.cmd --help
exit /b 0

:usage_error
echo Usage:
echo   start-dev.cmd
echo   start-dev.cmd --no-browser
echo   start-dev.cmd --help
exit /b 1
