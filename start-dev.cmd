@echo off
setlocal

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" scripts\run.py web %*
  exit /b %errorlevel%
)

where python >nul 2>nul
if %errorlevel%==0 (
  python scripts\run.py web %*
  exit /b %errorlevel%
)

py -3 scripts\run.py web %*
exit /b %errorlevel%
