@echo off
setlocal EnableExtensions

REM Backward-compatible wrapper. Preferred entrypoint: start-dev.cmd
call "%~dp0start-dev.cmd" %*
exit /b %errorlevel%
