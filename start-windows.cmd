@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m envscope.desktop
  if errorlevel 1 pause
  exit /b
)
where python >nul 2>nul
if %errorlevel%==0 (
  python -m envscope.desktop
  if errorlevel 1 pause
  exit /b
)
echo Python 3.10+ was not found. Use the Windows desktop release or install Python.
pause
