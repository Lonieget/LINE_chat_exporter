@echo off
set "SCRIPT_DIR=%~dp0"

if exist "%SCRIPT_DIR%LINE_chat_exporter.exe" (
  start "" "%SCRIPT_DIR%LINE_chat_exporter.exe"
  exit /b 0
)
if exist "%SCRIPT_DIR%dist\LINE_chat_exporter.exe" (
  start "" "%SCRIPT_DIR%dist\LINE_chat_exporter.exe"
  exit /b 0
)

set "PYTHONPATH=%SCRIPT_DIR%vendor"
where pythonw >nul 2>nul
if errorlevel 1 (
  python "%SCRIPT_DIR%LINE_chat_exporter.pyw"
) else (
  start "" pythonw "%SCRIPT_DIR%LINE_chat_exporter.pyw"
)
