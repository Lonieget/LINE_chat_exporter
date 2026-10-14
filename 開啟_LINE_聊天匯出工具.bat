@echo off
set "SCRIPT_DIR=%~dp0"
set "PYTHONPATH=%SCRIPT_DIR%vendor"
where pythonw >nul 2>nul
if errorlevel 1 (
  python "%SCRIPT_DIR%LINE_chat_exporter.pyw"
) else (
  start "" pythonw "%SCRIPT_DIR%LINE_chat_exporter.pyw"
)
