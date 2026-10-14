@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo 找不到 python，請先安裝 Python 並加入 PATH。
  exit /b 1
)

python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 exit /b 1

python -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --onefile ^
  --name "LINE_chat_exporter" ^
  --collect-all openpyxl ^
  --collect-all cryptography ^
  --hidden-import apsw ^
  --hidden-import line_read_helper ^
  "LINE_chat_exporter.pyw"

if errorlevel 1 exit /b 1

echo.
echo 完成：dist\LINE_chat_exporter.exe
echo 把這個 exe 複製給別人即可，對方不必安裝 Python。
endlocal
