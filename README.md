# LINE Chat Exporter

從本機 LINE 讀取聊天紀錄並匯出的小工具（Windows）。

## 給一般使用者（不必安裝 Python）

1. 取得 `LINE_chat_exporter.exe`
2. 雙擊執行（或執行 `開啟_LINE_聊天匯出工具.bat`）
3. 使用前請先開啟 LINE 電腦版並登入
4. 按「更新 LINE 資料與聯絡人名稱」：每次更新會新建一個資料夾

### 每次更新產生的資料夾

```text
exports/
  LINE_匯出_YYYYMMDD_HHMMSS/
    LINE_聊天室索引.csv
    LINE_全部聊天.csv
    圖片/
      <訊息ID>.jpg / .eimg / …
```

- 文字在資料夾根目錄的 CSV
- 圖片在 `圖片/` 子資料夾
- CSV「內容」欄會寫相對路徑（例如 `圖片/6156….jpg`）
- 有 `keyMaterial` 的加密快取會自動解密成可開啟的 `.jpg`／`.png`；失敗時才保留 `.eimg`（「圖片（未解密）」）
- 目前匯出的是 LINE 本機縮圖快取（`thumbPath`），不是一定等於原圖全尺寸

之後可在介面勾選聊天室，再另存 Excel。

---

## 開發者：用原始碼執行

### 環境需求

- Windows
- Python 3.10 以上（建議 64-bit）
- 安裝時勾選 **Add python.exe to PATH**

### 安裝與執行

```bat
git clone https://github.com/Lonieget/LINE_chat_exporter.git
cd LINE_chat_exporter

python -m pip install -r requirements.txt

開啟_LINE_聊天匯出工具.bat
```

### 打包成 exe

```bat
build_exe.bat
```

完成後檔案在 `dist\LINE_chat_exporter.exe`。

## 依賴套件

| 套件 | 用途 |
|------|------|
| `apsw_sqlite3mc` | 讀取 LINE SQLite 資料庫 |
| `openpyxl` | 匯出 Excel（`.xlsx`） |

## 注意事項

- 需在已登入、可讀取 LINE 資料的環境下使用。
- `exports/`、`dist/`、`build/`、`vendor/` 預設不進版控。
- 匯出／更新產生的檔案請自行保管。
