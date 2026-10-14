# LINE Chat Exporter

從本機 LINE 讀取聊天紀錄並匯出的小工具（Windows）。

## 給一般使用者（不必安裝 Python）

1. 取得 `LINE_chat_exporter.exe`
2. 雙擊執行（或執行 `開啟_LINE_聊天匯出工具.bat`）
3. 使用前請先開啟 LINE 電腦版並登入

產生的 CSV／Excel 會出現在 **exe 同一個資料夾**。

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

在已安裝 Python 的電腦執行：

```bat
build_exe.bat
```

完成後檔案在 `dist\LINE_chat_exporter.exe`，把這個 exe 傳給別人即可，對方**不必**安裝 Python。

## 依賴套件

| 套件 | 用途 |
|------|------|
| `apsw_sqlite3mc` | 讀取 LINE SQLite 資料庫 |
| `openpyxl` | 匯出 Excel（`.xlsx`） |

## 注意事項

- 需在已登入、可讀取 LINE 資料的環境下使用。
- 匯出檔請自行保管，勿提交到 git。
- `dist/`、`build/`、`vendor/` 預設不進版控；若要發佈免安裝版，請另外提供 exe。
