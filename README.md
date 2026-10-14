# LINE Chat Exporter

從本機 LINE 讀取聊天紀錄並匯出的小工具（Windows）。

## 環境需求

- Windows
- Python 3.10 以上（建議 64-bit）
- 已安裝 [Python](https://www.python.org/downloads/)，安裝時勾選 **Add python.exe to PATH**

## 安裝與執行

```bat
git clone https://github.com/Lonieget/LINE_chat_exporter.git
cd LINE_chat_exporter

python -m pip install -r requirements.txt

開啟_LINE_聊天匯出工具.bat
```

或直接執行：

```bat
pythonw LINE_chat_exporter.pyw
```

## 依賴套件

| 套件 | 用途 |
|------|------|
| `apsw_sqlite3mc` | 讀取 LINE SQLite 資料庫 |
| `openpyxl` | 匯出 Excel（`.xlsx`） |

安裝 `openpyxl` 時會一併帶入 `et-xmlfile`，不必另外指定。

## 注意事項

- 需在已登入、可讀取 LINE 資料的環境下使用。
- 匯出檔請自行保管，勿提交到 git。
- 本機若仍有 `vendor/` 資料夾，程式會優先使用它；一般 clone 後只要用 `pip` 安裝即可，不需要 `vendor/`。
