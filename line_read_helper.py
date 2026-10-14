import ctypes
import ctypes.wintypes as wt
import csv
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def app_base_dir() -> Path:
    """Directory for CSV/JSON outputs: next to the .exe when frozen, else this script's folder."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


SCRIPT_DIR = app_base_dir()
LOCAL_VENDOR_DIR = SCRIPT_DIR / "vendor"
VENDOR_DIR = LOCAL_VENDOR_DIR if LOCAL_VENDOR_DIR.exists() else SCRIPT_DIR.parent / "work" / "vendor"
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))

import apsw


TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.restype = wt.BOOL


def find_line_processes():
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    pids = []
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == "line.exe":
                pids.append(entry.th32ProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return pids


def candidate_keys(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return set()
    marker = re.compile(rb"(?i)encryption[_ ]?key[^0-9a-f]{0,64}([0-9a-f]{32})")
    suffix = re.compile(rb"(?i)([0-9a-f]{32})mse")
    generic = re.compile(rb"(?i)(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])")
    text_marker = re.compile(r"(?i)encryption[_ ]?key[^0-9a-f]{0,64}([0-9a-f]{32})")
    text_suffix = re.compile(r"(?i)([0-9a-f]{32})mse")
    text_generic = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])")
    marked = set()
    all_hex = set()
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    try:
        while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            readable = mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS
            if readable and size:
                offset = 0
                overlap = b""
                while offset < size:
                    amount = min(4 * 1024 * 1024, size - offset)
                    buffer = ctypes.create_string_buffer(amount)
                    read = ctypes.c_size_t()
                    ok = kernel32.ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(base + offset),
                        buffer,
                        amount,
                        ctypes.byref(read),
                    )
                    if ok and read.value:
                        data = overlap + buffer.raw[: read.value]
                        for match in marker.finditer(data):
                            marked.add(match.group(1).decode("ascii"))
                        for match in suffix.finditer(data):
                            marked.add(match.group(1).decode("ascii"))
                        for match in generic.finditer(data):
                            all_hex.add(match.group(1).decode("ascii"))
                        try:
                            decoded = data.decode("utf-16-le", errors="ignore")
                            for match in text_marker.finditer(decoded):
                                marked.add(match.group(1))
                            for match in text_suffix.finditer(decoded):
                                marked.add(match.group(1))
                            for match in text_generic.finditer(decoded):
                                all_hex.add(match.group(1))
                        except Exception:
                            pass
                        overlap = data[-512:]
                    offset += amount
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
    finally:
        kernel32.CloseHandle(handle)
    return marked, all_hex


def make_snapshot():
    db_dir = Path(os.environ["LOCALAPPDATA"]) / "LINE" / "Data" / "db"
    databases = [
        path for path in db_dir.glob("qw*.edb")
        if not path.name.endswith(("-wal", "-shm"))
    ]
    if not databases:
        raise RuntimeError("找不到 LINE 主資料庫。")
    source = max(databases, key=lambda path: path.stat().st_size)
    snapshot_dir = Path(tempfile.mkdtemp(prefix="line-read-"))
    target = snapshot_dir / source.name
    # The main file alone is sufficient for key validation. Avoid pairing it
    # with a WAL copied at a slightly different instant from a running app.
    for suffix in ("",):
        item = Path(str(source) + suffix)
        if item.exists():
            shutil.copyfile(item, snapshot_dir / item.name)
    return target, snapshot_dir


def configure(connection, cipher, legacy, key_pragma, key):
    connection.pragma("cipher", cipher)
    if legacy is not None:
        connection.pragma("legacy", legacy)
        connection.pragma("legacy_page_size", 4096)
    connection.pragma(key_pragma, key)


def opens_database(path, key):
    connection = None
    try:
        for cipher, legacy, key_pragma in (
            ("aes128cbc", None, "key"),
            ("aes128cbc", 0, "key"),
            ("aes128cbc", 1, "key"),
            ("aes128cbc", None, "hexkey"),
            ("aes256cbc", None, "key"),
        ):
            try:
                connection = apsw.Connection(str(path))
                configure(connection, cipher, legacy, key_pragma, key)
                connection.pragma("user_version")
                return (cipher, legacy, key_pragma)
            except Exception:
                pass
            finally:
                if connection is not None:
                    connection.close()
                    connection = None
        return None
    except Exception:
        return False
    finally:
        if connection is not None:
            connection.close()


def inventory(path, key, settings):
    connection = apsw.Connection(str(path))
    try:
        cipher, legacy, key_pragma = settings
        configure(connection, cipher, legacy, key_pragma, key)
        cursor = connection.cursor()
        tables = []
        rows = list(cursor.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ))
        for name, sql in rows:
            escaped = name.replace('"', '""')
            try:
                count = cursor.execute(f'SELECT count(*) FROM "{escaped}"').fetchone()[0]
            except Exception:
                count = None
            columns = [row[1] for row in cursor.execute(f'PRAGMA table_info("{escaped}")')]
            tables.append({"name": name, "rows": count, "columns": columns, "schema": sql})
        return tables
    finally:
        connection.close()


def iso_time(value):
    if not value:
        return None


TAIPEI = timezone(timedelta(hours=8))


def taipei_time(value):
    if not value:
        return ""


def excel_safe(value):
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
    try:
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=TAIPEI).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return ""
    try:
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (ValueError, OSError, TypeError):
        return None


def chat_summary(path, key, settings):
    connection = apsw.Connection(str(path))
    try:
        cipher, legacy, key_pragma = settings
        configure(connection, cipher, legacy, key_pragma, key)
        cursor = connection.cursor()
        overall = cursor.execute(
            """
            SELECT COUNT(*),
                   SUM(CASE WHEN _text IS NOT NULL AND _text <> '' THEN 1 ELSE 0 END),
                   MIN(_createdTime), MAX(_createdTime)
            FROM _message
            """
        ).fetchone()
        rows = cursor.execute(
            """
            WITH message_stats AS (
                SELECT _chatId,
                       COUNT(*) AS message_count,
                       MIN(_createdTime) AS oldest_time,
                       MAX(_createdTime) AS newest_time
                FROM _message
                GROUP BY _chatId
            ),
            latest_text AS (
                SELECT _chatId, _text, _createdTime,
                       ROW_NUMBER() OVER (
                           PARTITION BY _chatId ORDER BY _createdTime DESC, _id DESC
                       ) AS rn
                FROM _message
                WHERE _text IS NOT NULL AND _text <> ''
            )
            SELECT c._id,
                   COALESCE(
                       NULLIF(g._chatName, ''),
                       NULLIF(ct._displayNameOverridden, ''),
                       NULLIF(ct._displayName, ''),
                       NULLIF(CASE WHEN json_valid(ct._friendDetail) THEN json_extract(ct._friendDetail, '$.user.overriddenName') END, ''),
                       NULLIF(CASE WHEN json_valid(ct._targetProfileDetail) THEN json_extract(ct._targetProfileDetail, '$.profileName') END, ''),
                       NULLIF(s._name, ''),
                       c._id
                   ) AS chat_name,
                   c._midType,
                   c._lastUpdatedTime,
                   c._unreadCount,
                   COALESCE(ms.message_count, 0),
                   ms.oldest_time,
                   ms.newest_time,
                   lt._text,
                   lt._createdTime
            FROM _chat AS c
            LEFT JOIN _contact AS ct ON ct._mid = c._id
            LEFT JOIN _groupChat AS g ON g._chatMid = c._id
            LEFT JOIN _squareChat AS s ON s._squareChatMid = c._id
            LEFT JOIN message_stats AS ms ON ms._chatId = c._id
            LEFT JOIN latest_text AS lt ON lt._chatId = c._id AND lt.rn = 1
            ORDER BY c._lastUpdatedTime DESC
            LIMIT 100
            """
        )
        chats = []
        for row in rows:
            preview = row[8]
            if isinstance(preview, str) and len(preview) > 120:
                preview = preview[:120] + "…"
            chats.append({
                "chat_id": row[0],
                "name": row[1],
                "type": row[2],
                "last_updated": iso_time(row[3]),
                "unread": row[4],
                "message_count": row[5],
                "oldest_message": iso_time(row[6]),
                "newest_message": iso_time(row[7]),
                "last_text_preview": preview,
                "last_text_time": iso_time(row[9]),
            })
        return {
            "message_count": overall[0],
            "text_message_count": overall[1],
            "oldest_message": iso_time(overall[2]),
            "newest_message": iso_time(overall[3]),
            "recent_chats": chats,
        }
    finally:
        connection.close()


def resolve_chat(cursor, requested_name):
    rows = list(cursor.execute(
        """
        SELECT c._id,
               COALESCE(
                   NULLIF(g._chatName, ''),
                   NULLIF(ct._displayNameOverridden, ''),
                   NULLIF(ct._displayName, ''),
                   NULLIF(CASE WHEN json_valid(ct._friendDetail) THEN json_extract(ct._friendDetail, '$.user.overriddenName') END, ''),
                   NULLIF(CASE WHEN json_valid(ct._targetProfileDetail) THEN json_extract(ct._targetProfileDetail, '$.profileName') END, ''),
                   NULLIF(s._name, ''),
                   c._id
               ) AS chat_name
        FROM _chat AS c
        LEFT JOIN _contact AS ct ON ct._mid = c._id
        LEFT JOIN _groupChat AS g ON g._chatMid = c._id
        LEFT JOIN _squareChat AS s ON s._squareChatMid = c._id
        WHERE c._id = ? OR COALESCE(
                NULLIF(g._chatName, ''),
                NULLIF(ct._displayNameOverridden, ''),
                NULLIF(ct._displayName, ''),
                NULLIF(CASE WHEN json_valid(ct._friendDetail) THEN json_extract(ct._friendDetail, '$.user.overriddenName') END, ''),
                NULLIF(CASE WHEN json_valid(ct._targetProfileDetail) THEN json_extract(ct._targetProfileDetail, '$.profileName') END, ''),
                NULLIF(s._name, ''),
                c._id
              ) = ?
        """,
        (requested_name, requested_name),
    ))
    if not rows:
        raise RuntimeError(f"找不到聊天室：{requested_name}")
    if len(rows) > 1:
        raise RuntimeError(f"聊天室名稱不唯一：{requested_name}")
    return rows[0]


def export_chat(path, key, settings, requested_name):
    connection = apsw.Connection(str(path))
    try:
        cipher, legacy, key_pragma = settings
        configure(connection, cipher, legacy, key_pragma, key)
        cursor = connection.cursor()
        chat_id, chat_name = resolve_chat(cursor, requested_name)
        own_mid_row = cursor.execute("SELECT _mid FROM _profile LIMIT 1").fetchone()
        own_mid = own_mid_row[0] if own_mid_row else None
        rows = cursor.execute(
            """
            SELECT m._createdTime,
                   m._from,
                   COALESCE(
                       NULLIF(sender._displayNameOverridden, ''),
                       NULLIF(sender._displayName, ''),
                       NULLIF(CASE WHEN json_valid(sender._friendDetail) THEN json_extract(sender._friendDetail, '$.user.overriddenName') END, ''),
                       NULLIF(CASE WHEN json_valid(sender._targetProfileDetail) THEN json_extract(sender._targetProfileDetail, '$.profileName') END, ''),
                       m._from
                   ) AS sender_name,
                   m._contentType,
                   m._text,
                   m._id
            FROM _message AS m
            LEFT JOIN _contact AS sender ON sender._mid = m._from
            WHERE m._chatId = ?
            ORDER BY m._createdTime, m._id
            """,
            (chat_id,),
        )
        safe_name = re.sub(r'[\\/:*?"<>|]+', "_", chat_name).strip() or "LINE_chat"
        csv_path = SCRIPT_DIR / f"{safe_name}_完整聊天.csv"
        count = 0
        with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["時間（台北）", "方向", "發言者", "訊息類型", "內容", "訊息ID"])
            for created_time, sender_mid, sender_name, content_type, message_text, message_id in rows:
                direction = "傳出" if own_mid and sender_mid == own_mid else "收到"
                sender = "我" if direction == "傳出" else sender_name
                kind = "文字" if message_text else f"非文字（{content_type}）"
                writer.writerow([
                    taipei_time(created_time),
                    direction,
                    excel_safe(sender),
                    kind,
                    excel_safe(message_text),
                    message_id,
                ])
                count += 1
        return csv_path, count
    finally:
        connection.close()


def export_all_chats(path, key, settings):
    connection = apsw.Connection(str(path))
    try:
        cipher, legacy, key_pragma = settings
        configure(connection, cipher, legacy, key_pragma, key)
        cursor = connection.cursor()
        own_mid_row = cursor.execute("SELECT _mid FROM _profile LIMIT 1").fetchone()
        own_mid = own_mid_row[0] if own_mid_row else None

        index_path = SCRIPT_DIR / "LINE_聊天室索引.csv"
        with index_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "聊天室名稱", "聊天室ID", "類別", "類型", "訊息數",
                "最早訊息（台北）", "最新訊息（台北）",
            ])
            index_rows = cursor.execute(
                """
                SELECT COALESCE(
                           NULLIF(g._chatName, ''),
                           NULLIF(ct._displayNameOverridden, ''),
                           NULLIF(ct._displayName, ''),
                           NULLIF(CASE WHEN json_valid(ct._friendDetail) THEN json_extract(ct._friendDetail, '$.user.overriddenName') END, ''),
                           NULLIF(CASE WHEN json_valid(ct._targetProfileDetail) THEN json_extract(ct._targetProfileDetail, '$.profileName') END, ''),
                           NULLIF(s._name, ''),
                           c._id
                       ) AS chat_name,
                       c._id,
                       CASE
                           WHEN c._id LIKE 'u%' AND bd._mid IS NOT NULL THEN '官方帳號'
                           WHEN c._id LIKE 'u%' THEN '好友'
                           WHEN c._id LIKE 'c%' THEN '群組'
                           WHEN c._id LIKE 'm%' OR c._id LIKE 't%' OR s._squareChatMid IS NOT NULL THEN '社群'
                           ELSE '其他'
                       END AS chat_category,
                       c._midType,
                       COUNT(m._id),
                       MIN(m._createdTime),
                       MAX(m._createdTime)
                FROM _chat AS c
                LEFT JOIN _contact AS ct ON ct._mid = c._id
                LEFT JOIN _buddyDetail AS bd ON bd._mid = c._id
                LEFT JOIN _groupChat AS g ON g._chatMid = c._id
                LEFT JOIN _squareChat AS s ON s._squareChatMid = c._id
                LEFT JOIN _message AS m ON m._chatId = c._id
                GROUP BY c._id
                ORDER BY MAX(c._lastUpdatedTime) DESC
                """
            )
            for name, chat_id, category, chat_type, count, oldest, newest in index_rows:
                writer.writerow([
                    excel_safe(name), chat_id, category, chat_type, count,
                    taipei_time(oldest), taipei_time(newest),
                ])

        messages_path = SCRIPT_DIR / "LINE_全部聊天.csv"
        count = 0
        with messages_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "聊天室名稱", "聊天室ID", "時間（台北）", "方向",
                "發言者", "發言者ID", "訊息類型", "內容", "訊息ID",
            ])
            message_rows = cursor.execute(
                """
                SELECT COALESCE(
                           NULLIF(g._chatName, ''),
                           NULLIF(chat_contact._displayNameOverridden, ''),
                           NULLIF(chat_contact._displayName, ''),
                           NULLIF(CASE WHEN json_valid(chat_contact._friendDetail) THEN json_extract(chat_contact._friendDetail, '$.user.overriddenName') END, ''),
                           NULLIF(CASE WHEN json_valid(chat_contact._targetProfileDetail) THEN json_extract(chat_contact._targetProfileDetail, '$.profileName') END, ''),
                           NULLIF(s._name, ''),
                           m._chatId
                       ) AS chat_name,
                       m._chatId,
                       m._createdTime,
                       m._from,
                       COALESCE(
                           NULLIF(sender._displayNameOverridden, ''),
                           NULLIF(sender._displayName, ''),
                           NULLIF(CASE WHEN json_valid(sender._friendDetail) THEN json_extract(sender._friendDetail, '$.user.overriddenName') END, ''),
                           NULLIF(CASE WHEN json_valid(sender._targetProfileDetail) THEN json_extract(sender._targetProfileDetail, '$.profileName') END, ''),
                           m._from
                       ) AS sender_name,
                       m._contentType,
                       m._text,
                       m._id
                FROM _message AS m
                LEFT JOIN _chat AS c ON c._id = m._chatId
                LEFT JOIN _contact AS chat_contact ON chat_contact._mid = c._id
                LEFT JOIN _groupChat AS g ON g._chatMid = c._id
                LEFT JOIN _squareChat AS s ON s._squareChatMid = c._id
                LEFT JOIN _contact AS sender ON sender._mid = m._from
                ORDER BY m._createdTime, m._id
                """
            )
            for chat_name, chat_id, created, sender_mid, sender_name, content_type, message_text, message_id in message_rows:
                direction = "傳出" if own_mid and sender_mid == own_mid else "收到"
                sender = "我" if direction == "傳出" else sender_name
                kind = "文字" if message_text else f"非文字（{content_type}）"
                writer.writerow([
                    excel_safe(chat_name), chat_id, taipei_time(created), direction,
                    excel_safe(sender), sender_mid, kind,
                    excel_safe(message_text), message_id,
                ])
                count += 1
        return messages_path, index_path, count
    finally:
        connection.close()


def main():
    print("正在尋找 LINE…")
    pids = find_line_processes()
    if not pids:
        raise RuntimeError("找不到 LINE.exe；請確認 LINE 桌面版已開啟並登入。")
    db_path, snapshot_dir = make_snapshot()
    try:
        marked = set()
        candidates = set()
        for pid in pids:
            process_marked, process_all = candidate_keys(pid)
            marked.update(process_marked)
            candidates.update(process_all)
        ordered = list(marked) + list(candidates - marked)
        print(
            f"找到 {len(marked)} 個標記候選、{len(candidates)} 個一般候選，"
            "正在直接驗證（不會顯示或儲存金鑰）…"
        )
        key = None
        settings = None
        for value in ordered:
            settings = opens_database(db_path, value)
            if settings is not None:
                key = value
                break
        if key is None:
            raise RuntimeError("未找到可用金鑰；請讓 LINE 保持登入並開啟任一聊天室後再試一次。")
        result = {
            "status": "ok",
            "database": db_path.name,
            "tables": inventory(db_path, key, settings),
        }
        output = SCRIPT_DIR / "line_inventory.json"
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        summary_output = SCRIPT_DIR / "line_chat_summary.json"
        summary_output.write_text(
            json.dumps(chat_summary(db_path, key, settings), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"完成：{output}")
        print(f"聊天摘要：{summary_output}")
        if len(sys.argv) >= 3 and sys.argv[1] in ("--export-chat", "--export-chat-id"):
            export_path, export_count = export_chat(db_path, key, settings, sys.argv[2])
            print(f"完整聊天：{export_path}（{export_count} 則）")
        elif len(sys.argv) >= 2 and sys.argv[1] == "--export-all":
            messages_path, index_path, export_count = export_all_chats(db_path, key, settings)
            print(f"全部聊天：{messages_path}（{export_count} 則）")
            print(f"聊天室索引：{index_path}")
    finally:
        shutil.rmtree(snapshot_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"失敗：{exc}")
        raise SystemExit(1)
