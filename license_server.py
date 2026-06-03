#!/usr/bin/env python3
"""
License Server — سيرفر التراخيص السحابي
يعمل على VPS/Cloud ويستقبل طلبات التحقق من البرنامج عند الزبائن
تشغيل: python license_server.py
"""

import sqlite3, json, os, time, random, string, hashlib, threading, webbrowser, secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════
#  إعدادات السيرفر
# ═══════════════════════════════════════════════
PORT        = int(os.environ.get("PORT", 7070))
DB_PATH     = Path(os.environ.get("DB_PATH", "licenses.db"))  # على Render: /data/licenses.db
API_SECRET  = os.environ.get("API_SECRET", "POS-SERVER-SECRET-2026")
# ↑ غيّر هذا أو اضبطه عبر متغير بيئة: export API_SECRET=xxxxx

# ═══════════════════════════════════════════════
#  قاعدة البيانات
# ═══════════════════════════════════════════════
def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS license (
            key          TEXT PRIMARY KEY,
            type         TEXT NOT NULL,
            duration     INTEGER NOT NULL DEFAULT 365,
            created_at   TEXT NOT NULL,
            activated_at TEXT DEFAULT NULL,
            expires_at   TEXT DEFAULT NULL,
            instance_id  TEXT DEFAULT NULL,
            note         TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS superadmin (
            id       INTEGER PRIMARY KEY,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS verify_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key         TEXT,
            instance_id TEXT,
            result      TEXT,
            ts          TEXT
        );
    """)
    # كلمة المرور الافتراضية (مخزّنة كـ SHA256)
    existing = conn.execute("SELECT COUNT(*) FROM superadmin").fetchone()[0]
    if existing == 0:
        conn.execute("INSERT INTO superadmin (password) VALUES (?)",
                     (sha256("SUPER2026"),))
    conn.commit()
    conn.close()
    print(f"  ✅ قاعدة البيانات: {DB_PATH.absolute()}")

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def today_str():
    return datetime.now().strftime("%Y-%m-%d")

def add_days(days: int) -> str:
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

# ═══════════════════════════════════════════════
#  منطق التراخيص
# ═══════════════════════════════════════════════
def verify_admin(password: str) -> bool:
    conn = get_conn()
    row = conn.execute("SELECT password FROM superadmin WHERE id=1").fetchone()
    conn.close()
    return row and row["password"] == sha256(password)

def generate_key() -> str:
    chars = (string.ascii_uppercase + string.digits).translate(
        str.maketrans("", "", "O0I1"))
    def part(): return ''.join(random.choices(chars, k=4))
    conn = get_conn()
    while True:
        key = f"{part()}-{part()}-{part()}-{part()}"
        if not conn.execute("SELECT 1 FROM license WHERE key=?", (key,)).fetchone():
            break
    conn.close()
    return key

def create_license(password: str, license_type: str, note: str):
    if not verify_admin(password):
        return {"error": "كلمة المرور غير صحيحة"}
    duration = {"trial": 7, "annual": 365, "lifetime": 0}.get(license_type, 7)
    key = generate_key()
    conn = get_conn()
    conn.execute(
        "INSERT INTO license (key, type, duration, created_at, note) VALUES (?,?,?,?,?)",
        (key, license_type, duration, today_str(), note)
    )
    conn.commit()
    conn.close()
    return {"key": key}

def list_licenses(password: str):
    if not verify_admin(password):
        return {"error": "كلمة المرور غير صحيحة"}
    conn = get_conn()
    rows = conn.execute(
        "SELECT key, type, duration, created_at, activated_at, "
        "expires_at, instance_id, note FROM license ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return {"licenses": [dict(r) for r in rows]}

def delete_license(password: str, key: str):
    if not verify_admin(password):
        return {"error": "كلمة المرور غير صحيحة"}
    conn = get_conn()
    conn.execute("DELETE FROM license WHERE key=?", (key,))
    conn.commit()
    conn.close()
    return {"ok": True}

def change_password(old_pass: str, new_pass: str):
    if not verify_admin(old_pass):
        return {"error": "كلمة المرور القديمة غير صحيحة"}
    if len(new_pass) < 4:
        return {"error": "كلمة المرور قصيرة جداً"}
    conn = get_conn()
    conn.execute("UPDATE superadmin SET password=? WHERE id=1", (sha256(new_pass),))
    conn.commit()
    conn.close()
    return {"ok": True}

def verify_license(key: str, instance_id: str, api_secret: str):
    """
    ← هذا الـ endpoint يستدعيه البرنامج عند الزبون
    يتحقق من الـ API_SECRET أولاً ثم من حالة الترخيص
    """
    # 1. تحقق من السر
    if api_secret != API_SECRET:
        return {"ok": False, "msg": "unauthorized"}

    conn = get_conn()

    # 2. هل المفتاح موجود؟
    row = conn.execute(
        "SELECT key, type, duration, activated_at, expires_at, instance_id "
        "FROM license WHERE key=?", (key,)
    ).fetchone()

    if not row:
        conn.execute("INSERT INTO verify_log (key,instance_id,result,ts) VALUES (?,?,?,?)",
                     (key, instance_id, "not_found", today_str()))
        conn.commit()
        conn.close()
        return {"ok": False, "msg": "المفتاح غير موجود"}

    row = dict(row)
    today = today_str()

    # 3. هل مفعّل على نسخة أخرى؟
    if row["instance_id"] and row["instance_id"] != instance_id:
        conn.execute("INSERT INTO verify_log (key,instance_id,result,ts) VALUES (?,?,?,?)",
                     (key, instance_id, "instance_mismatch", today))
        conn.commit()
        conn.close()
        return {"ok": False, "msg": "هذا المفتاح مُستخدم على جهاز آخر"}

    # 4. أول تفعيل؟
    if not row["activated_at"]:
        expires = add_days(row["duration"]) if row["duration"] > 0 else ""
        conn.execute(
            "UPDATE license SET activated_at=?, expires_at=?, instance_id=? WHERE key=?",
            (today, expires, instance_id, key)
        )
        row["activated_at"] = today
        row["expires_at"]   = expires
        row["instance_id"]  = instance_id

    # 5. منتهي الصلاحية؟
    if row["expires_at"] and row["expires_at"] < today:
        conn.execute("INSERT INTO verify_log (key,instance_id,result,ts) VALUES (?,?,?,?)",
                     (key, instance_id, "expired", today))
        conn.commit()
        conn.close()
        return {"ok": False, "msg": "انتهت صلاحية الترخيص", "expired": True}

    # 6. ✅ صالح
    days_left = -1
    if row["expires_at"]:
        d = datetime.strptime(row["expires_at"], "%Y-%m-%d") - datetime.now()
        days_left = max(0, d.days)

    conn.execute("INSERT INTO verify_log (key,instance_id,result,ts) VALUES (?,?,?,?)",
                 (key, instance_id, "ok", today))
    conn.commit()
    conn.close()

    return {
        "ok":         True,
        "type":       row["type"],
        "expires_at": row["expires_at"] or None,
        "days_left":  days_left
    }

def receive_analytics(data: dict, api_secret: str):
    """استقبال البيانات اليومية من البرنامج"""
    if api_secret != API_SECRET:
        return {"ok": False}
    # احفظ في ملف JSON أو قاعدة بيانات منفصلة
    log_file = Path("analytics.jsonl")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({**data, "ts": today_str()}, ensure_ascii=False) + "\n")
    return {"ok": True}

# ═══════════════════════════════════════════════
#  HTTP Handler
# ═══════════════════════════════════════════════
class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_html(HTML_PAGE)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length))
        except:
            self.send_json({"error": "JSON غير صالح"}, 400); return

        path = self.path.split("?")[0]

        # ── حالة قاعدة البيانات ──
        if path == "/api/status":
            self.send_json({
                "found": DB_PATH.exists(),
                "path":  str(DB_PATH.absolute())
            })

        # ── واجهة الإدارة ──
        elif path == "/api/login":
            pwd = data.get("password", "")
            self.send_json({"ok": True} if verify_admin(pwd)
                           else {"error": "كلمة المرور غير صحيحة"})

        elif path == "/api/licenses":
            self.send_json(list_licenses(data.get("password", "")))

        elif path == "/api/create":
            self.send_json(create_license(
                data.get("password", ""),
                data.get("type", "trial"),
                data.get("note", "")))

        elif path == "/api/delete":
            self.send_json(delete_license(
                data.get("password", ""),
                data.get("key", "")))

        elif path == "/api/change_pass":
            self.send_json(change_password(
                data.get("old_pass", ""),
                data.get("new_pass", "")))

        # ── واجهة البرنامج (الزبائن) ──
        elif path == "/api/verify":
            self.send_json(verify_license(
                data.get("key", ""),
                data.get("instance_id", ""),
                data.get("secret", "")))

        elif path == "/api/analytics":
            self.send_json(receive_analytics(
                data.get("data", {}),
                data.get("secret", "")))

        else:
            self.send_json({"error": "مسار غير موجود"}, 404)


HTML_PAGE = '''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SuperAdmin — إدارة التراخيص</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Tajawal:wght@300;400;500;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #070a0f;
  --surface:  #0e1318;
  --border:   #1c2530;
  --border2:  #243040;
  --text:     #c8d8e8;
  --muted:    #4a6070;
  --accent:   #00d4ff;
  --green:    #00e676;
  --orange:   #ff9800;
  --red:      #ff4444;
  --blue:     #448aff;
  --glow:     rgba(0,212,255,0.15);
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
  font-family: 'Tajawal', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

/* ══ شبكة خلفية ══ */
body::before {
  content:'';
  position:fixed; inset:0;
  background-image:
    linear-gradient(var(--border) 1px, transparent 1px),
    linear-gradient(90deg, var(--border) 1px, transparent 1px);
  background-size: 40px 40px;
  opacity: 0.4;
  pointer-events:none;
  z-index:0;
}

/* ══ صفحة اللوجين ══ */
#loginScreen {
  position: relative;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}

.login-wrap {
  width: 420px;
}

.login-header {
  text-align: center;
  margin-bottom: 40px;
}

.login-icon {
  width: 72px; height: 72px;
  background: linear-gradient(135deg, #0e1318, #1a2535);
  border: 1px solid var(--accent);
  border-radius: 18px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 32px;
  margin-bottom: 20px;
  box-shadow: 0 0 30px var(--glow), inset 0 1px 0 rgba(0,212,255,0.1);
  animation: pulse-glow 3s ease-in-out infinite;
}

@keyframes pulse-glow {
  0%,100% { box-shadow: 0 0 20px var(--glow); }
  50%      { box-shadow: 0 0 50px rgba(0,212,255,0.3); }
}

.login-header h1 {
  font-size: 26px; font-weight: 900;
  letter-spacing: -0.5px;
  background: linear-gradient(135deg, #fff 30%, var(--accent));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}

.login-header p {
  color: var(--muted); font-size: 14px; margin-top: 6px;
}

.card {
  background: var(--surface);
  border: 1px solid var(--border2);
  border-radius: 16px;
  padding: 32px;
  position: relative;
  overflow: hidden;
}

.card::before {
  content:'';
  position:absolute; top:0; left:0; right:0; height:1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0.5;
}

/* DB status banner */
.db-banner {
  padding: 12px 16px;
  border-radius: 10px;
  font-size: 13px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.db-banner.ok  { background: rgba(0,230,118,0.08); border:1px solid rgba(0,230,118,0.2); color: var(--green); }
.db-banner.err { background: rgba(255,68,68,0.08); border:1px solid rgba(255,68,68,0.2); color: var(--red); }
.db-path { font-family:'IBM Plex Mono',monospace; font-size:11px; opacity:0.7; direction:ltr; word-break:break-all; }

.field { margin-bottom: 16px; }
.field label { display:block; font-size:12px; color:var(--muted); margin-bottom:8px; font-weight:500; letter-spacing:.5px; text-transform:uppercase; }
.field input {
  width:100%;
  background: var(--bg);
  border: 1px solid var(--border2);
  border-radius: 10px;
  padding: 12px 16px;
  color: var(--text);
  font-size: 15px;
  font-family: 'Tajawal', sans-serif;
  outline: none;
  transition: border-color .2s, box-shadow .2s;
}
.field input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(0,212,255,0.1);
}

.btn-primary {
  width: 100%;
  background: linear-gradient(135deg, #0099bb, #0066dd);
  border: none;
  border-radius: 10px;
  color: #fff;
  padding: 13px;
  font-size: 15px;
  font-weight: 700;
  font-family: 'Tajawal', sans-serif;
  cursor: pointer;
  transition: all .2s;
  position: relative;
  overflow: hidden;
}
.btn-primary::after {
  content:'';
  position:absolute; inset:0;
  background: linear-gradient(135deg, rgba(255,255,255,0.1), transparent);
  opacity:0;
  transition: opacity .2s;
}
.btn-primary:hover::after { opacity:1; }
.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(0,150,255,0.3); }
.btn-primary:active { transform: translateY(0); }

.err-msg { color: var(--red); font-size: 13px; text-align:center; margin-top:12px; min-height:20px; }

/* ══ الشاشة الرئيسية ══ */
#mainScreen { display:none; position:relative; z-index:10; }

.topbar {
  background: rgba(14,19,24,0.95);
  backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border2);
  padding: 0 32px;
  height: 58px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky; top:0; z-index:100;
}

.topbar-brand {
  display:flex; align-items:center; gap:12px;
}
.topbar-brand .dot {
  width:8px; height:8px; border-radius:50%;
  background: var(--green);
  box-shadow: 0 0 8px var(--green);
  animation: blink 2s ease-in-out infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }
.topbar-brand span { font-size:15px; font-weight:700; color: var(--accent); }

.topbar-actions { display:flex; align-items:center; gap:10px; }
.btn-sm {
  background: none;
  border: 1px solid var(--border2);
  border-radius: 8px;
  color: var(--muted);
  padding: 6px 14px;
  font-size: 12px;
  font-family:'Tajawal',sans-serif;
  cursor:pointer;
  transition: all .2s;
  font-weight:500;
}
.btn-sm:hover { border-color: var(--red); color: var(--red); }

.main-content { padding: 28px 32px; max-width: 1300px; margin: 0 auto; }

/* ══ إحصائيات ══ */
.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 28px;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border2);
  border-radius: 14px;
  padding: 20px 22px;
  position: relative;
  overflow: hidden;
  transition: border-color .2s;
}
.stat:hover { border-color: var(--border); }
.stat::after {
  content: attr(data-icon);
  position:absolute; left:16px; top:50%;
  transform: translateY(-50%);
  font-size: 36px; opacity: 0.06;
}
.stat .num { font-size: 32px; font-weight:900; line-height:1; margin-bottom:6px; font-family:'IBM Plex Mono',monospace; }
.stat .lbl { font-size: 12px; color: var(--muted); font-weight:500; text-transform:uppercase; letter-spacing:.5px; }
.stat.s-total  .num { color: var(--text); }
.stat.s-trial  .num { color: var(--orange); }
.stat.s-annual .num { color: var(--blue); }
.stat.s-life   .num { color: var(--green); }

/* ══ بطاقات ══ */
.panel {
  background: var(--surface);
  border: 1px solid var(--border2);
  border-radius: 16px;
  padding: 26px 28px;
  margin-bottom: 22px;
}
.panel-title {
  font-size:14px; font-weight:700; color:var(--accent);
  text-transform:uppercase; letter-spacing:1px;
  margin-bottom: 22px;
  display:flex; align-items:center; gap:8px;
}
.panel-title::before {
  content:'';
  display:block; width:3px; height:16px;
  background: var(--accent);
  border-radius: 2px;
}

/* ══ توليد مفتاح ══ */
.gen-grid {
  display: grid;
  grid-template-columns: 1fr 1fr auto;
  gap: 14px;
  align-items: end;
}
.field-inline label { display:block; font-size:12px; color:var(--muted); margin-bottom:7px; font-weight:500; }
.field-inline select, .field-inline input {
  width:100%;
  background: var(--bg);
  border: 1px solid var(--border2);
  border-radius: 10px;
  padding: 11px 14px;
  color: var(--text);
  font-size: 14px;
  font-family:'Tajawal',sans-serif;
  outline:none;
  transition: border-color .2s;
}
.field-inline select:focus, .field-inline input:focus { border-color:var(--accent); }

.btn-gen {
  background: linear-gradient(135deg, #00b890, #006644);
  border:none; border-radius:10px;
  color:#fff; padding:11px 26px;
  font-size:14px; font-weight:700;
  font-family:'Tajawal',sans-serif;
  cursor:pointer; white-space:nowrap;
  transition: all .2s;
}
.btn-gen:hover { transform:translateY(-1px); box-shadow:0 6px 20px rgba(0,200,120,0.25); }

/* ══ نتيجة المفتاح ══ */
.result-box {
  display:none;
  margin-top: 18px;
  background: linear-gradient(135deg, rgba(0,230,118,0.05), transparent);
  border: 1px solid rgba(0,230,118,0.25);
  border-radius: 12px;
  padding: 18px 22px;
  align-items:center; gap:16px;
}
.result-box.show { display:flex; animation: slide-in .3s ease; }
@keyframes slide-in { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:translateY(0)} }
.result-key {
  font-family:'IBM Plex Mono',monospace;
  font-size:24px; font-weight:600;
  color: var(--green);
  letter-spacing: 5px;
  direction:ltr; flex:1;
}
.btn-copy {
  background: var(--bg); border:1px solid var(--border2);
  color:var(--muted); border-radius:8px;
  padding:8px 18px; font-size:13px;
  font-family:'Tajawal',sans-serif;
  cursor:pointer; transition:all .2s;
  white-space:nowrap;
}
.btn-copy:hover { border-color:var(--accent); color:var(--accent); }
.btn-copy.copied { border-color:var(--green); color:var(--green); }

/* ══ جدول ══ */
.search-bar {
  display:flex; align-items:center; gap:12px;
  margin-bottom:16px;
}
.search-bar input {
  background:var(--bg); border:1px solid var(--border2);
  border-radius:10px; padding:9px 14px;
  color:var(--text); font-size:13px;
  font-family:'Tajawal',sans-serif;
  outline:none; width:280px;
}
.search-bar input:focus { border-color:var(--accent); }
.btn-refresh {
  background:none; border:1px solid var(--border2);
  border-radius:8px; color:var(--muted);
  padding:8px 14px; font-size:13px;
  font-family:'Tajawal',sans-serif;
  cursor:pointer; transition:all .2s;
  margin-right:auto;
}
.btn-refresh:hover { border-color:var(--accent); color:var(--accent); }

.tbl-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th {
  background: rgba(0,0,0,0.3);
  padding:10px 14px; text-align:right;
  color:var(--muted); border-bottom:1px solid var(--border2);
  font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px;
  white-space:nowrap;
}
td {
  padding:12px 14px;
  border-bottom:1px solid var(--border);
  vertical-align:middle;
}
tr:last-child td { border-bottom:none; }
tr:hover td { background: rgba(255,255,255,0.02); }

.key-val {
  font-family:'IBM Plex Mono',monospace;
  font-size:13px; color:#79c0ff;
  direction:ltr; text-align:left;
  letter-spacing:1px;
}

.badge {
  display:inline-block; padding:3px 10px;
  border-radius:20px; font-size:11px; font-weight:700;
  white-space:nowrap;
}
.b-trial    { background:rgba(255,152,0,.12); color:#ff9800; }
.b-annual   { background:rgba(68,138,255,.12); color:#448aff; }
.b-lifetime { background:rgba(0,230,118,.12); color:#00e676; }
.b-active   { background:rgba(0,230,118,.1);  color:#00e676; }
.b-waiting  { background:rgba(100,120,140,.1);color:#6a8090; }
.b-expired  { background:rgba(255,68,68,.1);  color:#ff4444; }

.btn-del {
  background:none; border:1px solid var(--border2);
  color:var(--muted); border-radius:6px;
  padding:4px 10px; font-size:12px;
  cursor:pointer; transition:all .2s;
}
.btn-del:hover { border-color:var(--red); color:var(--red); }

.empty-row td {
  text-align:center; color:var(--muted);
  padding:40px; font-size:14px;
}

/* ══ تغيير كلمة المرور ══ */
.pass-grid {
  display:grid; grid-template-columns:1fr 1fr auto;
  gap:14px; align-items:end;
}

/* ══ Toast ══ */
.toast {
  position:fixed; bottom:28px; left:50%; transform:translateX(-50%);
  background: rgba(0,230,118,0.15);
  border:1px solid rgba(0,230,118,0.4);
  color: var(--green);
  padding:12px 28px; border-radius:12px;
  font-size:14px; font-weight:600;
  opacity:0; transition:opacity .3s;
  pointer-events:none; z-index:9999;
  backdrop-filter:blur(10px);
  white-space:nowrap;
}
.toast.err {
  background:rgba(255,68,68,0.15);
  border-color:rgba(255,68,68,0.4);
  color:var(--red);
}
.toast.show { opacity:1; }

/* ══ نافذة تأكيد الحذف ══ */
.overlay {
  position:fixed; inset:0;
  background:rgba(0,0,0,0.7); backdrop-filter:blur(4px);
  z-index:1000; display:none;
  align-items:center; justify-content:center;
}
.overlay.show { display:flex; }
.confirm-box {
  background:var(--surface); border:1px solid var(--border2);
  border-radius:16px; padding:32px; width:380px; text-align:center;
}
.confirm-box h3 { font-size:16px; margin-bottom:10px; }
.confirm-box p  { font-size:13px; color:var(--muted); margin-bottom:24px; }
.confirm-key { font-family:'IBM Plex Mono',monospace; color:var(--red); font-size:15px; }
.confirm-btns { display:flex; gap:10px; justify-content:center; }
.btn-cancel { background:none; border:1px solid var(--border2); color:var(--muted); border-radius:8px; padding:9px 22px; font-family:'Tajawal',sans-serif; cursor:pointer; font-size:14px; }
.btn-del-confirm { background:rgba(255,68,68,0.1); border:1px solid rgba(255,68,68,.3); color:var(--red); border-radius:8px; padding:9px 22px; font-family:'Tajawal',sans-serif; cursor:pointer; font-size:14px; font-weight:700; }
.btn-del-confirm:hover { background:rgba(255,68,68,0.2); }
</style>
</head>
<body>

<!-- ══ LOGIN ══ -->
<div id="loginScreen">
  <div class="login-wrap">
    <div class="login-header">
      <div class="login-icon">🛡️</div>
      <h1>لوحة SuperAdmin</h1>
      <p>أداة إدارة التراخيص المستقلة</p>
    </div>
    <div class="card">
      <div id="dbBanner" class="db-banner">
        <span id="dbIcon">⏳</span>
        <div>
          <div id="dbMsg">جاري التحقق من قاعدة البيانات...</div>
          <div class="db-path" id="dbPath"></div>
        </div>
      </div>
      <div class="field">
        <label>كلمة مرور SuperAdmin</label>
        <input type="password" id="loginPass" placeholder="••••••••" autocomplete="off">
      </div>
      <button class="btn-primary" onclick="doLogin()">دخول ←</button>
      <div class="err-msg" id="loginErr"></div>
    </div>
  </div>
</div>

<!-- ══ MAIN ══ -->
<div id="mainScreen">
  <div class="topbar">
    <div class="topbar-brand">
      <div class="dot"></div>
      <span>SuperAdmin — إدارة التراخيص</span>
    </div>
    <div class="topbar-actions">
      <span style="font-size:12px;color:var(--muted)" id="topDbPath"></span>
      <button class="btn-sm" onclick="doLogout()">تسجيل خروج</button>
    </div>
  </div>

  <div class="main-content">

    <!-- إحصائيات -->
    <div class="stats">
      <div class="stat s-total" data-icon="🗝">
        <div class="num" id="stTotal">0</div>
        <div class="lbl">إجمالي المفاتيح</div>
      </div>
      <div class="stat s-trial" data-icon="🕐">
        <div class="num" id="stTrial">0</div>
        <div class="lbl">تجربة</div>
      </div>
      <div class="stat s-annual" data-icon="📅">
        <div class="num" id="stAnnual">0</div>
        <div class="lbl">سنوي</div>
      </div>
      <div class="stat s-life" data-icon="♾">
        <div class="num" id="stLife">0</div>
        <div class="lbl">مدى الحياة</div>
      </div>
    </div>

    <!-- توليد مفتاح -->
    <div class="panel">
      <div class="panel-title">توليد مفتاح جديد</div>
      <div class="gen-grid">
        <div class="field-inline">
          <label>نوع الترخيص</label>
          <select id="genType">
            <option value="trial">🕐 تجربة — 7 أيام</option>
            <option value="annual">📅 سنوي — 365 يوم</option>
            <option value="lifetime">♾️ مدى الحياة</option>
          </select>
        </div>
        <div class="field-inline">
          <label>ملاحظة (اسم الزبون)</label>
          <input type="text" id="genNote" placeholder="مثال: متجر الأمل" onkeydown="if(event.key==='Enter')generateKey()">
        </div>
        <button class="btn-gen" onclick="generateKey()">⚡ توليد مفتاح</button>
      </div>
      <div class="result-box" id="resultBox">
        <div style="flex:1">
          <div style="font-size:11px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">المفتاح الجديد</div>
          <div class="result-key" id="resultKey">----</div>
        </div>
        <button class="btn-copy" id="btnCopy" onclick="copyKey()">📋 نسخ</button>
      </div>
    </div>

    <!-- قائمة المفاتيح -->
    <div class="panel">
      <div class="panel-title" style="justify-content:space-between">
        <span style="display:flex;align-items:center;gap:8px">
          <span style="width:3px;height:16px;background:var(--accent);border-radius:2px;display:block"></span>
          قائمة المفاتيح
        </span>
        <button class="btn-refresh" onclick="loadLicenses()">🔄 تحديث</button>
      </div>
      <div class="search-bar">
        <input type="text" id="searchInput" placeholder="🔍 بحث بالمفتاح أو الملاحظة..." oninput="filterTable()">
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>المفتاح</th>
              <th>النوع</th>
              <th>الحالة</th>
              <th>الإنشاء</th>
              <th>التفعيل</th>
              <th>الانتهاء</th>
              <th>معرّف الجهاز</th>
              <th>ملاحظة</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="tbody">
            <tr class="empty-row"><td colspan="9">⏳ جاري التحميل...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- تغيير كلمة المرور -->
    <div class="panel">
      <div class="panel-title">تغيير كلمة مرور SuperAdmin</div>
      <div class="pass-grid">
        <div class="field-inline">
          <label>كلمة المرور الحالية</label>
          <input type="password" id="oldPass" placeholder="••••••••">
        </div>
        <div class="field-inline">
          <label>كلمة المرور الجديدة</label>
          <input type="password" id="newPass" placeholder="••••••••">
        </div>
        <button class="btn-gen" style="background:linear-gradient(135deg,#1a6ecc,#0044aa)" onclick="changePass()">حفظ</button>
      </div>
    </div>

  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<!-- نافذة تأكيد الحذف -->
<div class="overlay" id="deleteOverlay">
  <div class="confirm-box">
    <h3>🗑 تأكيد الحذف</h3>
    <p>هل أنت متأكد من حذف المفتاح:<br><span class="confirm-key" id="confirmKey"></span></p>
    <div class="confirm-btns">
      <button class="btn-cancel" onclick="closeDelete()">إلغاء</button>
      <button class="btn-del-confirm" onclick="confirmDelete()">حذف نهائياً</button>
    </div>
  </div>
</div>

<script>
const API = '';
let adminPass = '';
let allLicenses = [];
let pendingDeleteKey = '';

// ── تحقق من قاعدة البيانات عند التحميل
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const r = await fetch(API + '/api/status', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    const d = await r.json();
    const banner = document.getElementById('dbBanner');
    document.getElementById('dbPath').textContent = d.path || '';
    if (d.found) {
      banner.className = 'db-banner ok';
      document.getElementById('dbIcon').textContent = '✅';
      document.getElementById('dbMsg').textContent = 'قاعدة البيانات موجودة';
      document.getElementById('topDbPath').textContent = d.path;
    } else {
      banner.className = 'db-banner err';
      document.getElementById('dbIcon').textContent = '❌';
      document.getElementById('dbMsg').textContent = 'لم يُعثر على قاعدة البيانات — شغّل التطبيق أولاً';
    }
  } catch(e) {
    console.error(e);
  }
  document.getElementById('loginPass').focus();
});

document.getElementById('loginPass').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

async function doLogin() {
  const pass = document.getElementById('loginPass').value.trim();
  if (!pass) return;
  const errEl = document.getElementById('loginErr');
  try {
    const r = await api('/api/login', { password: pass });
    if (r.ok) {
      adminPass = pass;
      document.getElementById('loginScreen').style.display = 'none';
      document.getElementById('mainScreen').style.display = 'block';
      loadLicenses();
    } else {
      errEl.textContent = '⛔ ' + (r.error || 'كلمة المرور غير صحيحة');
    }
  } catch(e) {
    errEl.textContent = '⛔ خطأ في الاتصال بالسيرفر';
  }
}

function doLogout() {
  adminPass = '';
  document.getElementById('loginPass').value = '';
  document.getElementById('loginErr').textContent = '';
  document.getElementById('mainScreen').style.display = 'none';
  document.getElementById('loginScreen').style.display = 'flex';
}

async function generateKey() {
  const type = document.getElementById('genType').value;
  const note = document.getElementById('genNote').value.trim();
  const r = await api('/api/create', { password: adminPass, type, note });
  if (r.key) {
    document.getElementById('resultKey').textContent = r.key;
    document.getElementById('resultBox').classList.add('show');
    document.getElementById('btnCopy').textContent = '📋 نسخ';
    document.getElementById('btnCopy').classList.remove('copied');
    document.getElementById('genNote').value = '';
    loadLicenses();
    showToast('✅ تم إنشاء المفتاح بنجاح');
  } else {
    showToast('⛔ ' + (r.error || 'فشل'), true);
  }
}

function copyKey() {
  const key = document.getElementById('resultKey').textContent;
  navigator.clipboard.writeText(key).then(() => {
    const btn = document.getElementById('btnCopy');
    btn.textContent = '✅ تم النسخ';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '📋 نسخ'; btn.classList.remove('copied'); }, 2000);
  });
}

async function loadLicenses() {
  const r = await api('/api/licenses', { password: adminPass });
  if (r.licenses) {
    allLicenses = r.licenses;
    updateStats(r.licenses);
    renderTable(r.licenses);
  }
}

function updateStats(list) {
  document.getElementById('stTotal').textContent  = list.length;
  document.getElementById('stTrial').textContent  = list.filter(l=>l.type==='trial').length;
  document.getElementById('stAnnual').textContent = list.filter(l=>l.type==='annual').length;
  document.getElementById('stLife').textContent   = list.filter(l=>l.type==='lifetime').length;
}

function getStatus(l) {
  const today = new Date().toISOString().split('T')[0];
  if (!l.activated_at) return '<span class="badge b-waiting">لم يُفعَّل</span>';
  if (l.expires_at && l.expires_at < today) return '<span class="badge b-expired">منتهي</span>';
  return '<span class="badge b-active">نشط ✓</span>';
}
function getTypeBadge(t) {
  return {trial:'<span class="badge b-trial">تجربة</span>', annual:'<span class="badge b-annual">سنوي</span>', lifetime:'<span class="badge b-lifetime">مدى الحياة</span>'}[t] || t;
}

function renderTable(list) {
  const tb = document.getElementById('tbody');
  if (!list.length) {
    tb.innerHTML = '<tr class="empty-row"><td colspan="9">لا توجد مفاتيح بعد</td></tr>';
    return;
  }
  tb.innerHTML = list.map(l => `
    <tr>
      <td class="key-val">${l.key}</td>
      <td>${getTypeBadge(l.type)}</td>
      <td>${getStatus(l)}</td>
      <td style="color:var(--muted);font-size:12px">${l.created_at||'—'}</td>
      <td style="color:var(--muted);font-size:12px">${l.activated_at||'—'}</td>
      <td style="color:var(--muted);font-size:12px">${l.expires_at||(l.type==='lifetime'?'♾️':'—')}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);direction:ltr;text-align:left">${(l.instance_id||'').substring(0,14)||'—'}</td>
      <td style="color:var(--muted);font-size:13px">${l.note||'—'}</td>
      <td><button class="btn-del" onclick="askDelete('${l.key}')">🗑</button></td>
    </tr>
  `).join('');
}

function filterTable() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  if (!q) { renderTable(allLicenses); return; }
  renderTable(allLicenses.filter(l => l.key.toLowerCase().includes(q) || (l.note||'').toLowerCase().includes(q)));
}

function askDelete(key) {
  pendingDeleteKey = key;
  document.getElementById('confirmKey').textContent = key;
  document.getElementById('deleteOverlay').classList.add('show');
}
function closeDelete() {
  pendingDeleteKey = '';
  document.getElementById('deleteOverlay').classList.remove('show');
}
async function confirmDelete() {
  const r = await api('/api/delete', { password: adminPass, key: pendingDeleteKey });
  closeDelete();
  if (r.ok) { showToast('🗑 تم حذف المفتاح'); loadLicenses(); }
  else showToast('⛔ ' + (r.error||'فشل الحذف'), true);
}

async function changePass() {
  const old = document.getElementById('oldPass').value;
  const n   = document.getElementById('newPass').value;
  if (!old || !n) { showToast('⛔ أدخل كلمة المرور الحالية والجديدة', true); return; }
  const r = await api('/api/change_pass', { old_pass: old, new_pass: n });
  if (r.ok) {
    adminPass = n;
    document.getElementById('oldPass').value = '';
    document.getElementById('newPass').value = '';
    showToast('✅ تم تغيير كلمة المرور');
  } else {
    showToast('⛔ ' + (r.error||'فشل'), true);
  }
}

async function api(path, data) {
  try {
    const r = await fetch(API + path, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(data)
    });
    return await r.json();
  } catch(e) {
    return { error: 'خطأ في الاتصال' };
  }
}

function showToast(msg, isErr=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isErr?' err':'') + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}
</script>
</body>
</html>
'''


# ═══════════════════════════════════════════════
#  تشغيل السيرفر
# ═══════════════════════════════════════════════

def main():
    init_db()
    print("=" * 58)
    print("  🛡️  License Server — سيرفر التراخيص")
    print("=" * 58)
    print(f"  🌐 لوحة الإدارة : http://localhost:{PORT}")
    print(f"  🔑 كلمة المرور  : SUPER2026  (غيّرها فوراً)")
    print(f"  🔐 API Secret   : {API_SECRET}")
    print()
    print("  Endpoints للبرنامج (POST):")
    print(f"    /api/verify    ← تحقق من الترخيص")
    print(f"    /api/analytics ← استقبال بيانات يومية")
    print("=" * 58)
    print("  اضغط Ctrl+C لإيقاف السيرفر")

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⏹ تم إيقاف السيرفر.")
        server.server_close()

if __name__ == "__main__":
    main()
