# app.py — Recon AI for Render
# pip install -r requirements.txt
# ENV: ADMIN_PASSWORD (обязательно), SECRET_KEY (обязательно)
import json, socket, ssl, whois, dns.resolver, requests, io, os, threading, sys
from datetime import date, datetime
from functools import wraps
from flask import (Flask, request, jsonify, render_template_string, send_file,
                   session, redirect, url_for)
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# ENV CONFIG — без дефолтов для секретов
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
SECRET_KEY = os.environ.get("SECRET_KEY")

if not ADMIN_PASSWORD:
    print("[FATAL] ADMIN_PASSWORD не задан в Environment.", file=sys.stderr)
    sys.exit(1)
if not SECRET_KEY:
    print("[FATAL] SECRET_KEY не задан в Environment.", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)
app.secret_key = SECRET_KEY

DB_FILE = os.environ.get("DB_FILE", "recon_db.json")
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "30"))
LOCK = threading.Lock()

# ============================================================
# STORAGE (dict-based)
# ============================================================
DB = {"users": {}, "usage": {}, "logs": [], "next_uid": 1, "next_log_id": 1}

def save_db():
    with LOCK:
        data = {
            "users": {str(k): v for k, v in DB["users"].items()},
            "usage": [{"uid": k[0], "day": k[1], "count": v} for k, v in DB["usage"].items()],
            "logs": DB["logs"],
            "next_uid": DB["next_uid"],
            "next_log_id": DB["next_log_id"],
        }
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

def load_db():
    global DB
    if not os.path.exists(DB_FILE):
        DB["users"][1] = {
            "id": 1, "username": "admin",
            "password_hash": generate_password_hash(ADMIN_PASSWORD),
            "role": "admin", "created_at": datetime.utcnow().isoformat(),
            "last_ip": None, "suspected_multi": 0, "banned": 0, "ban_reason": None,
        }
        DB["next_uid"] = 2
        save_db()
        return
    with open(DB_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    DB["users"] = {int(k): v for k, v in data["users"].items()}
    DB["usage"] = {(item["uid"], item["day"]): item["count"] for item in data["usage"]}
    DB["logs"] = data["logs"]
    DB["next_uid"] = data["next_uid"]
    DB["next_log_id"] = data["next_log_id"]

def find_user_by_username(username):
    for u in DB["users"].values():
        if u["username"] == username: return u
    return None

def get_user(uid): return DB["users"].get(uid)

def add_user(username, password, ip):
    with LOCK:
        same_ip = sum(1 for u in DB["users"].values() if u.get("last_ip") == ip)
        uid = DB["next_uid"]; DB["next_uid"] += 1
        DB["users"][uid] = {
            "id": uid, "username": username,
            "password_hash": generate_password_hash(password),
            "role": "user", "created_at": datetime.utcnow().isoformat(),
            "last_ip": ip, "suspected_multi": 1 if same_ip > 0 else 0,
            "banned": 0, "ban_reason": None,
        }
    save_db()
    return DB["users"][uid]

def log_action(user_id, action, detail="", ip=None):
    with LOCK:
        DB["logs"].append({"id": DB["next_log_id"], "user_id": user_id, "action": action,
                           "detail": detail, "ip": ip or "?", "ts": datetime.utcnow().isoformat()})
        DB["next_log_id"] += 1
        if len(DB["logs"]) > 500: DB["logs"] = DB["logs"][-500:]
    save_db()

def today(): return date.today().isoformat()
def get_usage(uid): return DB["usage"].get((uid, today()), 0)
def inc_usage(uid):
    with LOCK:
        key = (uid, today()); DB["usage"][key] = DB["usage"].get(key, 0) + 1
    save_db()

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff: return xff.split(",")[0].strip()
    return request.remote_addr or "?"

# ============================================================
# AUTH
# ============================================================
def current_user():
    uid = session.get("uid")
    return get_user(uid) if uid else None

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not current_user(): return redirect(url_for("login_page"))
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        u = current_user()
        if not u or u["role"] != "admin": return "403 — только админ", 403
        return f(*a, **kw)
    return w

# ============================================================
# OSINT CHECKS
# ============================================================
CHECKS = {}
def check(name, label):
    def deco(fn):
        CHECKS[name] = {"fn": fn, "label": label}; return fn
    return deco

def safe(fn):
    def wrapper(target):
        try: return fn(target)
        except Exception as e: return {"error": str(e)}
    return wrapper

@check("whois","WHOIS")
@safe
def c_whois(d):
    w = whois.whois(d)
    keep = ["domain_name","registrar","creation_date","expiration_date","updated_date",
            "name_servers","status","emails","org","country"]
    return {k: str(w.get(k)) if w.get(k) else None for k in keep}

@check("dns","DNS records")
@safe
def c_dns(d):
    out = {}
    for t in ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","DS","DNSKEY"]:
        try: out[t] = [r.to_text() for r in dns.resolver.resolve(d,t)]
        except Exception: out[t] = []
    try: out["DMARC"] = [r.to_text() for r in dns.resolver.resolve(f"_dmarc.{d}","TXT")]
    except Exception: out["DMARC"] = []
    out["DKIM"] = {}
    for sel in ["default","google","selector1","selector2","k1","s1","mail","dkim"]:
        try: out["DKIM"][sel] = [r.to_text() for r in dns.resolver.resolve(f"{sel}._domainkey.{d}","TXT")]
        except Exception: pass
    return out

@check("ip","IP / Geo / ASN")
@safe
def c_ip(d):
    r = requests.get(f"http://ip-api.com/json/{d}?fields=status,country,regionName,city,isp,org,as,query", timeout=10)
    return r.json()

@check("asn","ASN info")
@safe
def c_asn(d):
    r = requests.get(f"https://api.hackertarget.com/aslookup/?q={d}", timeout=10)
    return r.text[:1000]

@check("ssl","SSL certificate")
@safe
def c_ssl(d):
    host = d.replace("https://","").replace("http://","").split("/")[0]
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.settimeout(10); s.connect((host,443)); cert = s.getpeercert()
    subj = dict(x[0] for x in cert.get("subject",[]))
    iss = dict(x[0] for x in cert.get("issuer",[]))
    return {"subject":subj,"issuer":iss,"notBefore":cert.get("notBefore"),
            "notAfter":cert.get("notAfter"),"SAN":[v for k,v in cert.get("subjectAltName",[])][:30]}

@check("headers","HTTP headers + security")
@safe
def c_headers(d):
    url = d if d.startswith("http") else f"https://{d}"
    r = requests.get(url, timeout=15, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
    h = dict(r.headers)
    sec = {k:h.get(k,"MISSING") for k in ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]}
    return {"status":r.status_code,"final_url":r.url,"server":h.get("Server"),
            "powered_by":h.get("X-Powered-By"),"security_headers":sec,"all_headers":h}

@check("tech","Tech stack")
@safe
def c_tech(d):
    url = d if d.startswith("http") else f"https://{d}"
    r = requests.get(url, timeout=15, headers={"User-Agent":"Mozilla/5.0"})
    h, html = r.headers, r.text.lower()
    tech = {}
    if h.get("Server"): tech["server"]=h["Server"]
    if h.get("X-Powered-By"): tech["powered_by"]=h["X-Powered-By"]
    for k,v in [("cf-ray","cloudflare"),("x-vercel","vercel"),("x-nextjs","nextjs"),("x-github","github_pages")]:
        if k in h: tech[v]=True
    for k in ["wp-content","react","vue","jquery","bootstrap"]:
        if k in html: tech[k]=True
    return tech

@check("robots","robots.txt")
@safe
def c_robots(d):
    r = requests.get(f"https://{d}/robots.txt", timeout=10)
    return r.text[:3000] if r.status_code==200 else "not found"

@check("sitemap","sitemap.xml")
@safe
def c_sitemap(d):
    r = requests.get(f"https://{d}/sitemap.xml", timeout=10)
    return r.text[:3000] if r.status_code==200 else "not found"

@check("subs","Subdomains")
@safe
def c_subs(d):
    found=set()
    for url, parser in [
        (f"https://crt.sh/?q=%25.{d}&output=json", lambda r: [n.strip().lower() for it in r.json() for n in it.get("name_value","").split("\n") if n.strip()]),
        (f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", lambda r: [it.get("hostname","").strip().lower() for it in r.json().get("passive_dns",[]) if it.get("hostname")]),
        (f"https://api.threatminer.org/v2/domain.php?q={d}&rt=5", lambda r: [h.strip().lower() for h in r.json().get("results",[])]),
        (f"https://anubisdb.com/anubis/subdomains/{d}", lambda r: [h.strip().lower() for h in r.json()]),
        (f"https://api.hackertarget.com/hostsearch/?q={d}", lambda r: [l.split(",")[0].strip().lower() for l in r.text.splitlines() if "," in l]),
    ]:
        try:
            r = requests.get(url, timeout=20, headers={"User-Agent":"Mozilla/5.0"})
            for n in parser(r):
                if n and "*" not in n: found.add(n)
        except Exception: pass
    return sorted(found)[:300]

@check("wayback","Wayback Machine")
@safe
def c_wayback(d):
    r = requests.get(f"http://web.archive.org/cdx/search/cdx?url={d}&output=json&limit=30&fl=timestamp,original,statuscode", timeout=20)
    try: return r.json()
    except Exception: return {"error":"non-json"}

@check("ports","Common ports")
@safe
def c_ports(d):
    host = socket.gethostbyname(d)
    common=[21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017]
    open_ports=[]
    for p in common:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(1.2)
        try:
            if s.connect_ex((host,p))==0: open_ports.append(p)
        except Exception: pass
        finally: s.close()
    return open_ports

@check("netapi","NetAPI compromised")
@safe
def c_netapi(d):
    r = requests.get(f"https://netapi.com/api-json/?method=compromised-check&value={d}", timeout=15)
    return r.json()

@check("urlscan","URLScan.io")
@safe
def c_urlscan(d):
    r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=5", timeout=20)
    return [{"url":x.get("page",{}).get("url"),"ip":x.get("page",{}).get("ip"),
             "server":x.get("page",{}).get("server"),"country":x.get("page",{}).get("country")}
            for x in r.json().get("results",[])[:5]]

@check("reverseip","Reverse IP")
@safe
def c_reverseip(d):
    try: ip = socket.gethostbyname(d)
    except Exception: return {"error":"resolve failed"}
    r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=20)
    return {"ip": ip, "domains": r.text.splitlines()[:30]}

def run_all(domain):
    results={}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures={ex.submit(m["fn"], domain): n for n,m in CHECKS.items()}
        for fut in as_completed(futures):
            n=futures[fut]
            try: results[n]={"label":CHECKS[n]["label"],"data":fut.result()}
            except Exception as e: results[n]={"label":CHECKS[n]["label"],"data":{"error":str(e)}}
    return dict(sorted(results.items(), key=lambda x:x[1]["label"]))

def make_txt_report(domain, results):
    lines=[f"RECON REPORT — {domain}", "="*60, f"generated: {datetime.utcnow().isoformat()}Z", ""]
    for key,v in results.items():
        lines.append(f"### {v['label']} ({key})")
        data=v["data"]
        lines.append(data if isinstance(data,str) else json.dumps(data, ensure_ascii=False, indent=2, default=str))
        lines.append("")
    return "\n".join(lines)

# ============================================================
# SHARED CSS
# ============================================================
BASE_CSS = r"""
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--border:#30363d;
  --text:#e6edf3;--text2:#8b949e;--accent:#10a37f;--accent2:#0d8a6a;
  --red:#f85149;--red2:#da3633;--yellow:#d29922;--blue:#58a6ff;
  --radius:12px;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#484f58}
input,button,textarea{font-family:inherit}
input{width:100%;padding:11px 14px;border-radius:10px;border:1px solid var(--border);
  background:var(--bg);color:var(--text);font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(16,163,127,.15)}
button{border:none;cursor:pointer;font-weight:600;transition:background .15s,transform .05s}
button:active{transform:scale(.98)}
button:disabled{opacity:.5;cursor:not-allowed}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:11px 20px;border-radius:10px;font-size:14px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-danger{background:var(--red2);color:#fff}
.btn-danger:hover{background:var(--red)}
.btn-ghost{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--border)}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:28px}
.center-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.err{color:var(--red);font-size:13px;padding:10px 14px;background:rgba(248,81,73,.1);
  border:1px solid rgba(248,81,73,.3);border-radius:8px;margin-bottom:14px}
.ok-msg{color:#3fb950;font-size:13px;padding:10px 14px;background:rgba(63,185,80,.1);
  border:1px solid rgba(63,185,80,.3);border-radius:8px;margin-bottom:14px}
.badge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;
  font-size:11px;font-weight:600;letter-spacing:.2px}
.badge-admin{background:rgba(88,166,255,.15);color:var(--blue)}
.badge-multi{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-ban{background:rgba(248,81,73,.15);color:var(--red)}
.badge-ok{background:rgba(63,185,80,.15);color:#3fb950}
"""

# ============================================================
# LOGIN / REGISTER
# ============================================================
AUTH_CSS = BASE_CSS + r"""
.auth-card{width:100%;max-width:400px}
.auth-card h2{font-size:22px;margin-bottom:6px;font-weight:700}
.auth-card .sub{color:var(--text2);font-size:13px;margin-bottom:22px}
.auth-card form input{margin-bottom:12px}
.auth-card .btn{width:100%}
.auth-foot{text-align:center;margin-top:18px;font-size:13px;color:var(--text2)}
.auth-brand{display:flex;align-items:center;gap:10px;margin-bottom:24px;justify-content:center}
.auth-brand .logo{width:38px;height:38px;border-radius:10px;
  background:linear-gradient(135deg,var(--accent),#3fb950);display:flex;
  align-items:center;justify-content:center;font-size:20px;font-weight:800;color:#fff}
.auth-brand .name{font-size:18px;font-weight:700}
"""

LOGIN_HTML = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Вход — Recon AI</title><style>" + AUTH_CSS + """
</style></head><body>
<div class="center-page">
  <div class="card auth-card">
    <div class="auth-brand"><div class="logo">R</div><div class="name">Recon AI</div></div>
    <h2>С возвращением</h2>
    <div class="sub">Войдите, чтобы продолжить</div>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="post" action="/login">
      <input name="username" placeholder="Логин" required autofocus autocomplete="username">
      <input name="password" type="password" placeholder="Пароль" required autocomplete="current-password">
      <button type="submit" class="btn btn-primary">Войти</button>
    </form>
    <div class="auth-foot">Нет аккаунта? <a href="/register">Регистрация</a></div>
  </div>
</div></body></html>
"""

REGISTER_HTML = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Регистрация — Recon AI</title><style>" + AUTH_CSS + """
</style></head><body>
<div class="center-page">
  <div class="card auth-card">
    <div class="auth-brand"><div class="logo">R</div><div class="name">Recon AI</div></div>
    <h2>Создать аккаунт</h2>
    <div class="sub">Логин ≥ 3 символов, пароль ≥ 6</div>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="post" action="/register">
      <input name="username" placeholder="Логин" required autofocus autocomplete="username">
      <input name="password" type="password" placeholder="Пароль" required autocomplete="new-password">
      <button type="submit" class="btn btn-primary">Создать аккаунт</button>
    </form>
    <div class="auth-foot">Уже есть аккаунт? <a href="/login">Вход</a></div>
  </div>
</div></body></html>
"""

@app.route("/login", methods=["GET","POST"])
def login_page():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        row = find_user_by_username(u)
        if not row or not check_password_hash(row["password_hash"], p):
            return render_template_string(LOGIN_HTML, error="Неверный логин или пароль")
        if row["banned"]:
            return render_template_string(LOGIN_HTML, error="Аккаунт забанен: " + (row["ban_reason"] or ""))
        session["uid"] = row["id"]
        with LOCK: row["last_ip"] = client_ip()
        save_db()
        log_action(row["id"], "login", ip=client_ip())
        return redirect(url_for("index"))
    return render_template_string(LOGIN_HTML, error=None)

@app.route("/register", methods=["GET","POST"])
def register_page():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if len(u) < 3 or len(p) < 6:
            return render_template_string(REGISTER_HTML, error="Логин ≥3, пароль ≥6")
        if find_user_by_username(u):
            return render_template_string(REGISTER_HTML, error="Логин занят")
        ip = client_ip()
        user = add_user(u, p, ip)
        session["uid"] = user["id"]
        log_action(user["id"], "register", f"suspected_multi={user['suspected_multi']}", ip=ip)
        return redirect(url_for("index"))
    return render_template_string(REGISTER_HTML, error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ============================================================
# PROFILE
# ============================================================
PROFILE_CSS = BASE_CSS + r"""
.profile-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.profile-card{width:100%;max-width:480px}
.profile-head{display:flex;align-items:center;gap:14px;margin-bottom:24px}
.avatar{width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#3fb950);
  display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;color:#fff}
.profile-head .name{font-size:19px;font-weight:700}
.profile-head .role{font-size:13px;color:var(--text2)}
.row{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border);font-size:14px}
.row:last-of-type{border-bottom:none}
.row span:first-child{color:var(--text2)}
.row span:last-child{font-weight:500}
.section-title{margin:24px 0 14px;font-size:15px;font-weight:700;color:var(--text)}
.profile-actions{display:flex;gap:10px;margin-top:24px}
.profile-actions .btn{flex:1}
"""

PROFILE_HTML = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Профиль — Recon AI</title><style>" + PROFILE_CSS + """
</style></head><body>
<div class="profile-wrap">
  <div class="card profile-card">
    <div class="profile-head">
      <div class="avatar">{{ u.username[0]|upper }}</div>
      <div>
        <div class="name">{{ u.username }}</div>
        <div class="role">{{ 'Администратор' if u.role=='admin' else 'Пользователь' }}</div>
      </div>
    </div>
    {% if msg %}<div class="{{ 'ok-msg' if msg_type=='ok' else 'err' }}">{{ msg }}</div>{% endif %}
    <div class="row"><span>Логин</span><span>{{ u.username }}</span></div>
    <div class="row"><span>Роль</span><span>{{ u.role }}</span></div>
    <div class="row"><span>Создан</span><span>{{ u.created_at[:19] }}</span></div>
    <div class="row"><span>Запросов сегодня</span><span>{{ usage }} / {{ limit }}</span></div>
    <div class="row"><span>Последний IP</span><span>{{ u.last_ip or '—' }}</span></div>

    <div class="section-title">Сменить пароль</div>
    <form method="post" action="/profile/password">
      <input name="old" type="password" placeholder="Текущий пароль" required style="margin-bottom:10px">
      <input name="new" type="password" placeholder="Новый пароль (мин. 6)" required style="margin-bottom:10px">
      <button type="submit" class="btn btn-primary" style="width:100%">Сохранить</button>
    </form>

    <div class="profile-actions">
      <a href="/" class="btn btn-ghost">← В чат</a>
      <a href="/logout" class="btn btn-danger">Выйти</a>
    </div>
  </div>
</div></body></html>
"""

@app.route("/profile")
@login_required
def profile_page():
    u = current_user()
    return render_template_string(PROFILE_HTML, u=u, usage=get_usage(u["id"]),
                                  limit=DAILY_LIMIT, msg=request.args.get("msg"),
                                  msg_type=request.args.get("t","ok"))

@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    u = current_user()
    old = request.form.get("old",""); new = request.form.get("new","")
    if not check_password_hash(u["password_hash"], old):
        return redirect(url_for("profile_page", msg="Текущий пароль неверный", t="err"))
    if len(new) < 6:
        return redirect(url_for("profile_page", msg="Новый пароль мин. 6 символов", t="err"))
    with LOCK: u["password_hash"] = generate_password_hash(new)
    save_db()
    log_action(u["id"], "change_password", ip=client_ip())
    return redirect(url_for("profile_page", msg="Пароль изменён", t="ok"))

# ============================================================
# ADMIN
# ============================================================
ADMIN_CSS = BASE_CSS + r"""
.admin-wrap{max-width:1200px;margin:0 auto;padding:32px 20px}
.admin-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.admin-head h1{font-size:24px;font-weight:700}
.admin-head .links{display:flex;gap:10px}
.section{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:20px;overflow-x:auto}
.section h2{font-size:15px;font-weight:700;margin-bottom:16px;color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:600px}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--border)}
th{color:var(--text2);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.3px}
tr:hover td{background:var(--bg3)}
td:last-child{white-space:nowrap}
.ban-form{display:inline-flex;gap:6px;align-items:center}
.ban-form input{width:130px;padding:6px 10px;font-size:12px}
.ban-form button{padding:6px 12px;border-radius:6px;font-size:12px;background:var(--red2);color:#fff}
.ban-form button:hover{background:var(--red)}
.unban-btn{padding:6px 12px;border-radius:6px;font-size:12px;background:var(--accent);color:#fff}
.unban-btn:hover{background:var(--accent2)}
@media(max-width:600px){.admin-head h1{font-size:20px}.section{padding:14px}}
"""

ADMIN_HTML = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Админ — Recon AI</title><style>" + ADMIN_CSS + """
</style></head><body>
<div class="admin-wrap">
  <div class="admin-head">
    <h1>Админ-панель</h1>
    <div class="links">
      <a href="/" class="btn btn-ghost">← В чат</a>
      <a href="/profile" class="btn btn-ghost">Профиль</a>
    </div>
  </div>

  <div class="section">
    <h2>Пользователи</h2>
    <table>
      <tr><th>ID</th><th>Логин</th><th>Роль</th><th>Создан</th><th>Запросов</th><th>IP</th><th>Флаги</th><th>Действия</th></tr>
      {% for u in users %}
      <tr>
        <td>{{ u.id }}</td>
        <td>{{ u.username }}</td>
        <td>{% if u.role=='admin' %}<span class="badge badge-admin">admin</span>{% else %}user{% endif %}</td>
        <td>{{ u.created_at[:10] }}</td>
        <td>{{ u.usage }}</td>
        <td>{{ u.last_ip or '—' }}</td>
        <td>
          {% if u.suspected_multi %}<span class="badge badge-multi">мультиакк</span>{% endif %}
          {% if u.banned %}<span class="badge badge-ban">{{ u.ban_reason }}</span>{% endif %}
          {% if not u.suspected_multi and not u.banned %}<span class="badge badge-ok">ок</span>{% endif %}
        </td>
        <td>
          {% if u.role!='admin' %}
            {% if u.banned %}
              <form method="post" action="/admin/unban/{{ u.id }}" style="display:inline">
                <button class="unban-btn">Разбан</button>
              </form>
            {% else %}
              <form method="post" action="/admin/ban/{{ u.id }}" class="ban-form">
                <input name="reason" placeholder="причина">
                <button>Бан</button>
              </form>
            {% endif %}
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="section">
   
