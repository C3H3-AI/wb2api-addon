#!/usr/bin/env python3
"""WB2API 管理面板 + OpenAI API 统一入口。

功能对齐 C3H3-AI/ai-proxy 的面板（4 个 tab：概览 / 账号 / 模型 / 设置），
后端适配 Sliverkiss/workbuddy2api —— 单渠道（WorkBuddy / CodeBuddy）。

只依赖上游的**稳定契约**（这是本加载项维护成本低的关键）：
  - GET /status                账号池状态（JSON，需 api_key）
  - GET /v1/models             模型列表
  - /v1/*                      反向代理
  - CLI login url|poll         登录编排
  - CLI signin <dir>           批量签到
  - CLI credit                 积分查询（目录走 WB2A_AUTH_DIR）

安全实现（沿用 ai-proxy 已修复的版本）：
  - 会话 token 用 secrets.token_urlsafe（不可预测）
  - cookie 比较用 hmac.compare_digest（恒定时间）
  - 未启用面板登录时只信任 ingress 与本机回环，不放行整个内网
    （ingress 与 LAN 源 IP 同属内网，仅凭 IP 无法区分）
  - 登录失败 5 次 / 5 分钟限流
  - 设置页走字段白名单 + 类型强校验（防任意配置注入）
  - uid 经正则校验后才拼路径（防目录穿越）
"""
import datetime
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# ── 路径与常量 ──────────────────────────────────────────────────────
APP_DIR = "/app"
DATA_DIR = "/data/data"
AUTH_DIR = "/data/auths"
OPTIONS_FILE = "/data/options.json"
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
PANEL_AUTH_FILE = os.path.join(DATA_DIR, "panel-auth.json")
SESSION_FILE = os.path.join(DATA_DIR, "panel-session")

SRVD_BIN = os.path.join(APP_DIR, "serverd")
LOGIN_BIN = os.path.join(APP_DIR, "login")
SIGNIN_BIN = os.path.join(APP_DIR, "signin")
CREDIT_BIN = os.path.join(APP_DIR, "credit")

LISTEN_PORT = 7863
SRVD_PORT = 7864
WEBUI_COOKIE = "wb2api_session"

LOGIN_FAILS = {}
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 300

# 面板可改的配置项白名单：key -> (类型, 默认值)
# 只允许改这些，避免面板成为任意配置注入口。
EDITABLE_SETTINGS = {
    "api_key": ("str", ""),
    "upstream.timeout_seconds": ("int", 120),
    "cooldown.soft_rate": ("str", "600s"),
    "cooldown.soft_rate_max": ("str", "2h"),
    "pool.breaker_threshold": ("int", 3),
    "pool.breaker_cooldown": ("str", "30m"),
    "pool.breaker_cooldown_max": ("str", "6h"),
    "pool.max_in_flight": ("int", 3),
    "pool.max_in_flight_global": ("int", 2),
    "pool.idle_weight_per_hour": ("num", 0.5),
    "pool.idle_weight_max": ("num", 5.0),
    "pool.expiring_soon": ("str", "168h"),
    "global.enabled": ("bool", True),
    "prompt.mode": ("str", "passthrough"),
    "prompt.file": ("str", ""),
    "features.sanitize_blacklist_fingerprints": ("bool", True),
    "session_sticky.enabled": ("bool", True),
    "session_sticky.ttl": ("str", "30m"),
    "schedule.checkin_hours": ("hours", [9, 21]),
    "schedule.travel_hours": ("hours", [9, 21]),
    "schedule.activity_hours": ("hours", [10]),
    "schedule.keepalive_hours": ("hours", [22]),
    "schedule.school_hours": ("hours", [12]),
    "schedule.cat_hours": ("hours", [1]),
    "schedule.checkin_enabled": ("bool", True),
    "schedule.travel_enabled": ("bool", True),
    "schedule.activity_enabled": ("bool", True),
    "schedule.keepalive_enabled": ("bool", True),
    "schedule.school_enabled": ("bool", True),
    "schedule.cat_enabled": ("bool", True),
}


# ── 通用工具 ────────────────────────────────────────────────────────
def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def write_json_atomic(path, obj, mode=0o600):
    """唯一临时名 + rename：与 serverd 并发读写时不会互相踩。"""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = "%s.tmp-%s" % (path, secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise


def load_options():
    return read_json(OPTIONS_FILE, {})


def load_panel_auth():
    d = read_json(PANEL_AUTH_FILE, {})
    return (d.get("webui_user") or "").strip(), (d.get("webui_pass") or "").strip()


def webui_enabled():
    u, p = load_panel_auth()
    return bool(u and p)


# ── 会话 ────────────────────────────────────────────────────────────
def new_session():
    tok = secrets.token_urlsafe(32)
    try:
        fd = os.open(SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(tok)
    except Exception:
        return ""
    return tok


def check_session(cookie_val):
    if not cookie_val:
        return False
    want = ""
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            want = f.read().strip()
    except Exception:
        return False
    return bool(want) and hmac.compare_digest(want, cookie_val.strip())


# ── 子进程 / serverd ────────────────────────────────────────────────
def run_bin(bin_path, args, timeout=120, env_extra=None):
    if not os.path.isfile(bin_path):
        return False, "", "二进制不存在: %s" % bin_path
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run([bin_path] + list(args), cwd=APP_DIR,
                           capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode == 0, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return False, "", "超时（%ss）" % timeout
    except Exception as e:
        return False, "", str(e)


def svrd_request(path, method="GET", timeout=30, body=None):
    """调用本地 serverd，自动带 api_key（/status 也受保护）。"""
    key = (load_options().get("api_key") or "").strip()
    headers = {}
    if key:
        headers["Authorization"] = "Bearer %s" % key
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (SRVD_PORT, path),
                                 data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class Serverd:
    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return
            os.makedirs(DATA_DIR, exist_ok=True)
            self.proc = subprocess.Popen([SRVD_BIN, "-config", CONFIG_FILE], cwd=APP_DIR,
                                         stdout=sys.stdout, stderr=sys.stderr)

    def restart(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=10)
                except Exception:
                    self.proc.kill()
            self.proc = None
        self.start()

    def kill(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    self.proc.kill()


SRVD = Serverd()


# ── 账号文件（禁用 = 改名，方案 A）──────────────────────────────────
AUTH_NAME_RE = re.compile(r"^workbuddy-(.+)\.json$")


def list_auth_files():
    """[{uid, filename, path, disabled}]。禁用态 = 文件名以 .disabled 结尾。"""
    out = []
    try:
        names = sorted(os.listdir(AUTH_DIR))
    except Exception:
        return out
    for n in names:
        if n.endswith(".disabled"):
            m = AUTH_NAME_RE.match(n[:-len(".disabled")])
            if m:
                out.append({"uid": m.group(1), "filename": n,
                            "path": os.path.join(AUTH_DIR, n), "disabled": True})
        else:
            m = AUTH_NAME_RE.match(n)
            if m:
                out.append({"uid": m.group(1), "filename": n,
                            "path": os.path.join(AUTH_DIR, n), "disabled": False})
    return out


def find_auth_file(uid):
    for a in list_auth_files():
        if a["uid"] == uid:
            return a
    return None


def safe_uid(uid):
    """uid 来自前端，必须校验后才能拼路径（防目录穿越）。"""
    if uid and re.match(r"^[A-Za-z0-9_-]{1,64}$", uid):
        return uid
    return None


# ── 设置读写辅助 ────────────────────────────────────────────────────
def get_path(obj, dotted):
    cur = obj
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur


def set_path(obj, dotted, value):
    parts = dotted.split(".")
    cur = obj
    for k in parts[:-1]:
        if not isinstance(cur.get(k), dict):
            cur[k] = {}
        cur = cur[k]
    cur[parts[-1]] = value


def coerce(val, typ, dflt):
    """前端传来的都是字符串，必须转成正确类型。

    否则 config.json 会出现 "timeout_seconds": "120" 这类类型错误，
    serverd 解析可能失败。
    """
    if typ == "bool":
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "on", "yes")
    if typ == "int":
        try:
            return int(str(val).strip() or dflt)
        except Exception:
            raise ValueError("需要整数")
    if typ == "num":
        try:
            return float(str(val).strip() or dflt)
        except Exception:
            raise ValueError("需要数字")
    if typ == "hours":
        items = val if isinstance(val, list) else [x for x in re.split(r"[,\s]+", str(val).strip()) if x]
        out = []
        for x in items:
            try:
                h = int(str(x).strip())
            except Exception:
                raise ValueError("需为整点小时，逗号分隔")
            if not (0 <= h <= 23):
                raise ValueError("小时需在 0-23 之间")
            out.append(h)
        return sorted(set(out))
    return str(val)


def parse_login_poll(text):
    """解析 `login poll` 的 JSON（上游输出为 snake_case）。"""
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except Exception:
                continue
    try:
        return json.loads(text.strip())
    except Exception:
        return {}


def write_auth_file(info):
    """按 internal/auth 期望的嵌套形态落盘（camelCase + expiresAt 绝对值）。"""
    uid = info.get("uid") or ""
    if not uid:
        raise ValueError("缺少 uid")
    expires_at = int(info.get("expires_at") or 0)
    if not expires_at:
        expires_in = int(info.get("expires_in") or 0)
        expires_at = int(time.time()) + expires_in if expires_in else 0
    doc = {
        "account": {
            "uid": uid,
            "enterpriseId": info.get("enterprise_id") or "",
            "nickname": info.get("nickname") or "",
        },
        "auth": {
            "accessToken": info.get("access_token") or "",
            "refreshToken": info.get("refresh_token") or "",
            "expiresAt": expires_at,
            "domain": info.get("domain") or "",
            "realm": info.get("realm") or "cn",
        },
    }
    path = os.path.join(AUTH_DIR, "workbuddy-%s.json" % uid)
    write_json_atomic(path, doc, mode=0o600)
    return path


# ── 页面 ────────────────────────────────────────────────────────────
LOGIN_PAGE = r"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WB2API 登录</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--line:#2a2f3a;--txt:#e6e9ef;--sub:#9aa3b2;--pri:#0a84ff;--err:#ff453a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.6 -apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;width:340px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--sub);font-size:12px;margin-bottom:18px}
label{display:block;font-size:12px;color:var(--sub);margin-bottom:5px}
input{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:10px;font-size:14px;margin-bottom:12px}
button{width:100%;background:var(--pri);color:#fff;border:0;border-radius:8px;padding:11px;font-size:14px;cursor:pointer}
#msg{color:var(--err);font-size:13px;margin-top:10px;min-height:18px}
</style></head><body><div class="box">
<h1>WB2API 管理</h1><div class="sub">WorkBuddy / CodeBuddy → OpenAI 兼容 API</div>
<label>用户名</label><input id="u" autocomplete="username">
<label>密码</label><input id="p" type="password" autocomplete="current-password">
<button onclick="go()">登录</button><div id="msg"></div>
</div><script>
async function go(){
 var u=document.getElementById('u').value,p=document.getElementById('p').value;
 try{
  var r=await fetch('api/login',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({user:u,pass:p})});
  var d=await r.json().catch(function(){return{error:'响应异常'};});
  if(r.ok){location.href='./';}else{document.getElementById('msg').textContent=d.error||'登录失败';}
 }catch(e){document.getElementById('msg').textContent='网络错误: '+e.message;}
}
document.getElementById('p').addEventListener('keydown',function(e){if(e.key==='Enter')go();});
</script></body></html>
"""

HTML_PAGE = r"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WB2API 管理</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--card2:#1d2129;--line:#2a2f3a;--txt:#e6e9ef;--sub:#9aa3b2;
--pri:#0a84ff;--ok:#32d74b;--warn:#ff9f0a;--err:#ff453a;--info:#a0d7ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.6 -apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:20px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.brand h1{font-size:20px;margin:0}
.brand .sub{font-size:12px;color:var(--sub)}
.hd-right{display:flex;align-items:center;gap:10px}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--sub);
border:1px solid var(--line);border-radius:20px;padding:4px 12px}
.dot{width:8px;height:8px;border-radius:50%;background:#555}
.dot.up{background:var(--ok)}.dot.down{background:var(--err)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:16px;flex-wrap:wrap}
.tab{background:transparent;border:1px solid transparent;color:var(--sub);padding:9px 16px;
font-size:14px;cursor:pointer;border-radius:8px 8px 0 0}
.tab:hover{color:var(--txt)}
.tab.active{color:var(--pri);border-color:var(--line);border-bottom-color:var(--pri);background:rgba(10,132,255,.06)}
.panel{display:none}.panel.active{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.stat .lbl{font-size:12px;color:var(--sub);margin-bottom:6px}
.stat .val{font-size:20px;font-weight:700}
.val.good{color:var(--ok)}.val.warn{color:var(--warn)}.val.bad{color:var(--err)}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.box h2{font-size:15px;margin:0 0 12px}
.hint{font-size:12px;color:var(--sub);line-height:1.6}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--sub);font-weight:500;font-size:12px;white-space:nowrap;background:var(--card2)}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;padding:2px 8px;border-radius:6px;font-weight:500}
.b-ok{background:rgba(50,215,75,.15);color:var(--ok)}
.b-warn{background:rgba(255,159,10,.15);color:var(--warn)}
.b-bad{background:rgba(255,69,58,.15);color:var(--err)}
.btn{background:var(--pri);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
.btn:hover{opacity:.9}.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.sm{padding:5px 10px;font-size:12px}
.btn-ok{background:var(--ok)}.btn-warn{background:var(--warn)}.btn-err{background:var(--err)}
.btn-info{background:var(--info);color:#00365c}
.btn-sec{background:transparent;color:var(--pri);border:1px solid var(--pri)}
.tbar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.grp{display:flex;gap:8px;flex-wrap:wrap}
.field{margin-bottom:12px}
.field label{display:block;font-size:12px;color:var(--sub);margin-bottom:5px}
input,select,textarea{background:var(--bg);border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:9px 11px;font-size:13px;width:100%;font-family:inherit}
textarea{resize:vertical;min-height:70px}
.fsec{border-top:1px solid var(--line);padding-top:14px;margin-top:14px}
.fsec:first-child{border-top:0;padding-top:0;margin-top:0}
.fsec h3{font-size:13px;color:var(--pri);margin:0 0 12px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0 16px}
.empty{text-align:center;color:var(--sub);padding:24px;font-size:13px}
#toastBox{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:8px;z-index:99}
.t{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--pri);
border-radius:8px;padding:10px 16px;font-size:13px;box-shadow:0 4px 16px rgba(0,0,0,.3);max-width:360px}
.t.ok{border-left-color:var(--ok)}.t.err{border-left-color:var(--err)}.t.warn{border-left-color:var(--warn)}
.pwin{display:flex;gap:8px}
code{background:var(--card2);padding:1px 6px;border-radius:4px;font-size:12px}
.search{max-width:260px}
.mline{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-bottom:1px solid var(--line);font-size:13px}
.mline:hover{background:rgba(255,255,255,.02)}
.mline .mid{font-family:ui-monospace,Menlo,Consolas,monospace}
</style></head><body><div class="wrap">

<div class="top">
 <div class="brand"><h1>WB2API 管理面板</h1>
   <div class="sub">WorkBuddy / CodeBuddy → OpenAI 兼容 API</div></div>
 <div class="hd-right">
   <span class="pill"><span class="dot" id="svcDot"></span><span id="svcTxt">检测中</span></span>
   <span class="pill" id="upPill" title="当前镜像构建时所用的上游 commit">上游 -</span>
   <button class="btn btn-sec sm" onclick="doLogout()">退出</button>
 </div>
</div>

<nav class="tabs">
 <button class="tab active" onclick="switchPanel('overview')">概览</button>
 <button class="tab" onclick="switchPanel('accounts')">账号</button>
 <button class="tab" onclick="switchPanel('models')">模型</button>
 <button class="tab" onclick="switchPanel('settings')">设置</button>
</nav>

<section class="panel active" id="panel-overview">
 <div class="cards" id="ovCards"></div>
 <div class="box"><h2>服务状态</h2><div class="hint" id="ovDetail">加载中…</div></div>
 <div class="box"><h2>接入说明</h2><div class="hint" id="ovConnInfo">加载中…</div></div>
</section>

<section class="panel" id="panel-accounts">
 <div class="box">
  <b>添加账号</b>
  <div class="grp" style="margin-top:8px">
    <button class="btn" onclick="wbLogin()">WorkBuddy 登录</button>
    <button class="btn btn-info" onclick="reloadServerd()">重载服务</button>
  </div>
  <div class="hint" id="loginHint" style="margin-top:8px"></div>
  <div id="loginShow"></div>
 </div>
 <div class="tbar">
  <div class="grp">
   <button class="btn btn-warn" onclick="runCheckin()">全部签到</button>
   <button class="btn btn-pri" onclick="load()">刷新列表</button>
  </div>
  <span class="hint" id="acctCount">账号：加载中…</span>
 </div>
 <div class="box">
  <table><thead><tr>
    <th>昵称</th><th>UID</th><th>域</th><th>积分</th><th>状态</th><th>冷却剩余</th><th>操作</th>
  </tr></thead><tbody id="acctBody"></tbody></table>
  <div class="empty" id="acctEmpty" style="display:none">暂无账号，请用上方按钮添加。</div>
 </div>
 <div class="box" id="outBox" style="display:none">
  <div class="tbar"><b id="outTitle">输出</b>
   <button class="btn sm btn-sec" onclick="document.getElementById('outBox').style.display='none'">关闭</button></div>
  <pre id="outPre" style="white-space:pre-wrap;font-size:12px;max-height:340px;overflow:auto;margin:0"></pre>
 </div>
</section>

<section class="panel" id="panel-models">
 <div class="tbar">
  <div class="grp"><button class="btn" onclick="loadModels()">刷新模型</button></div>
  <span class="hint" id="modelInfo"></span>
 </div>
 <div class="box">
  <p class="hint" style="margin:0 0 10px">
   模型可直接用于 <code>/v1/chat/completions</code>；带 <code>global:</code> 前缀的为国际版渠道。</p>
  <input id="modelSearch" class="search" placeholder="搜索模型 ID…" oninput="renderModels()">
  <div id="modelGroups" style="margin-top:12px"></div>
  <div class="empty" id="modelEmpty" style="display:none">未加载到模型列表（可能还没有账号）。</div>
 </div>
</section>

<section class="panel" id="panel-settings">
 <div class="box"><h2>设置</h2>
  <p class="hint" style="margin:0 0 14px">
   保存后写入 <code>config.json</code> 并热重启 serverd（不影响本面板）。</p>

  <div class="fsec"><h3>通用</h3>
   <div class="grid2">
    <div class="field"><label>API Key（留空则不鉴权）</label>
      <div class="pwin"><input id="f_api_key" type="password" placeholder="OpenAI 客户端调用所需 Key" autocomplete="off">
      <button type="button" class="btn btn-info sm" onclick="toggleKey(this)" style="flex:0 0 auto">显示</button></div></div>
    <div class="field"><label>上游超时（秒）</label><input id="f_upstream_timeout_seconds" type="number" min="10" max="600"></div>
   </div>
  </div>

  <div class="fsec"><h3>账号池</h3>
   <div class="grid2">
    <div class="field"><label>单账号最大在途请求（国内版）</label><input id="f_pool_max_in_flight" type="number" min="1" max="64"></div>
    <div class="field"><label>单账号最大在途请求（国际版）</label><input id="f_pool_max_in_flight_global" type="number" min="1" max="64"></div>
    <div class="field"><label>熔断阈值（连续失败次数）</label><input id="f_pool_breaker_threshold" type="number" min="1" max="20"></div>
    <div class="field"><label>熔断冷却</label><input id="f_pool_breaker_cooldown" placeholder="如 30m"></div>
    <div class="field"><label>熔断冷却上限</label><input id="f_pool_breaker_cooldown_max" placeholder="如 6h"></div>
    <div class="field"><label>快过期积分优先窗口</label><input id="f_pool_expiring_soon" placeholder="如 168h"></div>
    <div class="field"><label>闲置补偿（每小时权重）</label><input id="f_pool_idle_weight_per_hour" type="number" step="0.1" min="0"></div>
    <div class="field"><label>闲置补偿上限</label><input id="f_pool_idle_weight_max" type="number" step="0.1" min="0"></div>
   </div>
  </div>

  <div class="fsec"><h3>冷却策略</h3>
   <div class="grid2">
    <div class="field"><label>限流(429)冷却时长</label><input id="f_cooldown_soft_rate" placeholder="如 600s"></div>
    <div class="field"><label>软冷却上限（指数退避封顶）</label><input id="f_cooldown_soft_rate_max" placeholder="如 2h"></div>
   </div>
  </div>

  <div class="fsec"><h3>定时任务（整点小时，逗号分隔；北京时间）</h3>
   <div class="grid2">
    <div class="field"><label>每日签到</label><input id="f_schedule_checkin_hours" placeholder="如 9,21"></div>
    <div class="field"><label>猫猫旅行</label><input id="f_schedule_travel_hours" placeholder="如 9,21"></div>
    <div class="field"><label>活跃上报</label><input id="f_schedule_activity_hours" placeholder="如 10"></div>
    <div class="field"><label>Token 保活</label><input id="f_schedule_keepalive_hours" placeholder="如 22"></div>
    <div class="field"><label>开学季任务</label><input id="f_schedule_school_hours" placeholder="如 12"></div>
    <div class="field"><label>夜猫子任务</label><input id="f_schedule_cat_hours" placeholder="如 1"></div>
   </div>
   <div class="grid2" style="margin-top:8px">
    <div class="field"><label><input type="checkbox" id="f_schedule_checkin_enabled" style="width:auto"> 启用签到</label></div>
    <div class="field"><label><input type="checkbox" id="f_schedule_travel_enabled" style="width:auto"> 启用猫猫旅行</label></div>
    <div class="field"><label><input type="checkbox" id="f_schedule_activity_enabled" style="width:auto"> 启用活跃上报</label></div>
    <div class="field"><label><input type="checkbox" id="f_schedule_keepalive_enabled" style="width:auto"> 启用保活</label></div>
    <div class="field"><label><input type="checkbox" id="f_schedule_school_enabled" style="width:auto"> 启用开学季</label></div>
    <div class="field"><label><input type="checkbox" id="f_schedule_cat_enabled" style="width:auto"> 启用夜猫子</label></div>
   </div>
  </div>

  <div class="fsec"><h3>其它</h3>
   <div class="grid2">
    <div class="field"><label><input type="checkbox" id="f_global_enabled" style="width:auto"> 启用国际版渠道（global）</label></div>
    <div class="field"><label><input type="checkbox" id="f_session_sticky_enabled" style="width:auto"> 启用会话粘性</label></div>
    <div class="field"><label>会话粘性 TTL</label><input id="f_session_sticky_ttl" placeholder="如 30m"></div>
    <div class="field"><label>提示词模式</label><select id="f_prompt_mode">
      <option value="passthrough">passthrough（透传客户端 system）</option>
      <option value="custom">custom（用自定义提示词）</option></select></div>
    <div class="field"><label>自定义提示词文件路径</label><input id="f_prompt_file" placeholder="/data/data/prompt.txt"></div>
    <div class="field"><label><input type="checkbox" id="f_features_sanitize_blacklist_fingerprints" style="width:auto"> 指纹脱敏</label></div>
   </div>
  </div>

  <div class="fsec"><h3>面板登录账号</h3>
   <div class="grid2">
    <div class="field"><label>登录名</label><input id="f_webui_user" placeholder="面板登录账号"></div>
    <div class="field"><label>新密码</label><input id="f_webui_pass" type="password" placeholder="留空则不修改"></div>
   </div>
   <button class="btn btn-warn" onclick="changeLogin()">保存登录账号</button>
   <p class="hint" style="margin:8px 0 0">修改后立即生效；当前会话保持，下次登录用新账号。</p>
  </div>

  <div class="tbar" style="margin-top:16px">
   <div class="grp">
    <button class="btn btn-ok" onclick="saveSettings()">保存设置</button>
    <button class="btn btn-sec" onclick="loadSettings()">重新加载</button>
   </div>
  </div>
 </div>
</section>
</div>
<div id="toastBox"></div>
<script>
function Q(s){return document.querySelector(s);}
function toast(msg,type){var b=Q('#toastBox');var t=document.createElement('div');
 t.className='t '+(type||'');t.textContent=msg;b.appendChild(t);
 setTimeout(function(){t.style.opacity=0;t.style.transition='opacity .3s';
  setTimeout(function(){t.remove();},300);},4200);}
function esc(s){s=(s===null||s===undefined)?'':String(s);
 return s.replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
async function api(path,opts){opts=opts||{};
 try{var r=await fetch(path,{method:opts.method||'GET',
   headers:opts.body?{'Content-Type':'application/json'}:{},
   body:opts.body?JSON.stringify(opts.body):undefined});
  var txt=await r.text();var d;try{d=JSON.parse(txt);}catch(e){d={error:txt,status:r.status};}
  if(!r.ok&&d&&!d.error)d.error='HTTP '+r.status;
  return d;
 }catch(e){return{error:'网络错误: '+e.message};}}
var ORDER=['overview','accounts','models','settings'];
function switchPanel(name){
 var ps=document.querySelectorAll('.panel');for(var i=0;i<ps.length;i++)ps[i].classList.remove('active');
 var ts=document.querySelectorAll('.tab');for(var j=0;j<ts.length;j++)ts[j].classList.remove('active');
 var p=document.getElementById('panel-'+name);if(p)p.classList.add('active');
 var k=ORDER.indexOf(name);if(k>=0&&ts[k])ts[k].classList.add('active');
 if(name==='models')loadModels();
 if(name==='settings')loadSettings();
}
function toggleKey(btn){var inp=Q('#f_api_key');if(!inp)return;
 var show=inp.type==='password';inp.type=show?'text':'password';btn.textContent=show?'隐藏':'显示';}
function copyTxt(t){if(!t)return;
 if(navigator.clipboard)navigator.clipboard.writeText(t).then(function(){toast('已复制','ok');},
  function(){toast('复制失败','err');});
 else toast('浏览器不支持剪贴板','err');}

var ST={};
async function load(){
 var d=await api('api/overview');
 if(d.error){toast(d.error,'err');return;}
 ST=d.status||{};
 var ok=(ST.healthy||0)>0;
 Q('#svcDot').className='dot '+(ok?'up':'down');
 Q('#svcTxt').textContent=ok?('正常 · '+(ST.healthy||0)+' 个可用'):'无可用账号';
 if(d.upstream_commit)Q('#upPill').textContent='上游 '+d.upstream_commit;
 Q('#ovCards').innerHTML=
  card('健康账号',ST.healthy||0,(ST.healthy||0)>0?'good':'bad')+
  card('账号总数',ST.total||0,'')+
  card('冷却中',ST.cooling||0,(ST.cooling||0)>0?'warn':'')+
  card('已禁用',ST.disabled||0,(ST.disabled||0)>0?'bad':'');
 var rt=ST.realm_totals||{};var cn=rt.cn||{},gl=rt.global||{};
 Q('#ovDetail').innerHTML=
  '服务时间：'+esc(d.server_time||'-')+'<br>'+
  '国内版(cn)：健康 '+(cn.healthy||0)+' / 共 '+(cn.total||0)+'<br>'+
  '国际版(global)：健康 '+(gl.healthy||0)+' / 共 '+(gl.total||0)+'<br>'+
  '在途占满：'+(ST.in_flight_full||0);
 var base=location.origin+location.pathname.replace(/\/$/,'');
 Q('#ovConnInfo').innerHTML=
  'OpenAI 兼容端点：<code>'+esc(base)+'v1/chat/completions</code><br>'+
  '模型列表：<code>'+esc(base)+'v1/models</code><br>'+
  '鉴权：<code>Authorization: Bearer &lt;你的 API Key&gt;</code>';
 renderAccounts(ST.accounts||[]);
}
function card(lbl,val,cls){return '<div class="stat"><div class="lbl">'+esc(lbl)+
 '</div><div class="val '+cls+'">'+esc(val)+'</div></div>';}

function statusBadge(a,dis){
 if(dis)return '<span class="badge b-bad">已禁用</span>';
 if(a.disabled)return '<span class="badge b-bad">已禁用</span>';
 if(a.breaker_until)return '<span class="badge b-warn">熔断</span>';
 if(a.cooling)return '<span class="badge b-warn">冷却</span>';
 return '<span class="badge b-ok">正常</span>';
}
function fmtSec(s){if(!s)return '-';if(s<60)return s+'s';
 if(s<3600)return Math.round(s/60)+'m';return Math.round(s/3600)+'h';}
function renderAccounts(accts){
 var files={};(ST._files||[]).forEach(function(f){files[f.uid]=f.disabled;});
 // 以文件系统为准（禁用态只体现在文件层）
 var seen={};var merged=[];
 accts.forEach(function(a){seen[a.uid]=1;
  merged.push(Object.assign({},a,{_dis:!!files[a.uid]}));});
 (ST._files||[]).forEach(function(f){
  if(!seen[f.uid])merged.push({uid:f.uid,nickname:'(未加载)',realm:'-',credits:'-',_dis:f.disabled,_off:true});});
 merged.sort(function(x,y){return String(x.uid).localeCompare(String(y.uid));});
 Q('#acctCount').textContent='账号：'+merged.length+(merged.length?'（健康 '+(ST.healthy||0)+'）':'');
 if(!merged.length){Q('#acctBody').innerHTML='';Q('#acctEmpty').style.display='block';return;}
 Q('#acctEmpty').style.display='none';
 Q('#acctBody').innerHTML=merged.map(function(a){
  var uid=esc(a.uid),nick=esc(a.nickname||'-');
  var acts='<button class="btn sm btn-sec" onclick="copyTxt(\''+uid+'\')">复制UID</button>';
  if(a._dis)acts+='<button class="btn sm btn-ok" onclick="setEnabled(\''+uid+'\',true)">启用</button>';
  else acts+='<button class="btn sm btn-warn" onclick="setEnabled(\''+uid+'\',false)">禁用</button>';
  acts+='<button class="btn sm btn-err" onclick="delAcct(\''+uid+'\')">删除</button>';
  return '<tr><td>'+nick+'</td><td>'+uid+'</td><td>'+esc(a.realm||'cn')+'</td>'+
   '<td>'+(a.credits===undefined||a.credits===null?'-':esc(a.credits))+'</td>'+
   '<td>'+statusBadge(a,a._dis)+
   (a.reason?' <span class="hint">'+esc(a.reason)+'</span>':'')+'</td>'+
   '<td>'+fmtSec(a.cool_remaining_sec)+'</td>'+
   '<td><div class="grp">'+acts+'</div></td></tr>';
 }).join('');
}
function showOut(title,text){Q('#outTitle').textContent=title;
 Q('#outPre').textContent=text||'(无输出)';Q('#outBox').style.display='block';}

async function wbLogin(){
 var d=await api('api/login-url');
 if(d.error){toast(d.error,'err');return;}
 Q('#loginHint').innerHTML='请在浏览器完成登录后回到本页点「我已完成登录」';
 Q('#loginShow').innerHTML='<div class="field" style="margin-top:10px">'+
  '<label>授权链接</label><div class="pwin">'+
  '<input value="'+esc(d.url)+'" readonly>'+
  '<button class="btn sm" style="flex:0 0 auto" onclick="copyTxt(this.previousElementSibling.value)">复制</button></div>'+
  '<button class="btn btn-ok" style="margin-top:10px" onclick="pollWbDone(this)">我已完成登录</button></div>';
 window.open(d.url,'_blank');
}
async function pollWbDone(btn){
 btn.disabled=true;btn.textContent='验证中…';
 var d=await api('api/login-poll',{method:'POST',body:{}});
 toast(d.message||d.error,d.success?'ok':'err');
 if(d.success){Q('#loginShow').innerHTML='';Q('#loginHint').textContent='';load();}
 else{btn.disabled=false;btn.textContent='我已完成登录';}
}
async function setEnabled(uid,on){
 var d=await api('api/account-toggle',{method:'POST',body:{uid:uid,enabled:on}});
 toast(d.message||d.error,d.success?'ok':'err');if(d.success)load();
}
async function delAcct(uid){
 if(!confirm('确定删除账号 '+uid+' ？会先备份到 data/，但请谨慎。'))return;
 var d=await api('api/account-delete',{method:'POST',body:{uid:uid}});
 toast(d.message||d.error,d.success?'ok':'err');if(d.success)load();
}
async function reloadServerd(){
 var d=await api('api/reload',{method:'POST',body:{}});
 toast(d.message||d.error,d.success?'ok':'err');
}
async function runCheckin(){
 toast('正在执行全部签到…');
 var d=await api('api/checkin',{method:'POST',body:{}});
 toast(d.success?'签到完成':(d.error||'签到失败'),d.success?'ok':'err');
 if(d.output)showOut('签到输出',d.output);
 load();
}

var MODELS=[];
async function loadModels(){
 Q('#modelInfo').textContent='加载中…';
 var d=await api('api/models');
 if(d.error){Q('#modelInfo').textContent=d.error;toast(d.error,'err');return;}
 MODELS=((d.data)||[]).map(function(m){return m.id;}).filter(Boolean);
 Q('#modelInfo').textContent='共 '+MODELS.length+' 个模型';
 renderModels();
}
function renderModels(){
 var q=(Q('#modelSearch').value||'').toLowerCase();
 var list=MODELS.filter(function(m){return !q||m.toLowerCase().indexOf(q)>=0;});
 if(!list.length){Q('#modelGroups').innerHTML='';Q('#modelEmpty').style.display='block';return;}
 Q('#modelEmpty').style.display='none';
 var groups={};
 list.forEach(function(m){var p=m.indexOf('global:')===0?'global':'cn';
  (groups[p]=groups[p]||[]).push(m);});
 var html='';
 Object.keys(groups).sort().forEach(function(g){
  html+='<div class="hint" style="margin:10px 0 6px">'+
   (g==='global'?'国际版 (global:*)':'国内版')+' · '+groups[g].length+' 个</div>';
  groups[g].forEach(function(m){
   html+='<div class="mline"><span class="mid">'+esc(m)+'</span>'+
    '<button class="btn sm btn-sec" onclick="copyTxt(\''+esc(m)+'\')">复制</button></div>';});
 });
 Q('#modelGroups').innerHTML=html;
}

var FIELDS=['api_key','upstream.timeout_seconds','cooldown.soft_rate','cooldown.soft_rate_max',
 'pool.breaker_threshold','pool.breaker_cooldown','pool.breaker_cooldown_max',
 'pool.max_in_flight','pool.max_in_flight_global','pool.idle_weight_per_hour','pool.idle_weight_max',
 'pool.expiring_soon','global.enabled','prompt.mode','prompt.file',
 'features.sanitize_blacklist_fingerprints','session_sticky.enabled','session_sticky.ttl',
 'schedule.checkin_hours','schedule.travel_hours','schedule.activity_hours',
 'schedule.keepalive_hours','schedule.school_hours','schedule.cat_hours',
 'schedule.checkin_enabled','schedule.travel_enabled','schedule.activity_enabled',
 'schedule.keepalive_enabled','schedule.school_enabled','schedule.cat_enabled'];
function fid(k){return 'f_'+k.replace(/\./g,'_');}
function getPath(o,p){return p.split('.').reduce(function(a,k){return (a==null)?a:a[k];},o);}
async function loadSettings(){
 var d=await api('api/settings');
 if(d.error){toast(d.error,'err');return;}
 var c=d.settings||{};
 FIELDS.forEach(function(k){
  var el=document.getElementById(fid(k));if(!el)return;
  var v=getPath(c,k);
  if(el.type==='checkbox')el.checked=!!v;
  else el.value=(v===undefined||v===null)?'':(Array.isArray(v)?v.join(','):v);
 });
}
async function saveSettings(){
 var body={};
 FIELDS.forEach(function(k){
  var el=document.getElementById(fid(k));if(!el)return;
  body[k]=(el.type==='checkbox')?el.checked:el.value;
 });
 var d=await api('api/settings',{method:'POST',body:body});
 toast(d.message||d.error,d.success?'ok':'err');
 if(d.success)load();
}
async function changeLogin(){
 var u=(Q('#f_webui_user')||{}).value||'',p=(Q('#f_webui_pass')||{}).value||'';
 if(!u){toast('请填写登录名','err');return;}
 var d=await api('api/change-login',{method:'POST',body:{user:u,pass:p}});
 toast(d.message||d.error,d.success?'ok':'err');
 if(d.success){Q('#f_webui_user').value='';Q('#f_webui_pass').value='';}
}
async function doLogout(){
 await api('api/logout',{method:'POST',body:{}});
 location.reload();
}
load();
setInterval(function(){
 if(document.getElementById('panel-overview').classList.contains('active'))load();
},30000);
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "wb2api-panel"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ── 响应 ────────────────────────────────────────────────────────
    def _send(self, body, ctype="text/html; charset=utf-8", code=200, extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200, extra=None):
        self._send(json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8", code, extra)

    # ── 来源与鉴权 ──────────────────────────────────────────────────
    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    def _is_loopback(self):
        return self._client_ip() in ("127.0.0.1", "::1", "localhost", "")

    def _is_ingress(self):
        p = self.path or ""
        return p.startswith("/api/hassio_ingress/") or "/hassio_ingress/" in p

    def _cookie(self):
        ck = self.headers.get("Cookie", "") or ""
        for part in ck.split(";"):
            part = part.strip()
            if part.startswith(WEBUI_COOKIE + "="):
                return part[len(WEBUI_COOKIE) + 1:].strip()
        return ""

    def _mgmt_authorized(self):
        if check_session(self._cookie()):
            return True
        if webui_enabled():
            return False
        return self._is_ingress() or self._is_loopback()

    def _strip_ingress(self, path):
        marker = "/hassio_ingress/"
        i = path.find(marker)
        if i < 0:
            return path
        rest = path[i + len(marker):]
        parts = rest.split("/", 1)
        return "/" + (parts[1] if len(parts) > 1 else "")

    # ── 路由 ────────────────────────────────────────────────────────
    def do_GET(self):
        path = self._strip_ingress(self.path.split("?")[0])

        if path in ("/healthz", "/api/healthz"):
            return self._send("OK", "text/plain")

        if path == "/" or path.endswith("/"):
            if webui_enabled() and not check_session(self._cookie()):
                return self._send(LOGIN_PAGE)
            return self._send(HTML_PAGE)

        if path in ("/api/login", "/login"):
            return self._send(LOGIN_PAGE)

        if path.startswith("/v1/"):
            return self._proxy("GET")

        if not self._mgmt_authorized():
            return self._json({"error": "未登录，请先访问面板首页登录"}, 401)

        if path == "/api/overview":
            return self._h_overview()
        if path == "/api/settings":
            return self._h_get_settings()
        if path == "/api/models":
            return self._h_models()
        if path == "/api/login-url":
            return self._h_login_url()
        if path == "/api/credit":
            return self._h_credit()

        return self._json({"error": "not found: %s" % path}, 404)

    def do_POST(self):
        path = self._strip_ingress(self.path.split("?")[0])

        if path == "/api/login":
            return self._h_login_post()

        if path.startswith("/v1/"):
            return self._proxy("POST")

        if not self._mgmt_authorized():
            return self._json({"error": "未登录，请先访问面板首页登录"}, 401)

        if path == "/api/login-poll":
            return self._h_login_poll()
        if path == "/api/checkin":
            return self._h_checkin()
        if path == "/api/settings":
            return self._h_save_settings()
        if path == "/api/change-login":
            return self._h_change_login()
        if path == "/api/account-toggle":
            return self._h_account_toggle()
        if path == "/api/account-delete":
            return self._h_account_delete()
        if path == "/api/reload":
            SRVD.restart()
            return self._json({"success": True, "message": "serverd 已重载"})
        if path == "/api/logout":
            try:
                os.remove(SESSION_FILE)
            except Exception:
                pass
            return self._json({"ok": True})

        return self._json({"error": "not found: %s" % path}, 404)

    # ── 登录 ────────────────────────────────────────────────────────
    def _h_login_post(self):
        ip = self._client_ip()
        cnt, first = LOGIN_FAILS.get(ip, [0, 0])
        if cnt >= LOGIN_MAX_FAILS and time.time() - first < LOGIN_LOCK_SECONDS:
            return self._json({"error": "尝试次数过多，请 5 分钟后再试"}, 429)

        body = self._read_body()
        user = (body.get("user") or "").strip()
        pw = (body.get("pass") or "").strip()
        want_user, want_pass = load_panel_auth()

        if want_user and hmac.compare_digest(user, want_user) and \
                hmac.compare_digest(pw, want_pass):
            LOGIN_FAILS.pop(ip, None)
            tok = new_session()
            if not tok:
                return self._json({"error": "会话创建失败，请检查容器磁盘与权限"}, 500)
            attrs = "%s=%s; Path=/; HttpOnly; SameSite=Lax" % (WEBUI_COOKIE, tok)
            fwd = self.headers.get("X-Forwarded-Proto", "")
            if fwd == "https" or self.headers.get("X-SSL") or \
                    self.headers.get("Front-End-Https", "") == "on":
                attrs += "; Secure"
            return self._json({"ok": True}, 200, [("Set-Cookie", attrs)])

        LOGIN_FAILS[ip] = [cnt + 1, first or time.time()]
        return self._json({"error": "用户名或密码错误"}, 401)

    def _h_change_login(self):
        body = self._read_body()
        user = (body.get("user") or "").strip()
        pw = (body.get("pass") or "").strip()
        if not user:
            return self._json({"success": False, "error": "登录名不能为空"})
        cur_u, cur_p = load_panel_auth()
        write_json_atomic(PANEL_AUTH_FILE,
                          {"webui_user": user, "webui_pass": pw if pw else cur_p})
        return self._json({"success": True, "message": "登录账号已更新"})

    # ── 概览 ────────────────────────────────────────────────────────
    def _h_overview(self):
        try:
            st = svrd_request("/status", timeout=15)
        except urllib.error.HTTPError as e:
            st = {"_error": "serverd HTTP %d（API Key 不匹配？）" % e.code}
        except Exception as e:
            st = {"_error": "无法连接 serverd: %s" % e}
        if isinstance(st, dict):
            st["_files"] = [{"uid": a["uid"], "disabled": a["disabled"]}
                            for a in list_auth_files()]
        # /status 里的 disabled 是「上游判定的失效」，与我们文件层的禁用合并展示
        commit = "unknown"
        try:
            with open(os.path.join(APP_DIR, "upstream-commit.txt"), encoding="utf-8") as f:
                commit = f.read().strip()[:7]
        except Exception:
            pass
        return self._json({"status": st, "upstream_commit": commit,
                           "server_time": now_str()})

    def _h_models(self):
        try:
            return self._json(svrd_request("/v1/models", timeout=30))
        except Exception as e:
            return self._json({"error": "无法获取模型列表: %s" % e}, 502)

    # ── 账号操作 ────────────────────────────────────────────────────
    def _h_account_toggle(self):
        body = self._read_body()
        uid = safe_uid((body.get("uid") or "").strip())
        if not uid:
            return self._json({"success": False, "error": "uid 非法"})
        a = find_auth_file(uid)
        if not a:
            return self._json({"success": False, "error": "账号不存在: %s" % uid})
        want_enabled = bool(body.get("enabled"))
        base = os.path.join(AUTH_DIR, "workbuddy-%s.json" % uid)
        disabled = base + ".disabled"
        try:
            if want_enabled and a["disabled"]:
                if os.path.exists(base):
                    return self._json({"success": False, "error": "目标文件已存在，存在冲突"})
                os.rename(disabled, base)
            elif (not want_enabled) and (not a["disabled"]):
                if os.path.exists(disabled):
                    return self._json({"success": False, "error": "禁用文件已存在，存在冲突"})
                os.rename(base, disabled)
        except Exception as e:
            return self._json({"success": False, "error": "文件操作失败: %s" % e})
        SRVD.restart()
        return self._json({"success": True,
                           "message": "账号已" + ("启用" if want_enabled else "禁用")})

    def _h_account_delete(self):
        body = self._read_body()
        uid = safe_uid((body.get("uid") or "").strip())
        if not uid:
            return self._json({"success": False, "error": "uid 非法"})
        a = find_auth_file(uid)
        if not a:
            return self._json({"success": False, "error": "账号不存在: %s" % uid})
        try:
            # 删除前备份，避免误操作无法挽回
            bak = os.path.join(DATA_DIR, "deleted-%s-%s.json"
                               % (uid, time.strftime("%Y%m%d%H%M%S")))
            shutil.copy2(a["path"], bak)
            os.remove(a["path"])
        except Exception as e:
            return self._json({"success": False, "error": "删除失败: %s" % e})
        SRVD.restart()
        return self._json({"success": True, "message": "账号已删除（已备份到 data/）"})

    # ── 登录编排 ────────────────────────────────────────────────────
    def _h_login_url(self):
        ok, out, err = run_bin(LOGIN_BIN, ["--realm=cn", "url"], timeout=60)
        text = (out or "") + (err or "")
        url = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("http"):
                url = line
                break
        if not url:
            return self._json({"error": "无法获取授权链接：%s" % text.strip()[:300]})
        return self._json({"url": url})

    def _h_login_poll(self):
        ok, out, err = run_bin(LOGIN_BIN, ["--realm=cn", "poll"], timeout=180)
        text = (out or "") + (err or "")
        if not ok:
            return self._json({"success": False, "error": text.strip()[:300] or "登录失败"})
        info = parse_login_poll(text)
        if not info.get("uid") or not info.get("access_token"):
            return self._json({"success": False,
                               "error": "登录响应缺少必要字段：%s" % text.strip()[:300]})
        try:
            write_auth_file(info)
        except Exception as e:
            return self._json({"success": False, "error": "写入凭证失败：%s" % e})
        SRVD.restart()
        return self._json({"success": True, "message": "账号已添加（uid=%s）" % info["uid"]})

    def _h_checkin(self):
        ok, out, err = run_bin(SIGNIN_BIN, [AUTH_DIR], timeout=600)
        return self._json({"success": ok, "output": (out or err or "").strip()[:8000]})

    def _h_credit(self):
        ok, out, err = run_bin(CREDIT_BIN, [], timeout=240,
                               env_extra={"WB2A_AUTH_DIR": AUTH_DIR})
        try:
            return self._json({"data": json.loads(out.strip()), "success": ok})
        except Exception:
            return self._json({"success": ok, "output": (out or err or "").strip()[:4000]})

    # ── 设置 ────────────────────────────────────────────────────────
    def _h_get_settings(self):
        cfg = read_json(CONFIG_FILE, {})
        opts = load_options()
        out = {}
        for k in EDITABLE_SETTINGS:
            v = get_path(cfg, k)
            if v is None:
                v = get_path(opts, k)
            out[k] = v
        return self._json({"settings": out})

    def _h_save_settings(self):
        body = self._read_body()
        cfg = read_json(CONFIG_FILE, {})
        changed, errors = [], []

        for k, val in body.items():
            if k not in EDITABLE_SETTINGS:
                continue
            typ, dflt = EDITABLE_SETTINGS[k]
            try:
                parsed = coerce(val, typ, dflt)
            except ValueError as e:
                errors.append("%s: %s" % (k, e))
                continue
            set_path(cfg, k, parsed)
            changed.append(k)

        if errors:
            return self._json({"success": False, "error": "；".join(errors)})
        if not changed:
            return self._json({"success": False, "error": "没有可保存的项"})

        # 同步回 options.json，避免容器重启后被 run.sh 用旧值覆盖
        opts = load_options()
        for k in changed:
            set_path(opts, k, get_path(cfg, k))
        try:
            write_json_atomic(CONFIG_FILE, cfg)
            write_json_atomic(OPTIONS_FILE, opts, mode=0o600)
        except Exception as e:
            return self._json({"success": False, "error": "写入失败: %s" % e})

        SRVD.restart()
        return self._json({"success": True,
                           "message": "已保存 %d 项并重载服务" % len(changed)})

    # ── /v1/* 反代 ──────────────────────────────────────────────────
    def _proxy(self, method):
        opts = load_options()
        want_key = (opts.get("api_key") or "").strip()
        if want_key:
            authz = self.headers.get("Authorization", "") or ""
            got = authz[7:].strip() if authz.lower().startswith("bearer ") else ""
            if not hmac.compare_digest(got, want_key):
                return self._json({"error": {"code": "invalid_api_key",
                                             "message": "missing or invalid API key",
                                             "type": "api_error"}}, 401)

        path = self._strip_ingress(self.path)
        url = "http://127.0.0.1:%d%s" % (SRVD_PORT, path)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "content-length", "connection")}
        body = None
        if method == "POST":
            ln = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(ln) if ln else b""

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:
            return self._json({"error": {"message": "upstream unavailable: %s" % e,
                                         "type": "api_error"}}, 502)

        ctype = resp.headers.get("Content-Type", "application/octet-stream")

        if "text/event-stream" not in ctype:
            # 非流式：读全再发，且必须显式 Content-Length，
            # 否则 HTTP/1.1 keep-alive 下客户端会一直等 body（实测踩到过）
            try:
                payload = resp.read()
            except Exception:
                payload = b""
            self.send_response(resp.status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            if payload:
                try:
                    self.wfile.write(payload)
                except Exception:
                    pass
            try:
                resp.close()
            except Exception:
                pass
            return

        # SSE：chunked 透传，逐块 flush
        self.send_response(resp.status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            while True:
                chunk = resp.read(1024)
                if not chunk:
                    break
                self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass

    def _read_body(self):
        try:
            ln = int(self.headers.get("Content-Length", 0) or 0)
            if not ln:
                return {}
            return json.loads(self.rfile.read(ln).decode("utf-8"))
        except Exception:
            return {}


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(AUTH_DIR, exist_ok=True)

    def shutdown(signum, frame):
        SRVD.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    SRVD.start()

    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    httpd.daemon_threads = True
    print("[wb2api] panel on 0.0.0.0:%d (serverd 127.0.0.1:%d)"
          % (LISTEN_PORT, SRVD_PORT), flush=True)
    if not webui_enabled():
        print("[wb2api] 面板登录未启用：管理接口仅允许 ingress 与本机回环。"
              "如需局域网访问请在设置中配置账号密码。", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
