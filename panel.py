#!/usr/bin/env python3
"""WB2API 管理面板 + OpenAI API 统一入口。

职责：
  1. 管理界面（登录编排、账号列表、积分、签到）—— 适配 HA ingress
  2. 反向代理 /v1/* 到本机 serverd

设计约束（刻意的「薄壳」）：
  - 只依赖 wb2api 的**稳定接口**：/status（JSON）、/v1/*（代理）、
    以及 login / signin / credit 三个 CLI。不碰上游内部实现，
    因此上游重构不会影响本面板。这是本 addon 维护成本低的关键。
  - 面板自带的鉴权（会话 cookie / ingress / 回环判定）与 /v1/* 的
    api_key 是**两条独立链路**，互不影响。

安全实现说明：
  - 会话 token 用 secrets.token_urlsafe（不可预测）
  - cookie 比较用 hmac.compare_digest（恒定时间）
  - 未启用面板登录时，只信任 ingress 转发与本机回环，
    不放行整个内网（ingress 与 LAN 源 IP 同属内网，仅凭 IP 无法区分）
"""
import datetime
import hashlib
import hmac
import http.server
import json
import os
import secrets
import signal
import socket
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
SRVD_PORT = 7864                      # serverd 实际监听端口（面板再代理）
WEBUI_COOKIE = "wb2api_session"

LOGIN_FAILS = {}                      # ip -> [次数, 首次失败时间]
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 300


# ── 通用工具 ────────────────────────────────────────────────────────
def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def load_options():
    return read_json(OPTIONS_FILE, {})


def load_panel_auth():
    """面板登录凭据（由 run.sh 从 HA options 提取）。"""
    d = read_json(PANEL_AUTH_FILE, {})
    return (d.get("webui_user") or "").strip(), (d.get("webui_pass") or "").strip()


def webui_enabled():
    u, p = load_panel_auth()
    return bool(u and p)


# ── 会话 ────────────────────────────────────────────────────────────
def new_session():
    """生成并持久化会话 token（密码学随机）。失败返回空串。"""
    tok = secrets.token_urlsafe(32)
    try:
        fd = os.open(SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(tok)
    except Exception:
        return ""
    return tok


def check_session(cookie_val):
    """恒定时间比较，避免时序侧信道。"""
    if not cookie_val:
        return False
    want = ""
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            want = f.read().strip()
    except Exception:
        return False
    return bool(want) and hmac.compare_digest(want, cookie_val.strip())


# ── 子进程调用（login / signin / credit）────────────────────────────
def run_bin(bin_path, args, timeout=120, env_extra=None):
    """跑一次 CLI，返回 (ok, stdout, stderr)。"""
    if not os.path.isfile(bin_path):
        return False, "", "二进制不存在: %s" % bin_path
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run([bin_path] + list(args),
                           cwd=APP_DIR, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return p.returncode == 0, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return False, "", "超时（%ss）" % timeout
    except Exception as e:
        return False, "", str(e)


def _parse_login_poll_output(text):
    """解析 `login poll` 的 JSON 输出。

    上游 buildLoginOutput 的键（实测自上源码 cmd/login/main.go）：
        access_token, refresh_token, expires_in, domain, realm,
        uid, enterprise_id, nickname
    注意是 **snake_case**，与落盘 auth 文件的 camelCase 不同。
    """
    # poll 可能混有 stderr 提示，取最后一个 JSON 对象
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


def _write_auth_file(info):
    """按 login.sh 的同款格式落盘 auth 文件。

    目标格式（与 internal/auth 的嵌套形态一致）：
        {"account": {"uid","enterpriseId","nickname"},
         "auth":    {"accessToken","refreshToken","expiresAt","domain","realm"}}

    expires_in 是相对秒数，需换算成绝对 expiresAt。
    """
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
    # 唯一临时名 + rename：与 serverd 并发读写时不会互相踩（同 ai-proxy 的 atomicfile 思路）
    tmp = "%s.tmp-%s" % (path, secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise
    return path


def fetch_status():
    """读 serverd 的 /status（JSON）。

    注意：serverd 的 /status 也受 api_key 保护，面板必须带上它 ——
    否则拿到的是 401（实测踩到过）。
    """
    key = (load_options().get("api_key") or "").strip()
    headers = {"Authorization": "Bearer %s" % key} if key else {}
    try:
        req = urllib.request.Request("http://127.0.0.1:%d/status" % SRVD_PORT,
                                     headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": "HTTP %d: %s" % (e.code, "API Key 不匹配" if e.code == 401 else e.reason)}
    except Exception as e:
        return {"_error": str(e)}


# ── serverd 子进程管理 ──────────────────────────────────────────────
class Serverd:
    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return
            # serverd 用 -config 指定配置；监听端口由 config.json 的 listen 决定
            self.proc = subprocess.Popen(
                [SRVD_BIN, "-config", CONFIG_FILE],
                cwd=APP_DIR, stdout=sys.stdout, stderr=sys.stderr,
            )

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


# ── HTML 页面 ───────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WB2API 管理</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1f2329;--muted:#646a73;--line:#e5e6eb;
--pri:#3370ff;--ok:#00b42a;--warn:#ff7d00;--err:#f53f3f}
@media(prefers-color-scheme:dark){:root{--bg:#17171a;--card:#232324;--fg:#e5e6eb;
--muted:#8f959e;--line:#333335}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
background:var(--bg);color:var(--fg)}
.wrap{max-width:960px;margin:0 auto;padding:20px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button{background:var(--pri);color:#fff;border:0;border-radius:6px;padding:8px 16px;
font-size:14px;cursor:pointer}
button.sec{background:transparent;color:var(--pri);border:1px solid var(--pri)}
button:disabled{opacity:.5;cursor:not-allowed}
input{background:var(--bg);border:1px solid var(--line);color:var(--fg);
border-radius:6px;padding:8px 10px;font-size:14px;min-width:200px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:500}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.t-ok{background:rgba(0,180,42,.12);color:var(--ok)}
.t-cool{background:rgba(255,125,0,.12);color:var(--warn)}
.t-off{background:rgba(245,63,63,.12);color:var(--err)}
.t-mut{background:var(--bg);color:var(--muted)}
.stat{display:flex;gap:22px;flex-wrap:wrap}
.stat div b{font-size:20px;display:block}
.stat div span{color:var(--muted);font-size:12px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;
overflow:auto;max-height:320px;font-size:12px;white-space:pre-wrap;word-break:break-all}
#toast{position:fixed;right:20px;bottom:20px;background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:10px 16px;display:none;box-shadow:0 4px 16px rgba(0,0,0,.12)}
.hint{color:var(--muted);font-size:12px;margin-top:6px}
a{color:var(--pri)}
</style>
</head>
<body>
<div class="wrap">
  <h1>WB2API 管理</h1>
  <div class="sub">WorkBuddy / CodeBuddy 多账号 → OpenAI 兼容 API
    <span id="uptime"></span></div>

  <div class="card">
    <div class="stat" id="stats"><span class="hint">加载中…</span></div>
  </div>

  <div class="card">
    <div class="row">
      <button onclick="doLogin()">添加账号</button>
      <button class="sec" onclick="doCheckin()">立即签到</button>
      <button class="sec" onclick="doCredit()">查询积分</button>
      <button class="sec" onclick="load()">刷新</button>
    </div>
    <div class="hint">添加账号会打开 WorkBuddy 授权页；完成登录后回到本页即可。</div>
  </div>

  <div class="card">
    <div style="margin-bottom:10px;color:var(--muted)">账号列表</div>
    <table>
      <thead><tr><th>UID</th><th>昵称</th><th>域</th><th>积分</th><th>状态</th><th>说明</th></tr></thead>
      <tbody id="accts"><tr><td colspan="6" class="hint">加载中…</td></tr></tbody>
    </table>
  </div>

  <div class="card" id="out-card" style="display:none">
    <div class="row" style="justify-content:space-between">
      <b id="out-title">输出</b>
      <button class="sec" onclick="document.getElementById('out-card').style.display='none'">关闭</button>
    </div>
    <pre id="out"></pre>
  </div>
</div>
<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
function toast(m, err){const t=$('#toast');t.textContent=m;
  t.style.borderColor = err ? 'var(--err)' : 'var(--line)';
  t.style.display='block';clearTimeout(t._h);t._h=setTimeout(()=>t.style.display='none',4000);}
function show(title, text){
  $('#out-title').textContent = title;
  $('#out').textContent = text;
  $('#out-card').style.display='block';
}
async function api(path, opt){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}}, opt||{}));
  const t = await r.text();
  try { return JSON.parse(t); } catch(e){ return {error:t}; }
}

function tag(a){
  if(a.disabled) return '<span class="tag t-off">禁用</span>';
  if(a.cooling)  return '<span class="tag t-cool">冷却</span>';
  return '<span class="tag t-ok">正常</span>';
}

async function load(){
  const d = await api('api/overview');
  if(d.error){ $('#stats').innerHTML = '<span class="tag t-off">'+d.error+'</span>'; return; }
  const s = d.status || {};
  $('#stats').innerHTML =
    `<div><b>${s.healthy ?? '-'}</b><span>健康</span></div>
     <div><b>${s.total ?? '-'}</b><span>总数</span></div>
     <div><b>${s.cooling ?? 0}</b><span>冷却中</span></div>
     <div><b>${s.disabled ?? 0}</b><span>已禁用</span></div>
     <div><b>${d.upstream_commit || '-'}</b><span>上游版本</span></div>`;
  $('#uptime').textContent = d.server_time ? '· ' + d.server_time : '';

  const accts = s.accounts || [];
  if(!accts.length){
    $('#accts').innerHTML = '<tr><td colspan="6" class="hint">还没有账号，点「添加账号」开始</td></tr>';
    return;
  }
  $('#accts').innerHTML = accts.map(a => `<tr>
    <td>${a.uid || ''}</td>
    <td>${a.nickname || '-'}</td>
    <td>${a.realm || 'cn'}</td>
    <td>${a.credits ?? '-'}</td>
    <td>${tag(a)}</td>
    <td>${a.reason || a.cool_kind || ''}</td>
  </tr>`).join('');
}

async function doLogin(){
  const d = await api('api/login-url');
  if(d.error){ toast(d.error, true); return; }
  show('请完成授权', '授权链接：\n' + d.url + '\n\n' +
       (d.user_code ? '设备码：' + d.user_code + '\n\n' : '') +
       '在浏览器打开上面的链接完成登录，然后点下面的「我已完成登录」。');
  const btn = document.createElement('button');
  btn.textContent = '我已完成登录';
  btn.style.marginTop = '10px';
  btn.onclick = async () => {
    btn.disabled = true;
    const r = await api('api/login-poll', {method:'POST', body:'{}'});
    toast(r.message || r.error, !!r.error);
    if(r.success) load();
    btn.remove();
  };
  $('#out').after(btn);
  window.open(d.url, '_blank');
}

async function doCheckin(){
  const d = await api('api/checkin', {method:'POST', body:'{}'});
  show('签到结果', d.output || d.error || '(无输出)');
  toast(d.success ? '签到完成' : (d.error||'签到失败'), !d.success);
  load();
}

async function doCredit(){
  const d = await api('api/credit');
  if(d.data) show('积分', JSON.stringify(d.data, null, 2));
  else show('积分', d.output || d.error || '(无输出)');
}

load();
setInterval(load, 30000);
</script>
</body>
</html>
"""

LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WB2API 登录</title>
<style>
body{margin:0;font:14px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;
background:#17171a;color:#e5e6eb;display:flex;align-items:center;justify-content:center;
min-height:100vh}
.box{background:#232324;border:1px solid #333335;border-radius:12px;padding:28px;width:320px}
h1{font-size:18px;margin:0 0 20px}
input{width:100%;background:#17171a;border:1px solid #333335;color:#e5e6eb;
border-radius:6px;padding:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box}
button{width:100%;background:#3370ff;color:#fff;border:0;border-radius:6px;
padding:10px;font-size:14px;cursor:pointer}
#msg{color:#f53f3f;font-size:13px;margin-top:10px;min-height:18px}
</style></head>
<body><div class="box">
<h1>WB2API 管理登录</h1>
<input id="u" placeholder="用户名" autocomplete="username">
<input id="p" type="password" placeholder="密码" autocomplete="current-password">
<button onclick="go()">登录</button>
<div id="msg"></div>
</div>
<script>
async function go(){
  const u=document.getElementById('u').value, p=document.getElementById('p').value;
  const r = await fetch('api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user:u,pass:p})});
  const d = await r.json().catch(()=>({error:'响应异常'}));
  if(r.ok){ location.href = './'; } else { document.getElementById('msg').textContent = d.error||'登录失败'; }
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "wb2api-panel"

    # 不把每个请求打到 stderr（面板自身足够安静；serverd 的日志已进 stdout）
    def log_message(self, fmt, *args):
        pass

    # ── 响应助手 ────────────────────────────────────────────────────
    def _send(self, body, ctype="text/html; charset=utf-8", code=200, extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200, extra_headers=None):
        self._send(json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8", code, extra_headers)

    # ── 来源判定 ────────────────────────────────────────────────────
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
        """管理接口鉴权。

        1. 有效会话 → 放行
        2. 未启用面板登录时：只信任 ingress 与本机回环。
           **不放行整个内网** —— ingress(172.30.x) 与 LAN(192.168.x)
           源 IP 同属内网，仅凭 IP 无法区分；而 7863 映射到宿主机，
           默许内网等于把管理接口暴露给同网段任意设备。
        """
        if check_session(self._cookie()):
            return True
        if webui_enabled():
            return False
        return self._is_ingress() or self._is_loopback()

    def _strip_ingress(self, path):
        """剥离 HA ingress 前缀 /api/hassio_ingress/<token>/。"""
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

        if path == "/api/login":
            return self._send(LOGIN_PAGE)

        if path.startswith("/v1/"):
            return self._proxy("GET")

        if not self._mgmt_authorized():
            return self._json({"error": "未登录，请先访问面板首页登录"}, 401)

        if path == "/api/overview":
            return self._handle_overview()
        if path == "/api/credit":
            return self._handle_credit()
        if path == "/api/login-url":
            return self._handle_login_url()

        return self._json({"error": "not found: %s" % path}, 404)

    def do_POST(self):
        path = self._strip_ingress(self.path.split("?")[0])

        if path == "/api/login":
            return self._handle_login_post()

        if path.startswith("/v1/"):
            return self._proxy("POST")

        if not self._mgmt_authorized():
            return self._json({"error": "未登录，请先访问面板首页登录"}, 401)

        if path == "/api/login-poll":
            return self._handle_login_poll()
        if path == "/api/checkin":
            return self._handle_checkin()
        if path == "/api/logout":
            try:
                os.remove(SESSION_FILE)
            except Exception:
                pass
            return self._json({"ok": True})

        return self._json({"error": "not found: %s" % path}, 404)

    # ── 各接口实现 ──────────────────────────────────────────────────
    def _handle_login_post(self):
        ip = self._client_ip()
        cnt, first = LOGIN_FAILS.get(ip, [0, 0])
        if cnt >= LOGIN_MAX_FAILS and time.time() - first < LOGIN_LOCK_SECONDS:
            return self._json({"error": "尝试次数过多，请 5 分钟后再试"}, 429)

        body = self._read_body()
        user = (body.get("user") or "").strip()
        pw = (body.get("pass") or "").strip()
        want_user, want_pass = load_panel_auth()

        if want_user and hmac.compare_digest(user, want_user) and hmac.compare_digest(pw, want_pass):
            LOGIN_FAILS.pop(ip, None)
            tok = new_session()
            if not tok:
                return self._json({"error": "会话创建失败，请检查容器磁盘空间与权限"}, 500)
            attrs = "%s=%s; Path=/; HttpOnly; SameSite=Lax" % (WEBUI_COOKIE, tok)
            fwd = self.headers.get("X-Forwarded-Proto", "")
            if fwd == "https" or self.headers.get("X-SSL") or \
               self.headers.get("Front-End-Https", "") == "on":
                attrs += "; Secure"
            return self._json({"ok": True}, 200, [("Set-Cookie", attrs)])

        LOGIN_FAILS[ip] = [cnt + 1, first or time.time()]
        return self._json({"error": "用户名或密码错误"}, 401)

    def _handle_overview(self):
        st = fetch_status()
        commit = "unknown"
        try:
            with open(os.path.join(APP_DIR, "upstream-commit.txt"), encoding="utf-8") as f:
                commit = f.read().strip()[:7]
        except Exception:
            pass
        return self._json({"status": st, "upstream_commit": commit,
                           "server_time": now_str()})

    def _handle_credit(self):
        # credit 没有目录参数，走环境变量 WB2A_AUTH_DIR 指定凭证目录
        ok, out, err = run_bin(CREDIT_BIN, [], timeout=180,
                               env_extra={"WB2A_AUTH_DIR": AUTH_DIR})
        # credit 默认输出 JSON；解析失败则返回原始文本
        try:
            return self._json({"data": json.loads(out.strip()), "success": ok})
        except Exception:
            return self._json({"success": ok, "output": (out or err or "").strip()[:4000]})

    def _handle_login_url(self):
        # login 是子命令式：login [--realm=cn|global] url|poll
        # realm 由面板选项决定（默认 cn）
        realm = "cn"
        ok, out, err = run_bin(LOGIN_BIN, ["--realm=%s" % realm, "url"], timeout=60)
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

    def _handle_login_poll(self):
        # poll 会输出 token+uid 等；凭证落盘由我们按 login.sh 的同款格式完成
        realm = "cn"
        ok, out, err = run_bin(LOGIN_BIN, ["--realm=%s" % realm, "poll"], timeout=180)
        text = (out or "") + (err or "")
        if not ok:
            return self._json({"success": False, "error": text.strip()[:300] or "登录失败"})

        info = _parse_login_poll_output(text)
        if not info.get("uid") or not info.get("accessToken"):
            return self._json({
                "success": False,
                "error": "登录响应缺少必要字段（uid / accessToken）：%s" % text.strip()[:300],
            })

        try:
            _write_auth_file(info)
        except Exception as e:
            return self._json({"success": False, "error": "写入凭证失败：%s" % e})

        SRVD.restart()      # 新账号落盘后让 serverd 重新加载
        return self._json({"success": True,
                           "message": "账号已添加（uid=%s）" % info["uid"]})

    def _handle_checkin(self):
        # signin 取位置参数（凭证目录），无 -config
        ok, out, err = run_bin(SIGNIN_BIN, [AUTH_DIR], timeout=300)
        return self._json({"success": ok, "output": (out or err or "").strip()[:4000]})

    # ── /v1/* 反代 ──────────────────────────────────────────────────
    def _proxy(self, method):
        o = load_options()
        want_key = (o.get("api_key") or "").strip()
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
        is_sse = "text/event-stream" in ctype

        # 非流式响应：先读完整 body 再发，并**显式给出 Content-Length**。
        # 原因：BaseHTTPRequestHandler 默认 protocol_version=HTTP/1.0，
        # 不发 Content-Length 且不关闭连接时，客户端读不到 body（实测踩到过）。
        if not is_sse:
            try:
                payload = resp.read()
            except Exception as e:
                payload = b""
                ctype = "application/json"
                self.send_response(502)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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

        # SSE 流式：用 chunked 语义 —— 逐块写出并 flush。
        # HTTP/1.0 下无法用 chunked，故对流式响应声明 Connection: close，
        # 由连接关闭标识结束（客户端按 SSE 规范读到流结束）。
        self.send_response(resp.status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        try:
            while True:
                chunk = resp.read(1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass
            self.close_connection = True

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
    print("[wb2api] panel listening on 0.0.0.0:%d (serverd on 127.0.0.1:%d)"
          % (LISTEN_PORT, SRVD_PORT), flush=True)
    if not webui_enabled():
        print("[wb2api] 面板登录未启用：管理接口仅允许 ingress 转发与本机回环访问。"
              "如需从局域网访问，请在设置中配置面板账号/密码。", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
