#!/usr/bin/env bash
# WB2API add-on 入口。
#
# 职责：把 HA 的 options（/data/options.json）翻译成 wb2api 的 config.json，
# 然后启动 serverd。面板（panel.py）负责登录编排与管理界面。
set -euo pipefail

OPTIONS=/data/options.json
CONFIG=/data/data/config.json
AUTH_DIR=/data/auths
STATE=/data/data/state.json
# 面板登录凭据另存（serverd 不认这两个字段，只有 panel.py 用）
PANEL_AUTH_FILE=/data/data/panel-auth.json

log() { echo "[wb2api] $*"; }

# ── 读取 HA options ──────────────────────────────────────────────
# jq 取键，缺省为空（config.yaml 已给默认值，这里只做兜底）
opt() { jq -r --arg k "$1" '.[$k] // empty' "$OPTIONS" 2>/dev/null || true; }

API_KEY="$(opt api_key)"
WEBUI_USER="$(opt webui_user)"
WEBUI_PASS="$(opt webui_pass)"
LOG_LEVEL="$(opt log_level)"

mkdir -p "$AUTH_DIR" "$(dirname "$STATE")"

# ── 生成 config.json ─────────────────────────────────────────────
# 把逗号分隔的整点串 "9,21" 转成 JSON 数组 [9,21]
hours_json() {
  local raw="$1"
  if [ -z "$raw" ]; then echo '[]'; return; fi
  echo "$raw" | tr ',' '\n' | sed 's/[^0-9]//g' | grep -v '^$' \
    | jq -s 'map(select(. >= 0 and . <= 23))' 2>/dev/null || echo '[]'
}

# 数值兜底：空值给默认
num() { local v="$1" d="$2"; [ -z "$v" ] && echo "$d" || echo "$v"; }
str() { local v="$1" d="$2"; [ -z "$v" ] && echo "$d" || echo "$v"; }
json_str() { printf '%s' "$1" | jq -Rs .; }

# bool：把 options 里的布尔转成 JSON 字面量。
# 不能用 `$(bool "$(opt k)" true)` —— 在 JSON heredoc 里空值会替换成空白，
# 产生 `"enabled": ,` 这样的非法 JSON（实测踩到过）。
bool() { local v="$1" d="$2"; v="$(printf '%s' "$v" | tr 'A-Z' 'a-z')";
         case "$v" in true|false) echo "$v" ;; *) echo "$d" ;; esac; }

CHECKIN_HOURS="$(hours_json "$(opt checkin_hours)")"
TRAVEL_HOURS="$(hours_json "$(opt travel_hours)")"
ACTIVITY_HOURS="$(hours_json "$(opt activity_hours)")"
KEEPALIVE_HOURS="$(hours_json "$(opt keepalive_hours)")"
SCHOOL_HOURS="$(hours_json "$(opt school_hours)")"
CAT_HOURS="$(hours_json "$(opt cat_hours)")"

cat > "$CONFIG" <<JSON
{
  "listen": ":7863",
  "api_key": $(json_str "$API_KEY"),
  "auth_dir": $(json_str "$AUTH_DIR"),
  "state_file": $(json_str "$STATE"),
  "log_level": $(json_str "$(str "$LOG_LEVEL" info)"),
  "server": {
    "max_body_mb": 8
  },
  "cooldown": {
    "soft_rate": $(json_str "$(str "$(opt soft_rate)" 600s)"),
    "soft_rate_max": $(json_str "$(str "$(opt soft_rate_max)" 2h)")
  },
  "schedule": {
    "checkin_hours":   $CHECKIN_HOURS,
    "travel_hours":    $TRAVEL_HOURS,
    "activity_hours":  $ACTIVITY_HOURS,
    "keepalive_hours": $KEEPALIVE_HOURS,
    "school_hours":    $SCHOOL_HOURS,
    "cat_hours":       $CAT_HOURS,
    "checkin_enabled":   $(bool "$(opt checkin_enabled)" true),
    "travel_enabled":    $(bool "$(opt travel_enabled)" true),
    "activity_enabled":  $(bool "$(opt activity_enabled)" true),
    "keepalive_enabled": $(bool "$(opt keepalive_enabled)" true),
    "school_enabled":    $(bool "$(opt school_enabled)" true),
    "cat_enabled":       $(bool "$(opt cat_enabled)" true)
  },
  "global": {
    "enabled": $(bool "$(opt global_enabled)" true),
    "chat_base": "",
    "billing_base": ""
  },
  "upstream": {
    "timeout_seconds": $(num "$(opt timeout_seconds)" 120),
    "header_timeout_seconds": $(num "$(opt header_timeout_seconds)" 120),
    "idle_timeout_seconds": $(num "$(opt idle_timeout_seconds)" 300),
    "client_name": "WorkBuddy"
  },
  "features": {
    "sanitize_blacklist_fingerprints": $(bool "$(opt sanitize_fingerprints)" true)
  },
  "prompt": {
    "mode": $(json_str "$(str "$(opt prompt_mode)" passthrough)"),
    "file": $(json_str "$(opt prompt_file)")
  },
  "upstash": { "url": "", "token": "" },
  "pool": {
    "max_in_flight": $(num "$(opt max_in_flight)" 3),
    "max_in_flight_global": $(num "$(opt max_in_flight_global)" 2),
    "breaker_threshold": $(num "$(opt breaker_threshold)" 3),
    "breaker_cooldown": $(json_str "$(str "$(opt breaker_cooldown)" 30m)"),
    "breaker_cooldown_max": $(json_str "$(str "$(opt breaker_cooldown_max)" 6h)"),
    "idle_weight_per_hour": $(num "$(opt idle_weight_per_hour)" 0.5),
    "idle_weight_max": $(num "$(opt idle_weight_max)" 5.0),
    "expiring_soon": $(json_str "$(str "$(opt expiring_soon)" 168h)")
  },
  "session_sticky": {
    "enabled": $(bool "$(opt session_sticky_enabled)" true),
    "ttl": $(json_str "$(str "$(opt session_sticky_ttl)" 30m)"),
    "gc_interval": "5m"
  }
}
JSON

# 校验生成的 JSON（fail fast，避免带着坏配置启动）
if ! jq -e . "$CONFIG" >/dev/null 2>&1; then
  log "ERROR: 生成的 config.json 不是合法 JSON，内容如下："
  cat "$CONFIG"
  exit 1
fi

# 面板需要的 WebUI 凭据另存一份（serverd 不认这两个字段）
jq -n --arg u "$WEBUI_USER" --arg p "$WEBUI_PASS" '{webui_user:$u, webui_pass:$p}' \
  > "$PANEL_AUTH_FILE"

chmod 600 "$CONFIG" "$PANEL_AUTH_FILE" 2>/dev/null || true

log "upstream commit: $(cat /app/upstream-commit.txt 2>/dev/null || echo unknown)"
log "auth_dir=$AUTH_DIR  accounts=$(find "$AUTH_DIR" -name 'workbuddy*.json' 2>/dev/null | wc -l)"
if [ -z "$API_KEY" ]; then
  log "WARNING: api_key 为空 —— OpenAI API 将不校验鉴权，请仅在可信网络中使用"
fi

# ── 启动面板（它同时托管 serverd 子进程与 /v1/* 反向代理）────────
exec python3 /app/panel.py
