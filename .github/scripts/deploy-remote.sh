#!/usr/bin/env bash
set -Eeuo pipefail

required=(
  DEPLOY_PATH DEPLOY_SERVICE DEPLOY_HEALTH_URL DEPLOY_BACKUP_DIR
  DEPLOY_BACKUP_KEEP RELEASE_ARCHIVE DEPLOY_SHA
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: missing environment variable ${name}" >&2
    exit 1
  fi
done

DEPLOY_CLIPROXY="${DEPLOY_CLIPROXY:-0}"
if [[ "$DEPLOY_CLIPROXY" == "1" ]]; then
  cliproxy_required=(CLIPROXY_DEPLOY_PATH CLIPROXY_SERVICE CLIPROXY_BINARY CLIPROXY_MANAGEMENT_ENV)
  for name in "${cliproxy_required[@]}"; do
    if [[ -z "${!name:-}" ]]; then
      echo "ERROR: missing environment variable ${name}" >&2
      exit 1
    fi
  done
fi

DEPLOY_PATH="${DEPLOY_PATH%/}"
[[ "$DEPLOY_PATH" == /* && "$DEPLOY_PATH" != "/" ]] || { echo "ERROR: invalid DEPLOY_PATH" >&2; exit 1; }
[[ "$DEPLOY_BACKUP_DIR" == /* ]] || { echo "ERROR: DEPLOY_BACKUP_DIR must be absolute" >&2; exit 1; }
[[ "$DEPLOY_SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "ERROR: invalid DEPLOY_SERVICE" >&2; exit 1; }
[[ "$DEPLOY_BACKUP_KEEP" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid DEPLOY_BACKUP_KEEP" >&2; exit 1; }
[[ -f "$RELEASE_ARCHIVE" ]] || { echo "ERROR: release archive not found" >&2; exit 1; }
if [[ "$DEPLOY_CLIPROXY" == "1" ]]; then
  [[ "$CLIPROXY_DEPLOY_PATH" == /* && "$CLIPROXY_DEPLOY_PATH" != "/" ]] || { echo "ERROR: invalid CLIPROXY_DEPLOY_PATH" >&2; exit 1; }
  [[ "$CLIPROXY_SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "ERROR: invalid CLIPROXY_SERVICE" >&2; exit 1; }
  [[ -f "$CLIPROXY_BINARY" && -x "$CLIPROXY_BINARY" ]] || { echo "ERROR: CLIProxyAPI binary not found" >&2; exit 1; }
  [[ -f "$CLIPROXY_MANAGEMENT_ENV" ]] || { echo "ERROR: CLIProxyAPI management environment not found" >&2; exit 1; }
fi

for command in curl flock rsync systemctl tar; do
  command -v "$command" >/dev/null || { echo "ERROR: required command not found: ${command}" >&2; exit 1; }
done

if [[ $EUID -eq 0 ]]; then
  SYSTEMCTL=(systemctl)
else
  command -v sudo >/dev/null || { echo "ERROR: sudo is required for non-root deployment" >&2; exit 1; }
  SYSTEMCTL=(sudo -n systemctl)
fi

CLI_SYSTEMCTL=(systemctl --user)

UV_BIN="$(command -v uv || true)"
if [[ -z "$UV_BIN" && -x "$HOME/.local/bin/uv" ]]; then
  UV_BIN="$HOME/.local/bin/uv"
fi
[[ -n "$UV_BIN" ]] || { echo "ERROR: uv is not installed on the server" >&2; exit 1; }

umask 077
mkdir -p "$DEPLOY_PATH" "$DEPLOY_BACKUP_DIR"
exec 9>"$DEPLOY_PATH/.github-deploy.lock"
flock -w 10 9 || { echo "ERROR: another deployment is running" >&2; exit 1; }

STAGING_DIR="$(mktemp -d /tmp/grok-reg-release.XXXXXX)"
EXISTING_FILES="$(mktemp /tmp/grok-reg-existing.XXXXXX)"
NEW_FILES="$(mktemp /tmp/grok-reg-new.XXXXXX)"
BACKUP_FILE="$DEPLOY_BACKUP_DIR/deploy-$(TZ=Asia/Shanghai date +%Y%m%d_%H%M%S)-${DEPLOY_SHA:0:12}.tar.gz"
CLIPROXY_BACKUP="$DEPLOY_BACKUP_DIR/cliproxy-$(TZ=Asia/Shanghai date +%Y%m%d_%H%M%S)-${DEPLOY_SHA:0:12}"
WEBUI_CONFIG_BACKUP="$DEPLOY_BACKUP_DIR/config-$(TZ=Asia/Shanghai date +%Y%m%d_%H%M%S)-${DEPLOY_SHA:0:12}.json"
DEPLOY_APPLIED=0
CLIPROXY_APPLIED=0
WEBUI_CONFIG_APPLIED=0

cleanup() {
  rm -rf -- "$STAGING_DIR"
  rm -f -- "$EXISTING_FILES" "$NEW_FILES" "$RELEASE_ARCHIVE"
  if [[ "$DEPLOY_CLIPROXY" == "1" ]]; then
    rm -f -- "$CLIPROXY_BINARY" "$CLIPROXY_MANAGEMENT_ENV"
  fi
}
trap cleanup EXIT

rollback() {
  echo "Deployment failed; restoring ${BACKUP_FILE}" >&2
  while IFS= read -r -d '' relative; do
    rm -f -- "$DEPLOY_PATH/$relative"
  done <"$NEW_FILES"
  tar -xzf "$BACKUP_FILE" -C "$DEPLOY_PATH"
  (
    cd "$DEPLOY_PATH"
    "$UV_BIN" sync --frozen
  ) || echo "WARNING: dependency rollback failed" >&2
  if [[ $WEBUI_CONFIG_APPLIED -eq 1 && -f "$WEBUI_CONFIG_BACKUP" ]]; then
    install -m 600 "$WEBUI_CONFIG_BACKUP" "$DEPLOY_PATH/config.json" || true
  fi
  if [[ $CLIPROXY_APPLIED -eq 1 && -f "$CLIPROXY_BACKUP" ]]; then
    install -m 755 "$CLIPROXY_BACKUP" "$CLIPROXY_DEPLOY_PATH/cli-proxy-api" || true
    "${CLI_SYSTEMCTL[@]}" restart "$CLIPROXY_SERVICE" || echo "WARNING: CLIProxyAPI rollback restart failed" >&2
  fi
  "${SYSTEMCTL[@]}" restart "$DEPLOY_SERVICE" || echo "WARNING: service restart after rollback failed" >&2
}

on_error() {
  local exit_code=$?
  local line=${1:-unknown}
  trap - ERR
  echo "ERROR: deployment command failed at line ${line} (exit ${exit_code})" >&2
  if [[ $DEPLOY_APPLIED -eq 1 || $CLIPROXY_APPLIED -eq 1 || $WEBUI_CONFIG_APPLIED -eq 1 ]]; then
    rollback
  fi
  exit "$exit_code"
}
trap 'on_error "$LINENO"' ERR

tar -xzf "$RELEASE_ARCHIVE" -C "$STAGING_DIR"
[[ -f "$STAGING_DIR/pyproject.toml" && -f "$STAGING_DIR/uv.lock" ]] || {
  echo "ERROR: release archive is missing pyproject.toml or uv.lock" >&2
  exit 1
}

while IFS= read -r -d '' relative; do
  relative="${relative#./}"
  case "$relative" in
    config.json|config.local.json|config.json.bak*|.env|accounts_*.txt|emails_used.txt|emails_error.txt|emails_error.txt.*|proxies.txt|*/proxies.txt|proxies_state.json|*/proxies_state.json|mail_credentials.txt|*/mail_credentials.txt|mail_tool_credentials.txt|*/mail_tool_credentials.txt|cpa_pool_state.json|*/cpa_pool_state.json|cpa_pool_state.sqlite3*|*/cpa_pool_state.sqlite3*|cpa_pool_scan.journal.jsonl|*/cpa_pool_scan.journal.jsonl|mail_tool_state.json|*/mail_tool_state.json|cpa_auths/*|*/cpa_auths/*|cpa_quarantine/*|*/cpa_quarantine/*|cookies/*|*/cookies/*|screenshots/*|*/screenshots/*|*.log|*.bak|*.pyc|*/__pycache__/*|.venv/*)
      echo "ERROR: release archive contains protected runtime file: ${relative}" >&2
      exit 1
      ;;
  esac
  if [[ -e "$DEPLOY_PATH/$relative" || -L "$DEPLOY_PATH/$relative" ]]; then
    printf '%s\0' "$relative" >>"$EXISTING_FILES"
  else
    printf '%s\0' "$relative" >>"$NEW_FILES"
  fi
done < <(cd "$STAGING_DIR" && find . \( -type f -o -type l \) -print0)

tar -C "$DEPLOY_PATH" --null -T "$EXISTING_FILES" -czf "$BACKUP_FILE"
echo "Backup created: ${BACKUP_FILE}"

DEPLOY_APPLIED=1
rsync -a "$STAGING_DIR/" "$DEPLOY_PATH/"
cd "$DEPLOY_PATH"
"$UV_BIN" sync --frozen
PYTHON_BIN="$DEPLOY_PATH/.venv/bin/python"
[[ -x "$PYTHON_BIN" ]] || { echo "ERROR: deployment Python environment was not created" >&2; exit 1; }

if [[ "$DEPLOY_CLIPROXY" == "1" ]]; then
  cp -p "$CLIPROXY_DEPLOY_PATH/cli-proxy-api" "$CLIPROXY_BACKUP"
  CLIPROXY_APPLIED=1

  management_key="$(awk -F= '/^CPA_POOL_CLI_MANAGEMENT_KEY=/{print substr($0, index($0, "=") + 1); exit}' "$CLIPROXY_MANAGEMENT_ENV")"
  [[ "$management_key" =~ ^[A-Za-z0-9._~-]{32,}$ ]] || { echo "ERROR: invalid management key file" >&2; exit 1; }
  install -m 600 "$CLIPROXY_MANAGEMENT_ENV" "$CLIPROXY_DEPLOY_PATH/management.env"

  mkdir -p "$HOME/.config/systemd/user/${CLIPROXY_SERVICE}.d"
  cat >"$HOME/.config/systemd/user/${CLIPROXY_SERVICE}.d/management.conf" <<EOF
[Service]
EnvironmentFile=${CLIPROXY_DEPLOY_PATH}/management.env
EOF

  system_dropin="/etc/systemd/system/${DEPLOY_SERVICE}.d"
  if [[ $EUID -eq 0 ]]; then
    mkdir -p "$system_dropin"
    cat >"$system_dropin/cpa-pool-management.conf" <<EOF
[Service]
EnvironmentFile=${CLIPROXY_DEPLOY_PATH}/management.env
EOF
  else
    sudo -n mkdir -p "$system_dropin"
    printf '[Service]\nEnvironmentFile=%s/management.env\n' "$CLIPROXY_DEPLOY_PATH" \
      | sudo -n tee "$system_dropin/cpa-pool-management.conf" >/dev/null
  fi

  if [[ -f "$DEPLOY_PATH/config.json" ]]; then
    cp -p "$DEPLOY_PATH/config.json" "$WEBUI_CONFIG_BACKUP"
    config_tmp="$(mktemp "$DEPLOY_PATH/.config.json.deploy.XXXXXX")"
    "$PYTHON_BIN" - "$DEPLOY_PATH/config.json" "$config_tmp" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    config = json.load(handle)
if not isinstance(config, dict):
    raise TypeError("config.json must contain a JSON object")

config.update(
    {
        "cpa_pool_cli_management_enabled": True,
        "cpa_pool_cli_management_url": "http://127.0.0.1:8317/v0/management",
        "cpa_pool_probe_proxy": "direct",
        "cpa_pool_scan_interval_sec": 86400,
        "cpa_pool_healthy_check_interval_sec": 86400,
        "cpa_pool_scheduler_tick_sec": 300,
        "cpa_pool_adaptive_batch_size": 200,
        "cpa_pool_refill_target_active": 2500,
        "cpa_pool_reserve_target_percent": 10,
        "cpa_pool_refill_max_inventory": 4000,
        "cpa_pool_refill_max_per_scan": 200,
        "cpa_pool_refill_controller_interval_sec": 30,
        "cpa_pool_refill_emergency_threshold_percent": 90,
        "cpa_pool_refill_daily_limit": 200,
        "cpa_pool_refill_low_water_rounds": 2,
        "cpa_pool_refill_min_baseline_percent": 100,
        "cpa_pool_refill_cooling_grace_sec": 86400,
    }
)
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
PY
    chmod --reference="$DEPLOY_PATH/config.json" "$config_tmp"
    mv -f "$config_tmp" "$DEPLOY_PATH/config.json"
    WEBUI_CONFIG_APPLIED=1
  fi

  install -m 755 "$CLIPROXY_BINARY" "$CLIPROXY_DEPLOY_PATH/.cli-proxy-api.${DEPLOY_SHA:0:12}.new"
  mv -f "$CLIPROXY_DEPLOY_PATH/.cli-proxy-api.${DEPLOY_SHA:0:12}.new" "$CLIPROXY_DEPLOY_PATH/cli-proxy-api"
  "${SYSTEMCTL[@]}" daemon-reload
  "${CLI_SYSTEMCTL[@]}" daemon-reload
  "${CLI_SYSTEMCTL[@]}" restart "$CLIPROXY_SERVICE"
  "${CLI_SYSTEMCTL[@]}" is-active --quiet "$CLIPROXY_SERVICE"

  management_ready=0
  for _ in $(seq 1 30); do
    if curl --noproxy '*' --fail --silent --show-error --max-time 5 \
      -H "Authorization: Bearer ${management_key}" \
      http://127.0.0.1:8317/v0/management/request-retry >/dev/null; then
      management_ready=1
      break
    fi
    sleep 1
  done
  [[ $management_ready -eq 1 ]] || { echo "ERROR: CLIProxyAPI management API did not become ready" >&2; exit 1; }

  management_put() {
    local endpoint="$1"
    local value="$2"
    curl --noproxy '*' --fail --silent --show-error --max-time 10 \
      -X PUT \
      -H "Authorization: Bearer ${management_key}" \
      -H 'Content-Type: application/json' \
      --data "{\"value\":${value}}" \
      "http://127.0.0.1:8317/v0/management/${endpoint}" >/dev/null
  }
  management_put request-retry 2
  management_put max-retry-credentials 6
  management_put max-retry-interval 30
  management_put save-cooldown-status true

  auth_snapshot="$(mktemp /tmp/cliproxy-auth-files.XXXXXX)"
  curl --noproxy '*' --fail --silent --show-error --max-time 30 \
    -H "Authorization: Bearer ${management_key}" \
    http://127.0.0.1:8317/v0/management/auth-files >"$auth_snapshot"
  xai_loaded="$("$PYTHON_BIN" - "$auth_snapshot" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
files = payload.get("files") if isinstance(payload, dict) else None
if not isinstance(files, list):
    raise TypeError("CLIProxyAPI auth-files response is missing the files list")

print(
    sum(
        1
        for item in files
        if isinstance(item, dict)
        and (
            str(item.get("provider", "")).lower() == "xai"
            or str(item.get("type", "")).lower() == "xai"
            or str(item.get("name", "")).lower().startswith("xai-")
        )
    )
)
PY
)"
  rm -f "$auth_snapshot"
  [[ "$xai_loaded" =~ ^[0-9]+$ && "$xai_loaded" -gt 0 ]] || { echo "ERROR: CLIProxyAPI loaded no xAI auth files" >&2; exit 1; }
  echo "CLIProxyAPI healthy: xai_loaded=${xai_loaded}"
fi

# 如果 8787 上挂着手工启动的旧 WebUI，单纯 restart systemd 可能健康检查命中旧进程。
# 部署前先清理 DEPLOY_HEALTH_URL 对应的本机监听端口，再交给 systemd 拉起当前 release。
if [[ "$DEPLOY_HEALTH_URL" =~ ^https?://(127\.0\.0\.1|localhost):([0-9]+)(/|$) ]]; then
  health_port="${BASH_REMATCH[2]}"
  if command -v fuser >/dev/null; then
    fuser -k "${health_port}/tcp" >/dev/null 2>&1 || true
  else
    while IFS= read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" >/dev/null 2>&1 || true
    done < <(ss -ltnp "sport = :${health_port}" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u)
  fi
  sleep 0.5
fi

"${SYSTEMCTL[@]}" restart "$DEPLOY_SERVICE"
"${SYSTEMCTL[@]}" is-active --quiet "$DEPLOY_SERVICE"

healthy=0
for _ in $(seq 1 30); do
  if curl --noproxy '*' --fail --silent --show-error --max-time 5 "$DEPLOY_HEALTH_URL" >/dev/null; then
    healthy=1
    break
  fi
  sleep 2
done
if [[ $healthy -ne 1 ]]; then
  "${SYSTEMCTL[@]}" --no-pager --full status "$DEPLOY_SERVICE" || true
  if [[ $EUID -eq 0 ]]; then
    journalctl -u "$DEPLOY_SERVICE" -n 80 --no-pager || true
  else
    sudo -n journalctl -u "$DEPLOY_SERVICE" -n 80 --no-pager || true
  fi
  false
fi

if [[ "$DEPLOY_CLIPROXY" == "1" ]]; then
  pool_linked=0
  pool_status="$(mktemp /tmp/cpa-pool-status.XXXXXX)"
  pool_status_url="${DEPLOY_HEALTH_URL%/healthz}/api/cpa/pool/status"
  for _ in $(seq 1 30); do
    if curl --noproxy '*' --fail --silent --show-error --max-time 10 \
      "$pool_status_url" >"$pool_status" \
      && "$PYTHON_BIN" - "$pool_status" <<'PY' >/dev/null; then
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
pool = payload.get("pool") if isinstance(payload, dict) else None
if not isinstance(pool, dict) or pool.get("runtime_connected") is not True:
    raise SystemExit(1)
try:
    loaded = int(pool.get("cli_loaded", 0))
except (TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if loaded > 0 else 1)
PY
      pool_linked=1
      break
    fi
    sleep 2
  done
  if [[ $pool_linked -ne 1 ]]; then
    "$PYTHON_BIN" - "$pool_status" runtime_connected cli_loaded runtime_error <<'PY' >&2 || true
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
pool = payload.get("pool") if isinstance(payload, dict) else {}
print(json.dumps({key: pool.get(key) for key in sys.argv[2:]}, ensure_ascii=False))
PY
    rm -f "$pool_status"
    echo "ERROR: WebUI did not connect to CLIProxyAPI management API" >&2
    false
  fi
  "$PYTHON_BIN" - "$pool_status" runtime_connected cli_loaded file_inventory <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
pool = payload.get("pool") if isinstance(payload, dict) else {}
print(json.dumps({key: pool.get(key) for key in sys.argv[2:]}, ensure_ascii=False))
PY
  rm -f "$pool_status"
fi

DEPLOY_APPLIED=0
CLIPROXY_APPLIED=0
WEBUI_CONFIG_APPLIED=0
echo "Deployment succeeded: ${DEPLOY_SHA}"
echo "Service healthy: ${DEPLOY_SERVICE} (${DEPLOY_HEALTH_URL})"

if (( DEPLOY_BACKUP_KEEP > 0 )); then
  for pattern in 'deploy-*.tar.gz' 'cliproxy-*' 'config-*.json'; do
    find "$DEPLOY_BACKUP_DIR" -maxdepth 1 -type f -name "$pattern" -printf '%T@ %p\n' \
      | sort -nr \
      | tail -n "+$((DEPLOY_BACKUP_KEEP + 1))" \
      | cut -d' ' -f2- \
      | while IFS= read -r old_backup; do
          [[ -n "$old_backup" ]] && rm -f -- "$old_backup"
        done
  done
fi
