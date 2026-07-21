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

DEPLOY_PATH="${DEPLOY_PATH%/}"
[[ "$DEPLOY_PATH" == /* && "$DEPLOY_PATH" != "/" ]] || { echo "ERROR: invalid DEPLOY_PATH" >&2; exit 1; }
[[ "$DEPLOY_BACKUP_DIR" == /* ]] || { echo "ERROR: DEPLOY_BACKUP_DIR must be absolute" >&2; exit 1; }
[[ "$DEPLOY_SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "ERROR: invalid DEPLOY_SERVICE" >&2; exit 1; }
[[ "$DEPLOY_BACKUP_KEEP" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid DEPLOY_BACKUP_KEEP" >&2; exit 1; }
[[ -f "$RELEASE_ARCHIVE" ]] || { echo "ERROR: release archive not found" >&2; exit 1; }

for command in curl flock rsync systemctl tar; do
  command -v "$command" >/dev/null || { echo "ERROR: required command not found: ${command}" >&2; exit 1; }
done

if [[ $EUID -eq 0 ]]; then
  SYSTEMCTL=(systemctl)
else
  command -v sudo >/dev/null || { echo "ERROR: sudo is required for non-root deployment" >&2; exit 1; }
  SYSTEMCTL=(sudo -n systemctl)
fi

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
DEPLOY_APPLIED=0

cleanup() {
  rm -rf -- "$STAGING_DIR"
  rm -f -- "$EXISTING_FILES" "$NEW_FILES" "$RELEASE_ARCHIVE"
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
  "${SYSTEMCTL[@]}" restart "$DEPLOY_SERVICE" || echo "WARNING: service restart after rollback failed" >&2
}

on_error() {
  local exit_code=$?
  local line=${1:-unknown}
  trap - ERR
  echo "ERROR: deployment command failed at line ${line} (exit ${exit_code})" >&2
  if [[ $DEPLOY_APPLIED -eq 1 ]]; then
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
    config.json|config.local.json|config.json.bak*|.env|accounts_*.txt|emails_used.txt|emails_error.txt|emails_error.txt.*|proxies.txt|*/proxies.txt|proxies_state.json|*/proxies_state.json|mail_credentials.txt|*/mail_credentials.txt|cpa_pool_state.json|*/cpa_pool_state.json|cpa_pool_scan.journal.jsonl|*/cpa_pool_scan.journal.jsonl|mail_tool_state.json|*/mail_tool_state.json|cpa_auths/*|*/cpa_auths/*|cpa_quarantine/*|*/cpa_quarantine/*|cookies/*|*/cookies/*|screenshots/*|*/screenshots/*|*.log|*.bak|*.pyc|*/__pycache__/*|.venv/*)
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

DEPLOY_APPLIED=0
echo "Deployment succeeded: ${DEPLOY_SHA}"
echo "Service healthy: ${DEPLOY_SERVICE} (${DEPLOY_HEALTH_URL})"

if (( DEPLOY_BACKUP_KEEP > 0 )); then
  find "$DEPLOY_BACKUP_DIR" -maxdepth 1 -type f -name 'deploy-*.tar.gz' -printf '%T@ %p\n' \
    | sort -nr \
    | tail -n "+$((DEPLOY_BACKUP_KEEP + 1))" \
    | cut -d' ' -f2- \
    | while IFS= read -r old_backup; do
        [[ -n "$old_backup" ]] && rm -f -- "$old_backup"
      done
fi
