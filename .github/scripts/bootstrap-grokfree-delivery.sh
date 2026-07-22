#!/usr/bin/env bash
set -Eeuo pipefail

required=(DELIVERY_PUBLIC_KEY_FILE DELIVERY_CPA_ENV_FILE)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: missing environment variable ${name}" >&2
    exit 1
  fi
done

[[ -f "$DELIVERY_PUBLIC_KEY_FILE" ]] || {
  echo "ERROR: delivery public key file not found" >&2
  exit 1
}
[[ -f "$DELIVERY_CPA_ENV_FILE" ]] || {
  echo "ERROR: delivery CPA environment file not found" >&2
  exit 1
}

public_key="$(tr -d '\r\n' <"$DELIVERY_PUBLIC_KEY_FILE")"
if [[ ! "$public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+\ grokfree-delivery-github-actions$ ]]; then
  echo "ERROR: invalid GrokFree delivery public key" >&2
  exit 1
fi
if ! grep -Eq '^CPA_MANAGEMENT_KEY=[A-Za-z0-9._~-]{32,}$' "$DELIVERY_CPA_ENV_FILE"; then
  echo "ERROR: invalid CPA management environment file" >&2
  exit 1
fi
if [[ "$(wc -l <"$DELIVERY_CPA_ENV_FILE")" -ne 1 ]]; then
  echo "ERROR: CPA management environment file must contain exactly one line" >&2
  exit 1
fi

umask 077
install -d -m 700 "$HOME/.ssh"
authorized_keys="$HOME/.ssh/authorized_keys"
touch "$authorized_keys"
chmod 600 "$authorized_keys"

authorized_keys_new="$(mktemp "$HOME/.ssh/.authorized_keys.XXXXXX")"
cleanup() {
  rm -f -- "$authorized_keys_new" "$DELIVERY_PUBLIC_KEY_FILE" "$DELIVERY_CPA_ENV_FILE"
}
trap cleanup EXIT

grep -vE '[[:space:]]grokfree-delivery-github-actions$' "$authorized_keys" \
  >"$authorized_keys_new" || true
printf '%s\n' "$public_key" >>"$authorized_keys_new"
install -m 600 "$authorized_keys_new" "$authorized_keys"

install -d -m 700 /etc/grokfree-delivery
install -m 600 "$DELIVERY_CPA_ENV_FILE" /etc/grokfree-delivery/cpa.env

echo "GrokFree delivery deploy key installed"
echo "CPA environment prepared at /etc/grokfree-delivery/cpa.env"
