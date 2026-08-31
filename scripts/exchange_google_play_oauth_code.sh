#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
client_file="${KSYNC_GOOGLE_OAUTH_CLIENT_JSON_FILE:-$repo_root/secrets/google_play_oauth_client.json}"
code_file="${1:-/mnt/storage/Documents/google_oauth_code.txt}"
out_file="${KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN_FILE:-$repo_root/secrets/google_play_refresh_token.txt}"

if [ ! -f "$client_file" ]; then
  echo "missing OAuth client file: $client_file" >&2
  exit 1
fi
if [ ! -f "$code_file" ]; then
  echo "missing OAuth code file: $code_file" >&2
  exit 1
fi

raw_code="$(tr -d '\r\n' < "$code_file")"
code="$raw_code"
if [[ "$raw_code" == http*code=* ]]; then
  code="$(printf '%s' "$raw_code" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
fi
if [ -z "$code" ]; then
  echo "OAuth code file does not contain a code" >&2
  exit 1
fi

client_id="$(jq -r '.web.client_id // .installed.client_id' "$client_file")"
client_secret="$(jq -r '.web.client_secret // .installed.client_secret' "$client_file")"
redirect_uri="$(jq -r '(.web.redirect_uris // .installed.redirect_uris)[0]' "$client_file")"

response="$(curl -sS -X POST https://oauth2.googleapis.com/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "code=$code" \
  --data-urlencode "client_id=$client_id" \
  --data-urlencode "client_secret=$client_secret" \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'grant_type=authorization_code')"

refresh="$(printf '%s' "$response" | jq -r '.refresh_token // empty')"
if [ -z "$refresh" ]; then
  printf '%s\n' "$response" | jq '{error, error_description}' >&2
  exit 1
fi

install -d -m 0700 "$(dirname "$out_file")"
printf '%s\n' "$refresh" > "$out_file"
chmod 0600 "$out_file"
echo "refresh token saved to $out_file"
