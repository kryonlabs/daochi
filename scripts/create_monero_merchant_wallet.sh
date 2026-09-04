#!/usr/bin/env bash
set -euo pipefail

umask 077

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
backup_dir="${MONERO_BACKUP_DIR:-$repo_root/secrets/monero}"
network="${MONERO_NETWORK:-stagenet}"
restore_height="${MONERO_RESTORE_HEIGHT:-0}"
creation_date="$(date -u +%F)"

case "$network" in
  mainnet) network_flag=() ;;
  stagenet) network_flag=(--stagenet) ;;
  testnet) network_flag=(--testnet) ;;
  *) echo "MONERO_NETWORK must be mainnet, stagenet, or testnet" >&2; exit 1 ;;
esac
case "$restore_height" in
  ''|*[!0-9]*) echo "MONERO_RESTORE_HEIGHT must be a non-negative integer" >&2; exit 1 ;;
esac

for command_name in monero-wallet-cli openssl gpg tar sed; do
  command -v "$command_name" >/dev/null || {
    echo "missing required command: $command_name" >&2
    exit 1
  }
done

install -d -m 0700 "$backup_dir"
cold_backup="$backup_dir/waozi-monero-$network-recovery.gpg"
node_backup="$backup_dir/waozi-monero-$network-view-only.gpg"
if [ -e "$cold_backup" ] || [ -e "$node_backup" ]; then
  echo "refusing to overwrite an existing wallet backup in $backup_dir" >&2
  exit 1
fi

work_dir="$(mktemp -d /tmp/daochi-monero-wallet.XXXXXXXX)"
cleanup() {
  if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
    find "$work_dir" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT INT TERM HUP

encrypt_bundle() {
  local source_file="$1"
  local output_file="$2"
  local prompt_title="$3"
  local passphrase_file="$work_dir/gpg-passphrase"
  local confirmation_file="$work_dir/gpg-passphrase-confirmation"

  if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v zenity >/dev/null; then
    while true; do
      zenity --password --title="$prompt_title" > "$passphrase_file" || exit 1
      zenity --password --title="Confirm: $prompt_title" > "$confirmation_file" || exit 1
      if [ -s "$passphrase_file" ] && cmp -s "$passphrase_file" "$confirmation_file"; then
        break
      fi
      zenity --error --title="Passwords did not match" \
        --text="The passwords were empty or did not match. Please try again."
    done
    gpg --batch --yes --symmetric --cipher-algo AES256 \
      --pinentry-mode loopback --passphrase-file "$passphrase_file" \
      --output "$output_file" "$source_file"
    shred -u "$passphrase_file" "$confirmation_file" 2>/dev/null || true
  else
    gpg --symmetric --cipher-algo AES256 --output "$output_file" "$source_file"
  fi
}

cold_dir="$work_dir/cold"
node_dir="$work_dir/view-only"
install -d -m 0700 "$cold_dir" "$node_dir"
cold_wallet="$cold_dir/waozi-merchant"
view_wallet="$node_dir/waozi-merchant-view"

openssl rand -base64 48 > "$cold_dir/wallet-password"
openssl rand -base64 48 > "$node_dir/wallet-password"
openssl rand -base64 48 > "$node_dir/rpc-password"
printf '%s\n' 'daochi' > "$node_dir/rpc-user"

echo
echo "Creating the $network Waozi merchant spend wallet OFFLINE."
echo "The mnemonic will be captured only inside the encrypted recovery bundle."
echo
monero-wallet-cli \
  --offline \
  "${network_flag[@]}" \
  --generate-new-wallet "$cold_wallet" \
  --password-file "$cold_dir/wallet-password" \
  --mnemonic-language English \
  --restore-height "$restore_height" \
  --log-file "$work_dir/monero-wallet-cli.log" \
  --command version > "$cold_dir/wallet-creation-output.txt" 2>&1

monero-wallet-cli \
  --offline \
  "${network_flag[@]}" \
  --wallet-file "$cold_wallet" \
  --password-file "$cold_dir/wallet-password" \
  --log-file "$work_dir/monero-wallet-cli.log" \
  --command seed < "$cold_dir/wallet-password" \
  > "$cold_dir/MONERO-SEED-OUTPUT.txt" 2>&1

address="$(sed -n 's/^Generated new wallet: //p' "$cold_dir/wallet-creation-output.txt" | tail -n 1 | tr -d '\r')"
if [ "${#address}" -ne 95 ]; then
  echo "failed to read the primary wallet address" >&2
  exit 1
fi

seed="$(tr -d '\r' < "$cold_dir/MONERO-SEED-OUTPUT.txt" | awk '
  {
    valid = NF > 0
    for (i = 1; i <= NF; i++) {
      if ($i !~ /^[a-z]+$/) valid = 0
    }
    if (valid) {
      for (i = 1; i <= NF; i++) {
        words = words (words == "" ? "" : " ") $i
      }
    }
  }
  END { print words }
')"
if [ "$(printf '%s\n' "$seed" | awk '{ print NF }')" -ne 25 ]; then
  echo "failed to read the 25-word wallet seed" >&2
  exit 1
fi
printf '%s\n' "$seed" > "$cold_dir/monero-legacy-seed-25-words"
shred -u "$cold_dir/MONERO-SEED-OUTPUT.txt" "$cold_dir/wallet-creation-output.txt" 2>/dev/null || true

view_output="$(monero-wallet-cli \
  --offline \
  "${network_flag[@]}" \
  --wallet-file "$cold_wallet" \
  --password-file "$cold_dir/wallet-password" \
  --log-file "$work_dir/monero-wallet-cli.log" \
  --command viewkey < "$cold_dir/wallet-password" 2>&1)"
view_key="$(printf '%s\n' "$view_output" | sed -n 's/^secret: \([0-9a-f]\{64\}\)$/\1/p' | tail -n 1)"
if [ "${#view_key}" -ne 64 ]; then
  echo "failed to export the private view key" >&2
  exit 1
fi

printf '%s\n%s\n' "$address" "$view_key" > "$work_dir/view-wallet-input"
monero-wallet-cli \
  --offline \
  "${network_flag[@]}" \
  --generate-from-view-key "$view_wallet" \
  --password-file "$node_dir/wallet-password" \
  --restore-height "$restore_height" \
  --log-file "$work_dir/monero-wallet-cli.log" \
  --command version < "$work_dir/view-wallet-input" >/dev/null

printf '%s\n' "$address" > "$cold_dir/primary-address"
printf '%s\n' "$network" > "$cold_dir/network"
printf '%s\n' "$restore_height" > "$cold_dir/restore-height"
printf '%s\n' "$creation_date" > "$cold_dir/creation-date-utc"
{
  printf '%s\n\n' 'MONERO WALLET RECOVERY — KEEP SECRET'
  printf '%s\n' 'Anyone who obtains this file can spend every XMR in the wallet.'
  printf '%s\n\n' 'Never put this file on the Daōchi node or send it through chat/email.'
  printf '%s\n' 'Cake Wallet import:'
  printf '%s\n' '  Wallets → Restore Wallet → Restore from seed/keys → Monero → Next'
  printf '%s\n\n' '  Select Restore from seed and choose Legacy (25 words).'
  printf '%s\n%s\n\n' '25-word legacy seed:' "$seed"
  printf '%s\n%s\n\n' 'Restore height:' "$restore_height"
  printf '%s\n%s\n\n' 'Creation date (UTC; use this as the restore date if offered):' "$creation_date"
  printf '%s\n%s\n\n' 'Network:' "$network"
  printf '%s\n%s\n\n' 'Expected primary address after restore:' "$address"
  printf '%s\n' 'After restoring, leave Cake Wallet open until it is fully synchronized.'
  printf '%s\n' 'Importing these keys into Cake makes Cake a spending (hot) wallet.'
} > "$cold_dir/CAKE-WALLET-IMPORT.txt"
printf '%s\n' "$address" > "$node_dir/primary-address"
printf '%s\n' "$network" > "$node_dir/network"
printf '%s\n' "$restore_height" > "$node_dir/restore-height"
printf '%s\n' "$creation_date" > "$node_dir/creation-date-utc"

tar -C "$cold_dir" -czf "$work_dir/cold.tar.gz" .
tar -C "$node_dir" -czf "$work_dir/view-only.tar.gz" .

echo
echo "Encrypting the recovery backup. Enter a strong password in the visual prompt."
encrypt_bundle "$work_dir/cold.tar.gz" "$cold_backup" "Encrypt Monero recovery backup"
echo
echo "Encrypting the view-only node bundle. Use a different passphrase."
encrypt_bundle "$work_dir/view-only.tar.gz" "$node_backup" "Encrypt view-only node backup"
chmod 0600 "$cold_backup" "$node_backup"

echo
echo "Wallet ceremony complete."
echo "Encrypted recovery bundle: $cold_backup"
echo "View-only node bundle:    $node_backup"
echo "Primary address:          $address"
echo
echo "Before receiving mainnet funds:"
echo "  1. Verify the written mnemonic or CAKE-WALLET-IMPORT.txt restores the same address."
echo "  2. Copy the encrypted cold backup to a second offline physical location."
echo "  3. Deploy only the view-only bundle to the node."
echo "  4. Keep the two GPG passphrases outside this directory."
