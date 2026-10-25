#!/bin/sh
# Moves the node to the Dew per XMR ratio in RATIO_FILE. The deploy runs it as
# root with the service stopped. `daochi dew-ratio` runs with the service's
# user and environment: it rescales Dew once for a raised ratio and prints the
# node's new MONERO_RATE_* and DAOCHI_TOKEN_PRODUCTS lines, which replace the
# old ones in ENVIRONMENT_FILE. The node's current ratio changes nothing.
#
# Usage: apply-dew-ratio.sh RATIO_FILE ENVIRONMENT_FILE BINARY DATABASE
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: apply-dew-ratio.sh RATIO_FILE ENVIRONMENT_FILE BINARY DATABASE" >&2
    exit 2
fi
ratio_file=$1
environment_file=$2
binary=$3
database=$4

. "$ratio_file"

user=$(systemctl show daochi.service -p User --value)
set -- systemd-run --wait --pipe --collect --quiet \
    -p EnvironmentFile="$environment_file" \
    -p WorkingDirectory="$(dirname "$database")" \
    -p Environment=DAOCHI_DB="$database"
if [ -n "$user" ]; then
    set -- "$@" -p User="$user"
fi
output=$("$@" "$binary" dew-ratio "$DEW_RESCALE" "$MONERO_RATE_ATOMIC_AMOUNT" "$MONERO_RATE_TOKEN_UNITS")
printf '%s\n' "$output"

settings=$(printf '%s\n' "$output" | grep -E '^(MONERO_RATE_ATOMIC_AMOUNT|MONERO_RATE_TOKEN_UNITS|DAOCHI_TOKEN_PRODUCTS)=' || true)
if [ -z "$settings" ]; then
    exit 0
fi
keys=$(printf '%s\n' "$settings" | cut -d= -f1 | paste -sd '|' -)
updated=$(mktemp "$environment_file.XXXXXX")
{
    grep -Ev "^($keys)=" "$environment_file" || true
    printf '%s\n' "$settings"
} > "$updated"
chown --reference="$environment_file" "$updated"
chmod --reference="$environment_file" "$updated"
mv "$updated" "$environment_file"
echo "Node environment now has $(printf '%s\n' "$settings" | cut -d= -f1 | paste -sd ' ' -)"
