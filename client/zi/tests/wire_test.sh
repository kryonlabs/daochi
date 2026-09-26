#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
zi2c=${1:-"$root/../ziran/build/bin/zi2c"}
include=${2:-"$root/../ziran/include"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$zi2c" --no-main --root "$root/client/zi" -o "$work/generated" \
    "$root/client/zi/wire.zi"
"${CC:-cc}" -std=c11 -O0 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -I"$include" -I"$work/generated" \
    "$root/client/zi/tests/wire_test.c" \
    "$work/generated/wire.c" -o "$work/wire_test"
env -u DISPLAY -u WAYLAND_DISPLAY "$work/wire_test"
