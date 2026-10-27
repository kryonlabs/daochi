#!/bin/sh
# Writes the NAME=VALUE lines of SETTINGS (a file, or - for standard input) into
# ENVIRONMENT_FILE in place of the lines that set the same names, keeping the
# file's owner and mode. Comments and blank lines in SETTINGS are skipped.
#
# Usage: set-environment.sh SETTINGS ENVIRONMENT_FILE
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: set-environment.sh SETTINGS ENVIRONMENT_FILE" >&2
    exit 2
fi
environment_file=$2

settings=$(grep -E '^[A-Z][A-Z0-9_]*=' "$1" || true)
if [ -z "$settings" ]; then
    exit 0
fi
names=$(printf '%s\n' "$settings" | cut -d= -f1 | paste -sd '|' -)
updated=$(mktemp "$environment_file.XXXXXX")
{
    grep -Ev "^($names)=" "$environment_file" || true
    printf '%s\n' "$settings"
} > "$updated"
chown --reference="$environment_file" "$updated"
chmod --reference="$environment_file" "$updated"
mv "$updated" "$environment_file"
echo "Node environment now has $(printf '%s\n' "$settings" | cut -d= -f1 | paste -sd ' ' -)"
