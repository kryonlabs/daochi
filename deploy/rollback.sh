#!/bin/sh
set -eu
STAMP=$(cat)
case "$STAMP" in *[!0-9TZ]*|'') exit 1 ;; esac
[ "${#STAMP}" -eq 16 ]
systemctl stop daochi.service
cp "/var/lib/daochi/backups/daochi.pre-upgrade.$STAMP" /opt/daochi/daochi
cp "/var/lib/daochi/backups/daochi.db.$STAMP" /var/lib/daochi/daochi.db
cp "/var/lib/daochi/backups/daochi.env.$STAMP" /etc/daochi/daochi.env
if [ -f "/var/lib/daochi/backups/daochi.manifest.$STAMP" ]; then
  cp "/var/lib/daochi/backups/daochi.manifest.$STAMP" /opt/daochi/daochi.manifest.json
else
  rm -f /opt/daochi/daochi.manifest.json
fi
if [ -f "/var/lib/daochi/backups/daochi.mesh.$STAMP" ]; then
  install -m 600 "/var/lib/daochi/backups/daochi.mesh.$STAMP" /etc/systemd/system/daochi.service.d/20-daochi-mesh.conf
elif [ -f "/var/lib/daochi/backups/daochi.mesh-absent.$STAMP" ]; then
  rm -f /etc/systemd/system/daochi.service.d/20-daochi-mesh.conf
fi
systemctl daemon-reload
systemctl start daochi.service
