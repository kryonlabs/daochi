#!/bin/sh
# Install the verified build with data backups and restore on a failed migration.
set -eu
STAMP=${1:?backup timestamp required}
source_commit=${2:?source revision required}
expected_commit=${3:?native revision required}
case "$STAMP" in *[!0-9TZ]*|'') exit 1 ;; esac
[ "${#STAMP}" -eq 16 ]
for revision in "$source_commit" "$expected_commit"; do
  case "$revision" in *[!0-9a-f]*|'') exit 1 ;; esac
  [ "${#revision}" -eq 40 ]
done
mesh_token=$(cat)
rollback_ready=0
service_stopped=0
finish() {
  result=$?
  trap - 0
  if [ "$result" -ne 0 ] && [ "$rollback_ready" -eq 1 ]; then
    printf '%s' "$STAMP" | sh /opt/daochi-src/deploy/rollback.sh
  elif [ "$result" -ne 0 ] && [ "$service_stopped" -eq 1 ]; then
    systemctl start daochi.service
  fi
  exit "$result"
}
trap finish 0
python3 /opt/daochi-src/scripts/verify_deployment_inputs.py verify-artifact-manifest \
  --output /opt/daochi-src/daochi \
  --manifest /opt/daochi-src/build/daochi.manifest.json \
  --expected-source-commit "$source_commit" \
  --expected-liboqs-commit "$expected_commit"
mkdir -p /var/lib/daochi/backups
cp /opt/daochi/daochi "/var/lib/daochi/backups/daochi.pre-upgrade.$STAMP"
if [ -f /opt/daochi/daochi.manifest.json ]; then
  cp /opt/daochi/daochi.manifest.json "/var/lib/daochi/backups/daochi.manifest.$STAMP"
fi
systemctl stop daochi.service
service_stopped=1
sqlite3 /var/lib/daochi/daochi.db ".backup '/var/lib/daochi/backups/daochi.db.$STAMP'"
test -s "/var/lib/daochi/backups/daochi.db.$STAMP"
install -m 600 /etc/daochi/daochi.env "/var/lib/daochi/backups/daochi.env.$STAMP"
if [ -f /etc/systemd/system/daochi.service.d/20-daochi-mesh.conf ]; then
  cp /etc/systemd/system/daochi.service.d/20-daochi-mesh.conf "/var/lib/daochi/backups/daochi.mesh.$STAMP"
else
  touch "/var/lib/daochi/backups/daochi.mesh-absent.$STAMP"
fi
rollback_ready=1
# A daily timer deletes backups older than 28 days, also between deploys.
install -m 644 /opt/daochi-src/deploy/daochi-backup-prune.service /opt/daochi-src/deploy/daochi-backup-prune.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now daochi-backup-prune.timer
systemctl start daochi-backup-prune.service
cp /opt/daochi-src/daochi /opt/daochi/daochi.new
cp /opt/daochi-src/build/daochi.manifest.json /opt/daochi/daochi.manifest.new
mv /opt/daochi/daochi.new /opt/daochi/daochi
mv /opt/daochi/daochi.manifest.new /opt/daochi/daochi.manifest.json
if [ -n "$mesh_token" ]; then
  install -d -m 755 /etc/systemd/system/daochi.service.d
  printf '%s' "$mesh_token" | python3 -c '
import os, pathlib, sys
value = sys.stdin.read().strip()
if any(c in value for c in "\r\n\0"):
    sys.exit("invalid mesh credential line")
value = value.replace("\\", "\\\\").replace(chr(34), "\\" + chr(34)).replace("%", "%%")
path = pathlib.Path("/etc/systemd/system/daochi.service.d/20-daochi-mesh.conf")
temporary = path.with_suffix(".new")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as output:
    output.write("[Service]\nEnvironment=" + chr(34) + "DAOCHI_NODE_SYNC_TOKEN=" + value + chr(34) + "\n")
os.replace(temporary, path)
'
  systemctl daemon-reload
fi
python3 /opt/daochi-src/scripts/migrate-legacy-env.py /etc/daochi/daochi.env --apply --canonical-only
sh /opt/daochi-src/deploy/set-environment.sh /opt/daochi-src/deploy/node.env /etc/daochi/daochi.env
if [ -s /etc/daochi/google-play-service-account.json ]; then
  echo DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE=/etc/daochi/google-play-service-account.json |
    sh /opt/daochi-src/deploy/set-environment.sh - /etc/daochi/daochi.env
fi
# A raised Dew ratio or a new Dew product in deploy/dew-ratio.env
# rewrites the environment; if that fails, the previous node comes back.
sh /opt/daochi-src/deploy/apply-dew-ratio.sh /opt/daochi-src/deploy/dew-ratio.env /etc/daochi/daochi.env /opt/daochi/daochi /var/lib/daochi/daochi.db
systemctl start daochi.service
sleep 3
systemctl is-active --quiet daochi.service
rollback_ready=0
