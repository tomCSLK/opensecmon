#!/bin/sh
# Daily database backup: writes a consistent copy and keeps the newest $KEEP copies.
# The copy holds the *encrypted* secrets; the key file (/etc/opensecmon/secret.key) is NOT included and
# must be backed up separately. Installed to /usr/sbin/opensecmon-backup, run by opensecmon-backup.timer.
set -eu

OPENSECMON="${OPENSECMON_BIN:-/usr/bin/opensecmon}"
CONFIG="${OPENSECMON_CONFIG:-/etc/opensecmon/config.toml}"
DIR="${BACKUP_DIR:-/var/backups/opensecmon}"
KEEP="${KEEP:-14}"

mkdir -p "$DIR"
"$OPENSECMON" --config "$CONFIG" backup "$DIR/opensecmon-$(date +%Y%m%d-%H%M%S).db" >/dev/null

# Prune: the file names sort chronologically, so everything but the newest $KEEP goes.
count=0
for file in $(ls -1r "$DIR"/opensecmon-*.db 2>/dev/null); do
  count=$((count + 1))
  if [ "$count" -gt "$KEEP" ]; then
    rm -f -- "$file"
  fi
done
