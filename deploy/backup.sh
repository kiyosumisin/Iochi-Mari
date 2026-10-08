#!/usr/bin/env bash
# Daily backup of Mari's data (cron, 03:15 UTC; see README "Backups & monitoring").
#  - encrypted (AES-256) with the passphrase in ~/.mari-backup-pass:
#    keep a copy of it somewhere else, or the backups cannot be restored
#  - kept 7 days in ~/backups
#  - if BACKUP_REPO is set in .env, the 7 files are force-pushed to that
#    private GitHub repo as a single commit, so it too holds only 7 days
#  - on success, pings BACKUP_HEALTHCHECK_URL from .env (if set)
# Restore: gpg --decrypt mari-YYYY-MM-DD.tar.gz.gpg | tar xzf -
set -euo pipefail
cd "$(dirname "$0")/.."

out=~/backups
mkdir -p "$out"
env_value() { sed -n "s/^$1=//p" .env | tr -d '"'"'"; }

paths=()
for p in data .env log/scam_catches.csv log/datamine_last_id.txt ai/feedback.csv; do
  [ -e "$p" ] && paths+=("$p")
done
tar czf - "${paths[@]}" \
  | gpg --batch --yes --symmetric --cipher-algo AES256 \
        --passphrase-file ~/.mari-backup-pass -o "$out/mari-$(date -u +%F).tar.gz.gpg"
find "$out" -name 'mari-*' -mtime +6 -delete

repo=$(env_value BACKUP_REPO)
if [ -n "$repo" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  cp "$out"/mari-*.gpg "$tmp"/
  git -C "$tmp" init -q -b main
  git -C "$tmp" add -A
  git -C "$tmp" -c user.name=Mari -c user.email=mari@localhost commit -qm "Backup $(date -u +%F)"
  GIT_SSH_COMMAND="ssh -i $HOME/.ssh/mari_backup -o IdentitiesOnly=yes" \
    git -C "$tmp" push -qf "$repo" main
fi

hc=$(env_value BACKUP_HEALTHCHECK_URL)
if [ -n "$hc" ]; then
  curl -fsS -m 10 --retry 3 "$hc" >/dev/null || echo "backup ping failed"
fi
echo "$(date -u +%FT%TZ) backup ok"
