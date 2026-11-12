#!/usr/bin/env bash
# Turn on Debian's automatic security updates on the Pi (the unattended-upgrades package).
# This one needs admin rights: run it once on the board, as a user who can sudo:  bash scripts/pi_os_updates.sh
# It installs one package and writes one file, /etc/apt/apt.conf.d/20auto-upgrades. Nothing else changes.
# The box's own code is updated separately, by familybox-update.timer (scripts/pi_service.sh).
set -euo pipefail
CONF=/etc/apt/apt.conf.d/20auto-upgrades

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This board has no apt-get (not Debian or Raspberry Pi OS). Nothing was changed."
  exit 1
fi

echo "== installing unattended-upgrades"
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades

echo "== turning on daily package lists and security updates ($CONF)"
printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' \
  | sudo tee "$CONF" >/dev/null
sudo chmod 644 "$CONF"
cat "$CONF"

echo "== check"
for t in apt-daily.timer apt-daily-upgrade.timer; do
  echo "$t: $(systemctl is-enabled "$t" 2>/dev/null || echo missing), $(systemctl is-active "$t" 2>/dev/null || true)"
done
echo "Which archives it installs from is set in /etc/apt/apt.conf.d/50unattended-upgrades (security only, by default)."
echo "Log: /var/log/unattended-upgrades/unattended-upgrades.log"
