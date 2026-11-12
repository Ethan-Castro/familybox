#!/usr/bin/env bash
# Run familybox as a systemd user service on the Pi, so the box's page starts on its own after power-on,
# and turn on the daily signed update of the box's code (familybox-update.timer).
# No sudo. Touches only the familybox user units and ~/familybox-home. Never changes other services
# or the hostname. Run it from the checkout at ~/familybox:  bash scripts/pi_service.sh
# FAMILYBOX_AUTO_UPDATE=off bash scripts/pi_service.sh  installs the update units but leaves the timer off.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
HOME_DIR="$HOME/familybox-home"
UNITS="$HOME/.config/systemd/user"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "This needs a Linux board with systemd. Nothing was changed."
  exit 1
fi
# Shells started without a login (for example over a remote runner) may not have this set.
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi

if [ "$REPO" != "$HOME/familybox" ]; then
  echo "warning: the service runs the code in $HOME/familybox, but this checkout is $REPO."
fi
if [ ! -x "$HOME/.local/bin/uv" ]; then
  echo "warning: $HOME/.local/bin/uv was not found. Run scripts/pi_install.sh first, which installs it."
fi

echo "== box home"
if [ -d "$HOME_DIR" ]; then
  echo "$HOME_DIR already exists, left as it is."
else
  mkdir -p "$HOME_DIR"
  chmod 700 "$HOME_DIR"
  echo "made $HOME_DIR (empty, so the box opens its setup page)."
fi

echo "== service"
mkdir -p "$UNITS"
install -m 644 "$REPO/deploy/familybox.service" "$UNITS/familybox.service"
units=(familybox.service)
if command -v avahi-publish >/dev/null 2>&1; then
  install -m 644 "$REPO/deploy/familybox-mdns.service" "$UNITS/familybox-mdns.service"
  units+=(familybox-mdns.service)
  friendly=yes
else
  friendly=no
fi
systemctl --user daemon-reload
systemctl --user enable --now "${units[@]}"
# A unit that was already running keeps the old files until it restarts.
systemctl --user restart "${units[@]}"
for u in "${units[@]}"; do
  echo "$u: $(systemctl --user is-active "$u" || true)"
done

echo "== daily signed updates"
install -m 644 "$REPO/deploy/familybox-update.service" "$UNITS/familybox-update.service"
install -m 644 "$REPO/deploy/familybox-update.timer" "$UNITS/familybox-update.timer"
systemctl --user daemon-reload
if [ "${FAMILYBOX_AUTO_UPDATE:-on}" = off ]; then
  systemctl --user disable --now familybox-update.timer >/dev/null 2>&1 || true
  echo "familybox-update.timer: off (FAMILYBOX_AUTO_UPDATE=off). Update by hand: familybox update apply"
else
  systemctl --user enable --now familybox-update.timer
  echo "familybox-update.timer: $(systemctl --user is-active familybox-update.timer || true)"
  next=$(systemctl --user show familybox-update.timer --property=NextElapseUSecRealtime --value 2>/dev/null || true)
  if [ -n "$next" ]; then
    echo "next check: $next (only releases signed by our key are installed; log in $HOME_DIR/runtime/updates.log)"
  fi
fi

echo "== address"
host=$(hostname -s 2>/dev/null || hostname)
if [ "$friendly" = yes ]; then
  echo "https://familybox.local:8443/  (or https://$host.local:8443/)"
else
  echo "https://$host.local:8443/  (avahi-publish is not installed, so familybox.local is not published)"
fi

echo "== starts after a reboot without anyone signed in?"
linger=$(loginctl show-user "$USER" --property=Linger --value 2>/dev/null || echo unknown)
if [ "$linger" = yes ]; then
  echo "yes (linger is on)"
else
  echo "no (linger is $linger). Someone with admin rights on this board must run this once:"
  echo "  sudo loginctl enable-linger $USER"
fi

echo "== automatic security updates for the board's own software?"
if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
  echo "yes (unattended-upgrades is on)"
else
  echo "no. Someone with admin rights on this board should run this once:"
  echo "  bash scripts/pi_os_updates.sh"
fi
