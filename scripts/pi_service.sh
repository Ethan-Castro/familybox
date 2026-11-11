#!/usr/bin/env bash
# Run familybox as a systemd user service on the Pi, so the box's page starts on its own after power-on.
# No sudo. Touches only the familybox user units and ~/familybox-home. Never changes other services
# or the hostname. Run it from the checkout at ~/familybox:  bash scripts/pi_service.sh
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
