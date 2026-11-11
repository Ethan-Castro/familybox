#!/bin/sh
# Publish familybox.local for this box's own address on the home network.
# Finds the address from the routing table only (no packets sent, no scanning).
set -eu
NAME=familybox.local

if ! command -v avahi-publish >/dev/null 2>&1; then
  echo "avahi-publish is not installed, so $NAME is not published. Use the board's own name instead."
  exit 0
fi

ip_addr=""
if command -v ip >/dev/null 2>&1; then
  # "ip route get" only asks the kernel which address it would use; nothing goes out.
  ip_addr=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
fi
if [ -z "$ip_addr" ] && command -v hostname >/dev/null 2>&1; then
  ip_addr=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1 || true)
fi
if [ -z "$ip_addr" ]; then
  echo "No home network address yet. Trying again soon."
  exit 1
fi

echo "Publishing $NAME at $ip_addr"
exec avahi-publish -a -R "$NAME" "$ip_addr"
