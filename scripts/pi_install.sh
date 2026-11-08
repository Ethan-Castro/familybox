#!/usr/bin/env bash
# Install and check familybox on a Raspberry Pi (or any aarch64/x86_64 Linux) as a normal user.
# No sudo, no system packages, no services: everything lives in ~/familybox and ~/.local.
# Prints a short report: Python, tests, a replay answer, timings and memory.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== host"
uname -m; (grep -m1 Model /proc/cpuinfo || true); free -m | sed -n 1,2p

if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  echo "== installing uv (to ~/.local/bin)"
  curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null
fi
export PATH="$HOME/.local/bin:$PATH"
uv --version

echo "== python + dependencies"
uv python install 3.12 >/dev/null
/usr/bin/time -v uv sync --python 3.12 -q 2> /tmp/fb_sync_time.txt || { cat /tmp/fb_sync_time.txt; exit 1; }
grep -E "Elapsed|Maximum resident" /tmp/fb_sync_time.txt || true

echo "== tests"
uv run pytest -q tests 2>&1 | tail -3

echo "== replay demo (no API key needed)"
export FAMILYBOX_HOME="$PWD/demo"
/usr/bin/time -v uv run familybox ask --mode replay --as maya "What medications am I on?" 2> /tmp/fb_ask_time.txt
grep -E "Elapsed|Maximum resident" /tmp/fb_ask_time.txt || true

if [ -n "${NEAR_AI_CLOUD_API_KEY:-}" ]; then
  echo "== live attestation check"
  uv run familybox verify
else
  echo "== live checks skipped (no NEAR_AI_CLOUD_API_KEY on this board)"
fi
echo "== done"
