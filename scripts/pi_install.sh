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

timed() {  # run a command, print its wall time and peak memory when /usr/bin/time exists
  if [ -x /usr/bin/time ]; then /usr/bin/time -f "  (%e s, peak %M KB)" "$@"; else
    local t=$SECONDS; "$@"; echo "  ($((SECONDS - t)) s)"; fi
}

echo "== python + dependencies"
PY=$(command -v python3.13 || command -v python3.12 || true)
if [ -z "$PY" ]; then uv python install 3.12 >/dev/null; PY=3.12; fi
timed uv sync --python "$PY" -q

echo "== tests"
uv run pytest -q tests 2>&1 | tail -3

echo "== replay demo (no API key needed)"
export FAMILYBOX_HOME="$PWD/demo"
timed uv run familybox ask --mode replay --as maya "What medications am I on?"

if [ -n "${NEAR_AI_CLOUD_API_KEY:-}" ]; then
  echo "== live attestation check"
  uv run familybox verify
else
  echo "== live checks skipped (no NEAR_AI_CLOUD_API_KEY on this board)"
fi
echo "== done"
