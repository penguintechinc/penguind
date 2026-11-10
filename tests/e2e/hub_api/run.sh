#!/usr/bin/env bash
# Hub API end-to-end (T6): builds pdcli + the agent driver, prepares a hash-pinned venv,
# then runs the pytest flow inside a private D-Bus session with an unlocked, throwaway
# gnome-keyring (pdcli stores its OIDC token in the OS keychain). Fails when zero checks
# ran, any check failed, or any hub telemetry count is zero. Prints the real counts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
HUB="$ROOT/services/hub-api"
VENV="${HUB_E2E_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/penguind-hub-e2e/venv}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hub-e2e-run.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

for tool in cargo uv dbus-run-session gnome-keyring-daemon; do
  command -v "$tool" >/dev/null || { echo "hub-e2e: required tool '$tool' not found" >&2; exit 1; }
done

cargo build --locked -p pdcli -p penguin-daemon --example hub_e2e_agent
TARGET="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')"
export HUB_E2E_PDCLI_BIN="$TARGET/debug/pdcli"
export HUB_E2E_AGENT_BIN="$TARGET/debug/examples/hub_e2e_agent"

[ -x "$VENV/bin/python" ] || uv venv -q -p 3.13 "$VENV"
VIRTUAL_ENV="$VENV" uv pip install -q --require-hashes -r "$HUB/requirements.txt"
VIRTUAL_ENV="$VENV" uv pip install -q --require-hashes -r "$HERE/requirements-test.txt"

export PYTHONPATH="$HUB"
export HUB_E2E_WORK="$WORK"
export HUB_E2E_SUMMARY="$WORK/summary.json"
export XDG_DATA_HOME="$WORK/xdg-data"
mkdir -p "$XDG_DATA_HOME"
set +e
dbus-run-session -- bash -c '
  set -euo pipefail
  eval "$(printf "e2e-keyring\n" | gnome-keyring-daemon --unlock --components=secrets)"
  cd "$0" && exec "$1/bin/python" -m pytest -p no:cacheprovider -v -s test_hub_e2e.py
' "$HERE" "$VENV"
rc=$?
set -e

[ -s "$HUB_E2E_SUMMARY" ] || { echo "hub-e2e: FAIL — no summary written (rc=$rc)" >&2; exit 1; }
python3 - "$HUB_E2E_SUMMARY" "$rc" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); rc = int(sys.argv[2]); o = s["otel"]
total = s["checks_passed"] + len(s["checks_failed"])
print(f"hub-e2e: checks {s['checks_passed']}/{total} passed; failed={s['checks_failed']}")
print(f"hub-e2e: otel logs={o['log_records']} metrics={o['metric_points']} "
      f"histograms={o['histogram_points']} spans={o['spans']} exports={o['export_requests']}")
bad = rc != 0 or total == 0 or s["checks_failed"] or min(
    o["log_records"], o["metric_points"], o["histogram_points"]) < 1
if bad:
    print("hub-e2e: FAIL", file=sys.stderr); sys.exit(1)
print("hub-e2e: PASS")
PY
