#!/usr/bin/env bash
#
# validate-telemetry.sh — the Telemetry Validation blocking gate.
#
# Proves the OTLP emission added in #59 (crates/penguin-telemetry/src/otel.rs,
# wired into bins/penguind/src/logging.rs behind the `penguind.otel-telemetry`
# PostHog flag) actually reaches a collector over the wire — not just that
# `penguind` starts without crashing. Starting the daemon alone under-
# exercises the instrumentation, so this script also drives a real `pdcli`
# round trip (ListCommands -> ListModules -> GetStatus) over the daemon's
# real control socket before counting anything.
#
# Two modes, one harness:
#   --flag-on   seeds the license client's on-disk cache (the one legitimate
#               seam `LicenseChecker::feature_enabled` reads — never an env
#               var/CLI/config bypass, see critical-rules.md Feature Flags)
#               so `penguind.otel-telemetry` resolves true, then asserts
#               logs/metrics/histograms/spans ALL arrived at the sink.
#   --flag-off  runs the identical harness with the flag left at its
#               untouched default (no license key, no seeded cache) and
#               asserts the daemon still starts and serves requests
#               normally, but that ZERO telemetry arrived — proving the
#               flag genuinely gates emission, not just that the daemon
#               doesn't crash either way.
#
# The sink is a real otel/opentelemetry-collector-contrib container (digest-
# pinned, never `latest`) configured with the `file` exporter writing
# OTLP/JSON (one export request per line) for logs, metrics, and traces —
# deliberately not the `debug` exporter, whose prose output format is not a
# stable contract to assert against. Counts are read back with jq and
# printed BEFORE any assertion runs (critical-rules.md Verification
# Integrity: a count must be reported, "no errors" is not a pass). A sink
# that fails to start is a FAIL with its logs attached, never a silent skip.
#
# Env var escape hatches (production code is never touched by these):
#   VALIDATE_TELEMETRY_SINK_MODE=external
#       Skip starting/stopping a sink container; reuse one already running.
#       Requires VALIDATE_TELEMETRY_SINK_GRPC_ENDPOINT (e.g. "127.0.0.1:4317")
#       and VALIDATE_TELEMETRY_SINK_OUTPUT_DIR (the dir its file exporters
#       write logs.json/metrics.json/traces.json into) to already be set.
#   VALIDATE_TELEMETRY_OTLP_ENDPOINT_OVERRIDE
#       Overrides what this script tells penguind to export to, instead of
#       the real sink address. Exists solely so this gate's own "make it
#       fail on purpose" proof (see the task — a gate nobody has seen fail
#       is not trusted) can point the exporter at a dead endpoint without
#       editing this file. Never set by `make test-telemetry` or CI.
#
# Bash 3.2 compatible (no associative arrays, no `mapfile`).

set -euo pipefail

usage() {
    echo "usage: $0 --flag-on|--flag-off" >&2
    exit 1
}

MODE=""
case "${1:-}" in
    --flag-on) MODE="on" ;;
    --flag-off) MODE="off" ;;
    *) usage ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SINK_MODE="${VALIDATE_TELEMETRY_SINK_MODE:-managed}"
SINK_IMAGE="otel/opentelemetry-collector-contrib:0.144.0@sha256:213886eb6407af91b87fa47551c3632be1a6419ff3a5114ef1e6fc364628496f"
GRPC_PORT="${VALIDATE_TELEMETRY_GRPC_PORT:-14317}"
HTTP_PORT="${VALIDATE_TELEMETRY_HTTP_PORT:-14318}"
SINK_CONTAINER="penguind-telemetry-gate-$$"

# Short, top-level /tmp — NOT nested under a deep scratch path. The control
# socket this harness binds is a real AF_UNIX socket, capped at 103 bytes by
# penguin_ipc::listen_unix::MAX_UNIX_PATH; a long temp path makes `penguind`
# fail to bind with PathTooLong before the daemon is even up.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pdtg.XXXXXX")"
OUT_DIR="$WORK_DIR/otel-out"
STATE_DIR="$WORK_DIR/state"
SOCK="$WORK_DIR/penguind.sock"
LOG_FILE="$WORK_DIR/penguind.log"
mkdir -p "$OUT_DIR" "$STATE_DIR"
# The collector image runs as uid 10001, unrelated to whoever runs this
# script — its file exporters need write access to a directory they don't
# own.
chmod 777 "$OUT_DIR"

DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.5
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    fi
    if [ "$SINK_MODE" = "managed" ]; then
        docker rm -f "$SINK_CONTAINER" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
    echo "telemetry-gate: FAIL $1" >&2
    exit 1
}

# ── resolve the built binaries ──────────────────────────────────────────────

TARGET_DIR="$(cd "$REPO_ROOT" && cargo metadata --format-version 1 --no-deps | jq -r .target_directory)"
PENGUIND_BIN="$TARGET_DIR/debug/penguind"
PDCLI_BIN="$TARGET_DIR/debug/pdcli"
for bin in "$PENGUIND_BIN" "$PDCLI_BIN"; do
    [ -x "$bin" ] || fail "$bin not built — run \`make build\` first"
done

# ── stand up (or attach to) the OTLP sink ───────────────────────────────────

if [ "$SINK_MODE" = "managed" ]; then
    command -v docker >/dev/null 2>&1 || fail "docker is required to run the managed OTLP sink and is not available"

    cat > "$WORK_DIR/collector-config.yaml" <<'EOF'
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

exporters:
  file/logs:
    path: /output/logs.json
  file/metrics:
    path: /output/metrics.json
  file/traces:
    path: /output/traces.json

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [file/logs]
    metrics:
      receivers: [otlp]
      exporters: [file/metrics]
    traces:
      receivers: [otlp]
      exporters: [file/traces]
EOF

    docker rm -f "$SINK_CONTAINER" >/dev/null 2>&1 || true
    if ! docker run -d --name "$SINK_CONTAINER" \
        -p "${GRPC_PORT}:4317" -p "${HTTP_PORT}:4318" \
        -v "$WORK_DIR/collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro" \
        -v "$OUT_DIR:/output" \
        "$SINK_IMAGE" >/dev/null 2>"$WORK_DIR/sink-start.log"; then
        cat "$WORK_DIR/sink-start.log" >&2
        fail "could not start the OTLP sink container"
    fi

    ready=0
    for _ in $(seq 1 30); do
        if docker logs "$SINK_CONTAINER" 2>&1 | grep -q "Everything is ready"; then
            ready=1
            break
        fi
        if ! docker ps --filter "name=^${SINK_CONTAINER}\$" --filter status=running -q | grep -q .; then
            break
        fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
        echo "telemetry-gate: sink container logs follow" >&2
        docker logs "$SINK_CONTAINER" >&2 || true
        fail "OTLP sink never became ready"
    fi
    SINK_GRPC_ENDPOINT="http://127.0.0.1:${GRPC_PORT}"
else
    : "${VALIDATE_TELEMETRY_SINK_GRPC_ENDPOINT:?external sink mode requires VALIDATE_TELEMETRY_SINK_GRPC_ENDPOINT}"
    : "${VALIDATE_TELEMETRY_SINK_OUTPUT_DIR:?external sink mode requires VALIDATE_TELEMETRY_SINK_OUTPUT_DIR}"
    SINK_GRPC_ENDPOINT="http://${VALIDATE_TELEMETRY_SINK_GRPC_ENDPOINT}"
    OUT_DIR="$VALIDATE_TELEMETRY_SINK_OUTPUT_DIR"
fi

# ── seed the license cache (flag-on only) ───────────────────────────────────
#
# LicenseClient::feature_enabled (crates/penguin-licensing/src/client.rs)
# returns false unconditionally when license_key is empty, and otherwise
# reads straight from the in-memory state LicenseClient::new loads
# synchronously from <state_dir>/license/license-cache.json at construction
# — before any network refresh can race it. That on-disk cache is the one
# legitimate seam to turn the flag on for this gate (never an env var, CLI
# flag, or config override — see critical-rules.md Feature Flags & License
# Tiers).
LICENSE_KEY_VALUE=""
if [ "$MODE" = "on" ]; then
    LICENSE_KEY_VALUE="telemetry-gate-test-key"
    LICENSE_DIR="$STATE_DIR/license"
    mkdir -p "$LICENSE_DIR"
    cat > "$LICENSE_DIR/license-cache.json" <<EOF
{"tier":"enterprise","features":{"penguind.otel-telemetry":true},"fetched_at":$(date +%s)}
EOF
    chmod 600 "$LICENSE_DIR/license-cache.json"
fi

# ── start penguind ──────────────────────────────────────────────────────────

ENDPOINT="${VALIDATE_TELEMETRY_OTLP_ENDPOINT_OVERRIDE:-$SINK_GRPC_ENDPOINT}"

env \
    LICENSE_KEY="$LICENSE_KEY_VALUE" \
    OTEL_EXPORTER_OTLP_ENDPOINT="$ENDPOINT" \
    OTEL_EXPORTER_OTLP_PROTOCOL="grpc" \
    OTEL_SERVICE_NAME="penguind-telemetry-gate" \
    OTEL_RESOURCE_ATTRIBUTES="deployment.environment=telemetry-gate,service.namespace=penguind" \
    "$PENGUIND_BIN" \
    --config-dir "$WORK_DIR/config" \
    --state-dir "$STATE_DIR" \
    --socket "$SOCK" \
    >"$LOG_FILE" 2>&1 &
DAEMON_PID=$!

# ── wait for real readiness (a live client round trip, not a log grep) ─────

ready=0
for _ in $(seq 1 60); do
    if "$PDCLI_BIN" --socket "$SOCK" modules >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        cat "$LOG_FILE" >&2
        fail "penguind exited during startup"
    fi
    sleep 0.25
done
[ "$ready" -eq 1 ] || { cat "$LOG_FILE" >&2; fail "penguind never became ready on $SOCK"; }

# ── drive the real operation(s) the instrumentation is meant to cover ──────
# Startup alone under-exercises the daemon; this is the same
# ListCommands -> ListModules / GetStatus round trip an operator's `pdcli`
# invocation makes, now spanned (see crates/penguin-daemon/src/service.rs's
# `#[tracing::instrument]` additions).

"$PDCLI_BIN" --socket "$SOCK" modules >/dev/null
"$PDCLI_BIN" --socket "$SOCK" status >/dev/null

# ── stop the daemon — its shutdown path forces a bounded flush ─────────────
# OtelPipeline::shutdown_with_timeout (otel.rs) is called from the daemon's
# own shutdown sequence and synchronously drains all three providers'
# batched queues (bounded by OTEL_SHUTDOWN_BUDGET, 8s) before the process
# exits — far more deterministic than sleeping out the SDK's default
# periodic-export intervals.

kill -TERM "$DAEMON_PID"
waited=0
while kill -0 "$DAEMON_PID" 2>/dev/null; do
    sleep 0.5
    waited=$((waited + 1))
    if [ "$waited" -ge 40 ]; then
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
        cat "$LOG_FILE" >&2
        fail "penguind did not shut down within 20s of SIGTERM"
    fi
done
DAEMON_PID=""

# Give the collector a moment to finish writing what the shutdown flush just
# sent it over the wire.
sleep 2

# ── count what actually landed ──────────────────────────────────────────────

LOGS_FILE="$OUT_DIR/logs.json"
METRICS_FILE="$OUT_DIR/metrics.json"
TRACES_FILE="$OUT_DIR/traces.json"

# The `|| echo 0` here is safe per critical-rules.md Verification Integrity:
# it is followed by real, un-masked assertions on these exact counts below —
# never the only thing standing between a broken pipeline and a green exit.
count_signal() {
    file="$1"
    filter="$2"
    if [ ! -s "$file" ]; then
        echo 0
        return
    fi
    jq -s "$filter" "$file" 2>/dev/null || echo 0
}

LOG_COUNT="$(count_signal "$LOGS_FILE" '[.[] | .resourceLogs[]? | .scopeLogs[]? | .logRecords[]?] | length')"
METRIC_COUNT="$(count_signal "$METRICS_FILE" '[.[] | .resourceMetrics[]? | .scopeMetrics[]? | .metrics[]?] | length')"
HISTOGRAM_COUNT="$(count_signal "$METRICS_FILE" '[.[] | .resourceMetrics[]? | .scopeMetrics[]? | .metrics[]? | select(has("histogram") or has("exponentialHistogram"))] | length')"
SPAN_COUNT="$(count_signal "$TRACES_FILE" '[.[] | .resourceSpans[]? | .scopeSpans[]? | .spans[]?] | length')"

echo "OTel emission: logs=$LOG_COUNT metrics=$METRIC_COUNT histograms=$HISTOGRAM_COUNT spans=$SPAN_COUNT"

if [ "$MODE" = "on" ]; then
    bad=0
    [ -s "$LOGS_FILE" ] || { echo "telemetry-gate: FAIL sink wrote zero bytes for logs ($LOGS_FILE) — collector never received this signal" >&2; bad=1; }
    [ -s "$METRICS_FILE" ] || { echo "telemetry-gate: FAIL sink wrote zero bytes for metrics ($METRICS_FILE) — collector never received this signal" >&2; bad=1; }
    [ -s "$TRACES_FILE" ] || { echo "telemetry-gate: FAIL sink wrote zero bytes for traces ($TRACES_FILE) — collector never received this signal" >&2; bad=1; }
    [ "$LOG_COUNT" -gt 0 ] || { echo "telemetry-gate: FAIL zero log records received (logs=$LOG_COUNT)" >&2; bad=1; }
    [ "$METRIC_COUNT" -gt 0 ] || { echo "telemetry-gate: FAIL zero metric data points received (metrics=$METRIC_COUNT)" >&2; bad=1; }
    [ "$HISTOGRAM_COUNT" -gt 0 ] || { echo "telemetry-gate: FAIL zero histogram metrics received (histograms=$HISTOGRAM_COUNT) — load/latency histograms are the most-often-missing signal" >&2; bad=1; }
    [ "$SPAN_COUNT" -gt 0 ] || { echo "telemetry-gate: FAIL zero spans received (spans=$SPAN_COUNT)" >&2; bad=1; }
    [ "$bad" -eq 0 ] || exit 1
    echo "telemetry-gate: PASS (--flag-on) logs=$LOG_COUNT metrics=$METRIC_COUNT histograms=$HISTOGRAM_COUNT spans=$SPAN_COUNT"
else
    [ "$LOG_COUNT" -eq 0 ] || fail "expected zero log records with the flag OFF, got logs=$LOG_COUNT"
    [ "$METRIC_COUNT" -eq 0 ] || fail "expected zero metrics with the flag OFF, got metrics=$METRIC_COUNT"
    [ "$SPAN_COUNT" -eq 0 ] || fail "expected zero spans with the flag OFF, got spans=$SPAN_COUNT"
    echo "telemetry-gate: PASS (--flag-off) zero telemetry emitted while penguind started and served pdcli requests normally"
fi
