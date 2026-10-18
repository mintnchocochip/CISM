#!/usr/bin/env bash
# Launches the CISM TUI against the live lab started by scripts/start_lab.sh.
# Target/scope default to the lab's dvwa + metasploitable2 containers (looked
# up live via docker inspect); override any of the env vars below to point at
# a different target or inference server.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

NETWORK_NAME="${CISM_LAB_NETWORK:-cism-lab}"
DVWA_NAME="${CISM_DVWA_NAME:-dvwa}"
METASPLOITABLE_NAME="${CISM_METASPLOITABLE_NAME:-metasploitable2}"

container_ip() {
    docker inspect "$1" --format \
        "{{(index .NetworkSettings.Networks \"${NETWORK_NAME}\").IPAddress}}" 2>/dev/null
}

DVWA_IP="$(container_ip "$DVWA_NAME" || true)"
METASPLOITABLE_IP="$(container_ip "$METASPLOITABLE_NAME" || true)"

if [ -z "$DVWA_IP" ]; then
    echo "Could not resolve $DVWA_NAME's IP on $NETWORK_NAME -- is the lab running? (scripts/start_lab.sh)" >&2
    exit 1
fi

TARGET="${CISM_TARGET:-$DVWA_IP}"
SCOPE="${CISM_SCOPE:-${DVWA_IP}/32${METASPLOITABLE_IP:+,${METASPLOITABLE_IP}/32}}"
BASE_URL="${CISM_BASE_URL:-http://127.0.0.1:8189/v1}"
MODEL="${CISM_MODEL:-Ornith-1.5-9B-MTP-IQ3_M}"
# Reasoning models spend tokens "thinking" before a tool call/answer lands
# (run_agent.py --help); leaving this unset means unbounded (n_predict: -1)
# -- confirmed live 2026-10-18 to run away to 11,000+ tokens on one turn.
MAX_TOKENS="${CISM_MAX_TOKENS:-4096}"
# Without this, context-window discovery probes Ollama's /api/show against
# our llama.cpp server, 404s, and silently falls back to a 32768 default --
# double the real n_ctx (16384) -- confirmed live 2026-10-18. Also picks the
# json_schema-constrained /completion DEPG extractor over function-calling.
BACKEND="${CISM_BACKEND:-llamacpp}"
export CISM_API_KEY="${CISM_API_KEY:-local}"

PYTHON_BIN="${CISM_PYTHON:-.venv/bin/python}"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python)"
fi

echo "Target:   $TARGET"
echo "Scope:    $SCOPE"
echo "Base URL: $BASE_URL"
echo "Model:    $MODEL"
echo "Max tok:  $MAX_TOKENS"
echo "Backend:  $BACKEND"
echo

exec "$PYTHON_BIN" run_agent.py --live-tools \
    --target "$TARGET" \
    --scope "$SCOPE" \
    --base-url "$BASE_URL" \
    --model "$MODEL" \
    --max-tokens "$MAX_TOKENS" \
    --backend "$BACKEND" \
    "$@"
