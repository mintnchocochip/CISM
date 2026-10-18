#!/usr/bin/env bash
# Hardened-container variant of run_tui.sh: runs the agent itself inside the
# non-root, capability-dropped, seccomp-restricted cism-runner container
# (docker/README.md) instead of on the bare host shell. Requires
# scripts/start_lab.sh to have been run first (needs cism-lab up).
#
# Network note (docker/README.md, "D4 -- network egress", left open
# deliberately, not a bug in this script): cism-lab is `internal:true`, so
# it cannot reach the host's inference server at all. The container is
# therefore also attached to cism-egress (full internet/host egress) --
# `host.docker.internal` only resolves to Docker Desktop's WSL2 host-access
# proxy on that non-internal network, not on cism-lab. ScopeGuardStage (not
# the network) is what keeps tool calls confined to --scope. If you've since
# locked down cism-egress with a DOCKER-USER iptables rule (D4's option 1),
# this script doesn't need to change -- it only names the network.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE_NAME="${CISM_RUNNER_IMAGE:-cism-runner}"
LAB_NETWORK="${CISM_LAB_NETWORK:-cism-lab}"
EGRESS_NETWORK="${CISM_EGRESS_NETWORK:-cism-egress}"
DVWA_NAME="${CISM_DVWA_NAME:-dvwa}"
METASPLOITABLE_NAME="${CISM_METASPLOITABLE_NAME:-metasploitable2}"

container_ip() {
    docker inspect "$1" --format \
        "{{(index .NetworkSettings.Networks \"${LAB_NETWORK}\").IPAddress}}" 2>/dev/null
}

if ! docker network inspect "$LAB_NETWORK" >/dev/null 2>&1; then
    echo "Network $LAB_NETWORK not found -- run scripts/start_lab.sh first." >&2
    exit 1
fi

if ! docker network inspect "$EGRESS_NETWORK" >/dev/null 2>&1; then
    echo "Creating docker network $EGRESS_NETWORK (host/internet egress for the container)..."
    docker network create "$EGRESS_NETWORK" >/dev/null
fi

DVWA_IP="$(container_ip "$DVWA_NAME" || true)"
METASPLOITABLE_IP="$(container_ip "$METASPLOITABLE_NAME" || true)"

if [ -z "$DVWA_IP" ]; then
    echo "Could not resolve $DVWA_NAME's IP on $LAB_NETWORK -- is the lab running? (scripts/start_lab.sh)" >&2
    exit 1
fi

TARGET="${CISM_TARGET:-$DVWA_IP}"
SCOPE="${CISM_SCOPE:-${DVWA_IP}/32${METASPLOITABLE_IP:+,${METASPLOITABLE_IP}/32}}"
BASE_URL="${CISM_BASE_URL:-http://host.docker.internal:8189/v1}"
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
API_KEY="${CISM_API_KEY:-local}"

if [ "${CISM_REBUILD:-}" = "1" ] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building $IMAGE_NAME..."
    docker build -t "$IMAGE_NAME" -f cism-runner.Dockerfile .
fi

# D6 (docker/README.md): the key goes in as a mounted file, never -e/--env-file --
# those land in `docker inspect`'s Config.Env in full; a mounted file only
# ever exposes its path there.
KEY_FILE="$(mktemp)"
trap 'rm -f "$KEY_FILE"' EXIT
printf '%s' "$API_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"

echo "Target:   $TARGET"
echo "Scope:    $SCOPE"
echo "Base URL: $BASE_URL"
echo "Model:    $MODEL"
echo "Max tok:  $MAX_TOKENS"
echo "Backend:  $BACKEND"
echo

exec docker run --rm -it \
    --cap-drop=ALL \
    --cap-add=SYS_ADMIN \
    --security-opt "seccomp=docker/seccomp-bwrap.json" \
    --security-opt no-new-privileges \
    --security-opt systempaths=unconfined \
    --memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 \
    --network "$LAB_NETWORK" \
    --network "$EGRESS_NETWORK" \
    -v "$KEY_FILE:/run/secrets/cism_api_key:ro" \
    "$IMAGE_NAME" --live-tools \
    --target "$TARGET" \
    --scope "$SCOPE" \
    --base-url "$BASE_URL" \
    --model "$MODEL" \
    --max-tokens "$MAX_TOKENS" \
    --backend "$BACKEND" \
    --key-file /run/secrets/cism_api_key \
    "$@"
