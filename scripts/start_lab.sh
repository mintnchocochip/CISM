#!/usr/bin/env bash
# Stands up the live lab: the isolated cism-lab network, dvwa, and
# metasploitable2. Idempotent -- safe to re-run; only creates/starts what's
# missing or stopped. Run scripts/run_tui.sh separately to point the agent
# at this lab once it's up.
set -euo pipefail

NETWORK_NAME="${CISM_LAB_NETWORK:-cism-lab}"
NETWORK_SUBNET="${CISM_LAB_SUBNET:-172.28.0.0/24}"
DVWA_NAME="${CISM_DVWA_NAME:-dvwa}"
DVWA_IMAGE="${CISM_DVWA_IMAGE:-vulnerables/web-dvwa}"
METASPLOITABLE_NAME="${CISM_METASPLOITABLE_NAME:-metasploitable2}"
METASPLOITABLE_IMAGE="${CISM_METASPLOITABLE_IMAGE:-tleemcjr/metasploitable2:latest}"

container_ip() {
    docker inspect "$1" --format \
        "{{(index .NetworkSettings.Networks \"${NETWORK_NAME}\").IPAddress}}" 2>/dev/null
}

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "Creating docker network $NETWORK_NAME ($NETWORK_SUBNET)..."
    docker network create --subnet "$NETWORK_SUBNET" "$NETWORK_NAME"
else
    echo "Network $NETWORK_NAME already exists."
fi

if docker inspect "$DVWA_NAME" >/dev/null 2>&1; then
    if [ "$(docker inspect -f '{{.State.Running}}' "$DVWA_NAME")" != "true" ]; then
        echo "Starting existing container $DVWA_NAME..."
        docker start "$DVWA_NAME" >/dev/null
    else
        echo "Container $DVWA_NAME already running."
    fi
else
    echo "Creating container $DVWA_NAME from $DVWA_IMAGE..."
    docker run -d --name "$DVWA_NAME" --network "$NETWORK_NAME" "$DVWA_IMAGE" >/dev/null
    echo "First boot: visit http://$(container_ip "$DVWA_NAME")/setup.php once to initialize its database."
fi

if docker inspect "$METASPLOITABLE_NAME" >/dev/null 2>&1; then
    if [ "$(docker inspect -f '{{.State.Running}}' "$METASPLOITABLE_NAME")" != "true" ]; then
        echo "Starting existing container $METASPLOITABLE_NAME..."
        docker start "$METASPLOITABLE_NAME" >/dev/null
    else
        echo "Container $METASPLOITABLE_NAME already running."
    fi
else
    echo "Creating container $METASPLOITABLE_NAME from $METASPLOITABLE_IMAGE..."
    docker run -d --name "$METASPLOITABLE_NAME" --network "$NETWORK_NAME" \
        --restart unless-stopped "$METASPLOITABLE_IMAGE" >/dev/null
fi

echo
echo "Lab is up on $NETWORK_NAME:"
echo "  $DVWA_NAME            -> $(container_ip "$DVWA_NAME")"
echo "  $METASPLOITABLE_NAME  -> $(container_ip "$METASPLOITABLE_NAME")"
