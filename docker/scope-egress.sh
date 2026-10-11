#!/usr/bin/env bash
# §3.1 (D4, AUDIT.md): scope cism-egress's outbound traffic to the
# cism-lab subnet + the LLM backend only, dropping everything else.
#
# NOT RUN by CISM itself — this needs real root on whatever host actually
# owns the Docker daemon's network namespace, which the agent/session
# that wrote this script does not have. On Docker Desktop (Mac/Windows),
# that is the Docker Desktop VM, NOT your WSL/host shell directly — a
# `sudo` prompt in WSL will not reach the DOCKER-USER chain Docker
# Desktop's daemon actually enforces. Run this via:
#   docker run --rm --privileged --net=host --pid=host -it \
#     justincormack/nsenter1 sh
#   (then paste the commands below, with real root in the daemon's netns)
# or wherever your Docker install's real root/iptables access lives.
#
# Usage: ./scope-egress.sh <llm-host-ip> <llm-port>
#   e.g. ./scope-egress.sh 172.17.0.1 11434     (Ollama on the Docker host)
#   e.g. ./scope-egress.sh 192.168.1.50 8189    (a LAN-hosted llama.cpp server)

set -euo pipefail

LLM_HOST="${1:?usage: scope-egress.sh <llm-host-ip> <llm-port>}"
LLM_PORT="${2:?usage: scope-egress.sh <llm-host-ip> <llm-port>}"

CISM_LAB_SUBNET="$(docker network inspect cism-lab --format '{{(index .IPAM.Config 0).Subnet}}')"
CISM_EGRESS_SUBNET="$(docker network inspect cism-egress --format '{{(index .IPAM.Config 0).Subnet}}')"

echo "cism-lab:    $CISM_LAB_SUBNET"
echo "cism-egress: $CISM_EGRESS_SUBNET"
echo "LLM backend: $LLM_HOST:$LLM_PORT"

# DOCKER-USER runs before Docker's own forwarding ACCEPT rules and
# survives `docker` daemon restarts unmolested (unlike the FORWARD chain
# itself, which Docker rewrites) — this is the standard supported hook
# for operator-added rules on a Docker host.
iptables -I DOCKER-USER -s "$CISM_EGRESS_SUBNET" -d "$CISM_LAB_SUBNET" -j ACCEPT
iptables -I DOCKER-USER -s "$CISM_EGRESS_SUBNET" -d "$LLM_HOST" -p tcp --dport "$LLM_PORT" -j ACCEPT
# Already-established return traffic for the two ACCEPTs above.
iptables -I DOCKER-USER -s "$CISM_EGRESS_SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT
# Everything else from cism-egress is dropped.
iptables -I DOCKER-USER -s "$CISM_EGRESS_SUBNET" -j DROP

echo
echo "Rules added. Verify from inside a cism-runner container on cism-egress:"
echo "  curl -m 5 https://1.1.1.1            # must fail/timeout"
echo "  curl -m 5 http://$LLM_HOST:$LLM_PORT/health   # must succeed (llama.cpp) or similar for your backend"
echo "  then run a full --live-tools engagement against the DVWA target and confirm it still completes."
echo
echo "These rules are NOT persistent across a daemon/host restart unless you"
echo "also add them to whatever this host uses for persistent iptables rules"
echo "(iptables-persistent, a systemd unit, Docker Desktop's own hook, etc.)"
echo "— that mechanism is host-specific and out of scope for this script."
