#!/usr/bin/env bash
# Serve Gemma 4 E4B for CISM via llama.cpp. See README "Hosting the model with llama.cpp".
#
# -ngl 99   every layer on the GPU
# -fa on    flash attention — this is what makes a 96k context fit in 6 GB
# --jinja   use the model's own chat template, so tool calls come out in the format it was trained on
set -euo pipefail

MODEL="${CISM_MODEL_PATH:-$HOME/models/gemma-4-E4B-it-Q4_K_M.gguf}"
PORT="${CISM_LLM_PORT:-8189}"
CTX="${CISM_LLM_CTX:-98304}"
# 0.0.0.0 so WSL2 and Docker containers can reach it. On an untrusted network use 127.0.0.1.
LISTEN="${CISM_LLM_HOST:-0.0.0.0}"

exec llama-server \
    --model "$MODEL" \
    --alias gemma-4-e4b-it \
    --host "$LISTEN" --port "$PORT" \
    --jinja -ngl 99 -fa on \
    -c "$CTX" --temp 0.2
