# Local LLM Shootout for CISM — Project Summary

Goal: Find the best small, locally-hosted LLM to serve as the agentic driver for CISM (an agentic pentest/VAPT tool), running on a resource-constrained laptop.

## Hardware constraints

GPU: NVIDIA RTX 3050 6 GB Laptop (6144 MiB VRAM total, ~5.1 GB free after Windows overhead)
RAM: 24 GB (Ryzen 5 7235HS, 4 cores / 8 threads)
Served via llama.cpp (llama-server --jinja) on native Windows, OpenAI-compatible API on http://127.0.0.1:8189/v1
Models stored on D:\Models (not WSL, which has a 14 GB cap)

## Evaluation method

Built a custom test harness (toolcheck2.py → toolcheck3.py) that hits the server's /v1/chat/completions endpoint with a fixed tool schema (run_shell, read_file, nmap_scan, http_request) and scores whether each model:

Calls the correct tool with correctly-typed arguments (including nested objects, integer arrays, enums)
Correctly declines to call a tool when none applies (math questions, jokes, no matching tool)
Handles multi-turn tool results, parallel tool calls, and missing-argument cases

Final stress test: 18 case types × 5 repeats = 90 calls per model, temperature 0.2. Also measured: llama-bench prompt/generation speed, VRAM usage via nvidia-smi, and VRAM scaling across context sizes.

## Models evaluated (in order)

### Round 1 — general-purpose small models

Model	Type	Tool test	Speed (tg)	Notes
LFM2.5-8B-A1B	Hybrid MoE, reasoning	81/90 (90.0%)	79 t/s	Fast, writes long reasoning chains
Ornith-1.5-9B (dense, Qwen3.5 hybrid)	Dense	85/90 (94.4%)	33 t/s	Needs partial CPU offload (-ngl 35)
Granite-4.0-H-Tiny	Hybrid MoE	8/10 (early test)	69 t/s	Not pursued further
Ornith-1.5-35B-A3B	Large MoE	4/4 (early test)	7-16 t/s	Too slow — needs ~20GB RAM, ruled out
gpt-oss-20B	Large MoE	4/4 (early test)	9 t/s	Too slow, ruled out

Also tested and rejected: thecodacus/llama.cpp performance fork (expert-cache, speculative decoding/MTP) — built from source, gave zero benefit on this 6GB card because too few experts fit in VRAM to cross the fork's own ~15% break-even point.

### Round 2 — cybersecurity-specialized fine-tunes

Tested whether a security-focused fine-tune would help over a general model.

Model	Base	Tool test	Verdict
CyberSecQwen-4B	Qwen3-4B-Instruct-2507	2-3/10	Broken tool calling
Cyber-Ornith-1.5-9B-OBLITERATED	Ornith-1.5-9B	62-63/90 (~69%)	Regressed vs. plain Ornith (94%)
Qwen3-4B-Cybersecurity-Heretic	Qwen3-4B (older gen)	25/90 (27.8%)	Broken tool calling
Llama-3.1-CyberAlpha8B	Llama-3.1-8B-Instruct	24/90 (26.7%)	Broken — serializes JSON args as Python-repr strings
DeepSeek-R1-Cybersecurity-8B	DeepSeek-R1-0528-Qwen3-8B	—	Failed — mostly empty generations, skipped after 3/5 reps
NVIDIA-Orchestrator-Cybersecurity-8B	Qwen3 8B (full merge, not LoRA)	82/90 (91.1%)	Only cyber fine-tune that held up — full merges preserve tool calling better than LoRA adapters

Key finding: every community cybersecurity fine-tune tested except the one full-merge model degraded tool-calling ability relative to its base model. These fine-tunes train on security Q&A/CTI text, not function-calling examples, so the skill erodes or breaks. Conclusion: cybersecurity domain knowledge is better supplied via CISM's own tools/retrieval than via a specialized model's weights.

### Round 3 — Gemma 4 (the winner)

Tried Google's Gemma 4 "elastic" model family as a fresh general-purpose candidate.

Model	VRAM	Tool test	Speed
gemma-4-E4B-it Q4_K_M (4.62 GiB)	3.90 GB @16k	90/90 (100%)	39.7 t/s
gemma-4-E4B-it Q5_K_M (5.09 GiB)	4.61 GB @32k	10/10 (quick test only)	36.5 t/s

Zero misses across all 18 test case types — including every case that tripped up every other model tested (line-count tool confusion, declining non-existent tools, shell pipelines, missing-argument handling). Also the lowest VRAM footprint of any candidate, which left room to push context size much further.

## Context size tuning (final model)

Measured VRAM scaling for gemma-4-E4B-it-Q4_K_M at full GPU offload:

Context	VRAM used
16,384	3.90 GB
32,768	4.14 GB
65,536	4.68 GB
98,304 (96k — chosen)	5.23 GB
114,688	5.51 GB
131,072 (128k)	5.79 GB (rejected — only ~350 MB headroom, too risky)

Settled on 96k context, leaving ~900 MB headroom on the 6 GB card.

## Final decision

Driver: gemma-4-E4B-it-Q4_K_M.gguf, served via llama-server --jinja -ngl 99 -fa on -c 98304 --temp 0.2 on port 8189.

Metric	Result
Tool-calling accuracy	100% (90/90 stress test)
Generation speed	~40 t/s
VRAM	5.23 GB / 6.14 GB (96k context)
GPU offload	Full (-ngl 99, no CPU-offload tuning needed)

Fallback servers kept on standby (all independently verified working):

serve_ornith.ps1 — Ornith-1.5-9B, 94.4% tool test, faster per-token speed if ever needed
serve_orchestrator.ps1 — NVIDIA-Orchestrator-Cybersecurity-8B, 91.1%, only viable cybersecurity-flavored option

CISM integration:

python run_agent.py --base-url http://127.0.0.1:8189/v1 --model gemma-4-e4b-it

## Inference optimizations

What the final setup actually uses (serve_gemma.ps1):

Optimization	Flag / mechanism	Effect
4-bit quantization	Model stored as Q4_K_M GGUF	Weights at ~4.5 bits/parameter instead of 16/32-bit — cuts VRAM and memory bandwidth ~4x
Full GPU offload	-ngl 99	Every layer runs on the GPU, nothing on CPU — avoids slow CPU↔GPU layer-splitting
Flash Attention	-fa on	Fused attention kernel — smaller KV cache footprint, faster attention compute; this is what made the 96k context window fit in 6 GB
Correct chat template	--jinja	Not a speed optimization — ensures tool-call formatting matches the model's training format (correctness, not speed)

Gemma-4-E4B is a dense model, so no MoE-specific tuning applies to the final pick at all.

What was tried and explicitly rejected (no benefit on this hardware):

Custom llama.cpp performance fork (thecodacus/llama.cpp, built from source with CUDA 12.9) — adds an MoE expert-cache and speculative decoding (MTP / DSpark draft models). Gave zero speedup on this 6 GB card: too few experts fit in VRAM to cross the fork's own ~15% break-even point for the cache, and speculative decoding's draft acceptance rate wasn't high enough to pay for itself. The final setup runs on this fork's binaries but uses none of its special features — it behaves as a plain llama.cpp build.

-ncmoe (MoE expert CPU-offload tuning) — mattered earlier for LFM2.5 (a Mixture-of-Experts model), where it was the single biggest speed lever (tuning the number of expert layers kept on CPU vs GPU). Irrelevant to the final pick since Gemma-4-E4B is dense, not MoE.

Speculative decoding (draft models) — tested on both LFM2.5 and a 35B MoE model, no measurable speedup on this GPU, abandoned.

One-line summary for slides: 4-bit quantization + full GPU offload + Flash Attention — standard, well-established llama.cpp optimizations. The more exotic techniques (expert caching, speculative decoding) were tested and deliberately not used, because they didn't help on this hardware.

## Secondary investigation: decision-layer models (Jev / Laya)

Also researched "System One" calibrated-decision models (commercial Jev, open-source Laya) as a potential add-on for CISM's small routing/judgment decisions (tool selection, scope-gating). Conclusion: not pursued — the potential error reduction was estimated at only a few percentage points (smaller than the gap between any two models tested), and better tool descriptions/prompting were judged a cheaper first fix for the recurring "wrong tool chosen" failure pattern.
