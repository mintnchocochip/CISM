# Serve Gemma 4 E4B for CISM via llama.cpp. See README "Hosting the model with llama.cpp".
#
# -ngl 99   every layer on the GPU
# -fa on    flash attention — this is what makes a 96k context fit in 6 GB
# --jinja   use the model's own chat template, so tool calls come out in the format it was trained on
param(
    [string]$Model = "D:\Models\gemma-4-E4B-it-Q4_K_M.gguf",
    [int]$Port     = 8189,
    [int]$Ctx      = 98304,
    [string]$Alias = "gemma-4-e4b-it",
    # 0.0.0.0 so WSL2 and Docker containers can reach it. On an untrusted network use 127.0.0.1.
    [string]$ListenHost = "0.0.0.0"
)

llama-server `
    --model $Model `
    --alias $Alias `
    --host $ListenHost --port $Port `
    --jinja -ngl 99 -fa on `
    -c $Ctx --temp 0.2
