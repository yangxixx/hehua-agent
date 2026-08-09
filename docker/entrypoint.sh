#!/bin/sh
# Hosted-mode entrypoint: validate env -> enable gateway -> run autonomously.
set -e

for v in BENCHMARK_TOKEN BENCHMARK_BASE_URL; do
    if [ -z "$(eval echo \$$v)" ]; then
        echo "[entrypoint] missing required env: $v" >&2
        exit 1
    fi
done

export MODEL_GATEWAY=1
export HEHUA_MODE=hosted
export HEHUA_THINKING=${HEHUA_THINKING:-auto}
export HEHUA_POOL=${HEHUA_POOL:-3}

echo "[entrypoint] starting hehua (hosted) at $(date)"
python -m hehua run --mode hosted || echo "[entrypoint] agent exited rc=$?"

echo "[entrypoint] done at $(date)"
