#!/usr/bin/env bash

TASKS="chrome/93eabf48-6a27-4cb6-b963-7d5fe1e0d3a9,libreoffice_impress/455d3c66-7dc6-4537-a39a-36d3e9119df7,libreoffice_calc/7efeb4b1-3d19-4762-b163-63328d66303b,gimp/045bf3ff-9077-4b86-b483-a1040a949cff,libreoffice_writer/0810415c-bde4-4443-9047-d5f70165a697"

echo "=== TFORK pass (filecow_enabled=1) ==="
sudo sysctl -w vm.filecow_enabled=1
OS4AGENT_NO_CRUN_LOGS=1 sudo --preserve-env=PATH,OPENAI_API_KEY,OPENAI_API_BASE,JUDGE_API_KEY,JUDGE_API_BASE,OS4AGENT_NO_CRUN_LOGS \
  python3 bench.py \
    --workload osworld \
    --task-specs "$TASKS" \
    --modes TFORK \
    --n 4 \
    --depth 50 \
    --rounds 1 \
    --setup \
    --judge \
    --results-dir runs/osworld-sample50 \
    --llm-cache-name osworld-sample50 \
    -v

echo "=== CKPT pass (filecow_enabled=0) ==="
sudo sysctl -w vm.filecow_enabled=0
OS4AGENT_NO_CRUN_LOGS=1 sudo --preserve-env=PATH,OPENAI_API_KEY,OPENAI_API_BASE,JUDGE_API_KEY,JUDGE_API_BASE,OS4AGENT_NO_CRUN_LOGS \
  python3 bench.py \
    --workload osworld \
    --task-specs "$TASKS" \
    --modes CKPT \
    --n 4 \
    --depth 50 \
    --rounds 1 \
    --setup \
    --judge \
    --results-dir runs/osworld-sample50 \
    --llm-cache-name osworld-sample50 \
    -v
