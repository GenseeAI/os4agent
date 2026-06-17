# Agent-S × os4agent

Snapshot/clone perf comparison under a real Agent-S GUI workload. One
source container, N parallel branches, two ways to fan out:

| `ExpMode` | How it clones |
|---|---|
| `CKPT`      | N back-to-back CRIU `--copies=1` checkpoints. |
| `TFORK`     | one CRIU `--copies=N --persistent=async`. |

Cloning is the only mode-dependent phase; all branches then run
concurrently as the beam in beam-search.

## Setup

```bash
cd agents/agent-s
cp .env.example .env && $EDITOR .env       # at minimum, OPENAI_API_KEY
pip install openai
python3 scripts/fetch_tasks.py             # OSWorld fixtures → OSWORLD_ROOT
```

## Run it

```bash
# TFORK vs CKPT over a handful of OSWorld tasks
./run.sh
```

`--llm-cache-name <name>` makes LLM calls replayable. `--resume` skips
rounds with a `round-NN.done` marker.

## Env-var knobs (driver-side, ablation only)

| Var | Effect |
|---|---|
| `OS4AGENT_TFORK_PERSISTENT=sync\|async` | Override TFORK's `--persistent=` flag (default `async`; `sync` makes the on-disk dump complete before the clone returns). |
| `OS4AGENT_TFORK_FULL_MEMCOPY=1` | Pass `--tfork-full-memcopy` to crun → disable anon-private vma_cherrypick CoW; every anon page physically copied via `pread` on `/proc/<src>/mem`. Isolates the anon-CoW signal from a full-copy baseline. |
| `OS4AGENT_CKPT_PARALLEL=1` | In CKPT mode, fire all N `--copies=1` clones concurrently (via `subprocess.Popen`) instead of the default serial loop. |
| `OS4AGENT_NO_CRUN_LOGS=1` | Suppress crun-log scraping (quieter logs during sweeps). |

The env vars must be passed through `sudo --preserve-env=…` when running
under `sudo` (as `run.sh` does).

## What it records

`<results_dir>/timings.jsonl` — one JSON per phase, with structured
`round` / `mode` / `branch` / `step` fields. Labels: `src_launch`,
`clone_op`, `agent`, `step.<phase>`, `judge`, `llm_call`, `round`,
`cleanup`, `done`. `view.py` groups by them.

## Layout

```
run.sh              sample sweep (TFORK vs CKPT)
bench.py            RunExp + ExpMode + run_round/beam_search
drivers/            podman / kvm-migrate / kvm-virsh
workloads/          osworld (run_branch + judge)
scripts/            fetch_tasks.py (OSWorld fixtures fetcher)
monitor.py          live progress tail
view.py             static HTML report
tfork-clean.sh      orphan container / btrfs-subvol cleanup (CKPT/TFORK)
```
