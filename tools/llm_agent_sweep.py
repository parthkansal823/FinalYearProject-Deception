"""Bite rate as a function of agent capability.

One agentic result is not a finding. `tools/llm_agent_attacker.py` measured a bite
rate of 0.000 with a 1-billion-parameter model, and on its own that number is
unreadable: it could mean the probe is resistible, or simply that the model is too
weak to notice a planted hint. The two are distinguishable only by varying the
adversary's capability and watching what the bite rate does.

So this runs the same attacker over several local models and reports one row each.
It is the agentic counterpart of the `--curiosity` sweep: instead of asserting a
probability that an attacker follows a hint, it measures what a range of real
agents actually do. If the bite rate stays flat at zero as the models get stronger,
that is evidence about the probe. If it climbs, the earlier zero was about the model.

Each model runs against the SAME frozen detection model, on an isolated port and
data directory, so nothing here touches the canonical evaluation. Models that are
not pulled are skipped with a note rather than failing the sweep.

    docker start adf-ollama
    docker exec adf-ollama ollama pull qwen2.5:7b
    python -m tools.llm_agent_sweep --n 20 --models llama3.2:1b,llama3.2:3b,qwen2.5:7b

Writes one JSON per model plus a combined summary to data/eval/llm_sweep/.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from adf.decoy.llm_generator import OllamaClient

OUT = Path("data/eval/llm_sweep")


def main() -> None:
    ap = argparse.ArgumentParser(description="Agentic attacker bite rate vs model capability.")
    ap.add_argument("--models", default="llama3.2:1b,llama3.2:3b,qwen2.5:7b",
                    help="comma-separated local Ollama models, weakest first")
    ap.add_argument("--n", type=int, default=20, help="attacker sessions per model")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--num-thread", type=int, default=None,
                    help="cap Ollama CPU threads so a concurrent evaluation keeps its cores")
    ap.add_argument("--port-base", type=int, default=9800,
                    help="proxy port for the first model; each model gets the next triple")
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    OUT.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    for i, model in enumerate(models):
        if not OllamaClient(model=model).available():
            print(f"-- skipping {model}: not pulled "
                  f"(docker exec adf-ollama ollama pull {model})")
            continue

        port = args.port_base + i * 3
        run_dir = OUT / model.replace(":", "-").replace("/", "-")
        env_extra = {
            "ADF_NETWORK__PROXY_PORT": str(port),
            "ADF_NETWORK__TARGET_PORT": str(port + 1),
            "ADF_NETWORK__DECOY_PORT": str(port + 2),
            "ADF_LOGGING__LOG_DIR": f"{run_dir}/logs",
            "ADF_LOGGING__LABEL_DIR": f"{run_dir}/labels",
            "ADF_DATABASES__TARGET_DSN": f"sqlite:///{run_dir}/target.sqlite3",
            "ADF_DATABASES__FACT_NOTEBOOK_DSN": f"sqlite:///{run_dir}/notebook.sqlite3",
            "PYTHONUNBUFFERED": "1",
        }
        import os
        env = dict(os.environ, **env_extra)
        out_json = run_dir / "probe.json"
        # A crashed run leaves the PREVIOUS probe.json in place, and reading it
        # reports a result for a model that never ran -- the summary table happily
        # printed one. Clear it first so a missing file means exactly that.
        out_json.unlink(missing_ok=True)
        print(f"\n=== {model} (n={args.n}, ports {port}-{port+2}) ===")
        subprocess.run(
            [sys.executable, "-m", "tools.llm_agent_attacker",
             "--n", str(args.n), "--max-steps", str(args.max_steps),
             "--model", model,
             "--out", str(out_json),
             "--trajectory", str(run_dir / "traj.jsonl")]
            + (["--num-thread", str(args.num_thread)] if args.num_thread else []),
            env=env, check=False)

        if out_json.exists():
            rows.append(json.loads(out_json.read_text(encoding="utf-8")))
        else:
            print(f"  !! {model} produced no result (the run failed) -- see the "
                  f"traceback above; it is omitted rather than carried over.")

    if not rows:
        print("\nno model produced a result; nothing written")
        raise SystemExit(3)

    summary = OUT / "sweep.json"
    summary.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    print("\n" + "=" * 78)
    print(f"{'model':<16}{'n':>4}{'shown':>8}{'bit':>7}{'bite|shown':>12}"
          f"{'divert':>9}{'peak p':>9}")
    print("-" * 78)
    for r in rows:
        shown = r.get("baited_rate", 0.0)
        bgs = r.get("bite_rate_given_exposed")
        print(f"{r.get('model', '?'):<16}{r.get('n', 0):>4}{shown:>8.3f}"
              f"{r.get('bite_rate', 0.0):>7.3f}"
              f"{(f'{bgs:.3f}' if bgs is not None else '-'):>12}"
              f"{r.get('divert_rate', 0.0):>9.3f}{r.get('mean_peak_p', 0.0):>9.3f}")
    print("=" * 78)
    print(f"\nwritten -> {summary}")
    print("\nRead the trend, not any single row. A bite rate that stays at zero as the "
          "models strengthen says something about the probe; one that climbs says the "
          "weakest row was measuring the model.")


if __name__ == "__main__":
    main()
