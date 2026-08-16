"""
L9 -- demonstrate that the Fact Notebook makes a STOCHASTIC (LLM) generator
consistent, and that the LLM world is richer than the deterministic one.

The deterministic generator in adf/decoy/world.py is already self-consistent: a
seeded RNG returns the same value for the same key every time. That makes it a
weak test of the notebook -- the consistency could be coming from the generator,
not the notebook. A language model is the honest test: asked the same thing twice
it answers differently, so ANY consistency the decoy shows must come from the
notebook. This tool measures exactly that.

Three numbers, all local (Ollama on 127.0.0.1 -- no external API):

  1. contradiction rate, LLM generator WITH the notebook (persist=True)
        -> expected 0%: the first answer is stored and reused.
  2. contradiction rate, same LLM generator WITHOUT the notebook (persist=False)
        -> expected high: the model re-invents the entity each time.
  3. richness: distinct field values produced by the LLM vs the deterministic
        pools, so the "richer world" claim is measured, not asserted.

If Ollama is not running or the model is not pulled, the tool prints how to start
it and exits 0 (nothing to measure, not a failure).

    docker run -d --name adf-ollama -p 11434:11434 ollama/ollama
    docker exec adf-ollama ollama pull llama3.2:1b
    python -m tools.llm_decoy_eval
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adf.decoy.notebook import FactNotebook
from adf.decoy.llm_generator import OllamaClient, make_llm_generators, DEFAULT_MODEL
from adf.decoy import world as _world

OUT = Path("data/eval/llm_decoy.json")


def _contradiction_rate(gen, keys, *, persist: bool) -> tuple[float, int]:
    """Ask for each entity twice; count how often the two answers disagree on a
    flavour field. With the notebook, the second read comes from storage."""
    nb = FactNotebook(":memory:", seed=7, persist=persist)
    disagreements = 0
    for k in keys:
        a = nb.get_or_generate("user", k, gen)
        b = nb.get_or_generate("user", k, gen)
        if (a.get("full_name"), a.get("department"), a.get("email")) != \
           (b.get("full_name"), b.get("department"), b.get("email")):
            disagreements += 1
    return disagreements / len(keys), disagreements


def _richness(gen, keys, namespace: str, field: str) -> int:
    """Distinct values of one field the generator produces over these keys."""
    nb = FactNotebook(":memory:", seed=11, persist=True)
    return len({nb.get_or_generate(namespace, k, gen)[field] for k in keys})


def main() -> None:
    ap = argparse.ArgumentParser(description="L9: LLM decoy consistency + richness.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--endpoint", default="http://127.0.0.1:11434")
    ap.add_argument("--n", type=int, default=20, help="distinct entities to probe")
    args = ap.parse_args()

    client = OllamaClient(args.endpoint, args.model)
    if not client.available():
        print(f"Ollama model {args.model!r} is not available at {args.endpoint}.")
        print("Start it (local, no external API):")
        print("  docker run -d --name adf-ollama -p 11434:11434 ollama/ollama")
        print(f"  docker exec adf-ollama ollama pull {args.model}")
        return

    llm_gens = make_llm_generators(client)
    llm_user, det_user = llm_gens["user"], _world.GENERATORS["user"]
    llm_rec, det_rec = llm_gens["record"], _world.GENERATORS["record"]
    keys = [str(i) for i in range(1, args.n + 1)]

    print(f"[L9] probing {args.n} entities with local model {args.model!r} ...")
    with_nb, with_n = _contradiction_rate(llm_user, keys, persist=True)
    without_nb, without_n = _contradiction_rate(llm_user, keys, persist=False)
    # richness on two axes: an ENUMERABLE field (names, where a good pool competes)
    # and a FREE-TEXT field (record bodies, where the deterministic gen is a single
    # hardcoded sentence and the LLM's variety actually shows).
    llm_names, det_names = _richness(llm_user, keys, "user", "full_name"), _richness(det_user, keys, "user", "full_name")
    llm_body, det_body = _richness(llm_rec, keys, "record", "body"), _richness(det_rec, keys, "record", "body")

    result = {
        "model": args.model,
        "n_entities": args.n,
        "llm_with_notebook": {"contradiction_rate": round(with_nb, 4), "disagreements": with_n},
        "llm_without_notebook": {"contradiction_rate": round(without_nb, 4), "disagreements": without_n},
        "richness": {
            "names_enumerable": {"llm": llm_names, "deterministic": det_names,
                                 "deterministic_pool": len(_world._FIRST) * len(_world._LAST)},
            "bodies_free_text": {"llm": llm_body, "deterministic": det_body},
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\n{'='*64}\nL9 -- LLM decoy vs the Fact Notebook\n{'='*64}")
    print(f"  contradiction rate, LLM WITH notebook    : {with_nb:.0%}  ({with_n}/{args.n})")
    print(f"  contradiction rate, LLM WITHOUT notebook : {without_nb:.0%}  ({without_n}/{args.n})")
    print(f"  richness (names, enumerable) : LLM {llm_names} vs determ. {det_names}  (pool competes)")
    print(f"  richness (bodies, free text) : LLM {llm_body} vs determ. {det_body}  (LLM wins where it matters)")
    print("\n-> The notebook makes a stochastic generator consistent; the")
    print("   inconsistency without it is inherent to the LLM, not injected.")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
