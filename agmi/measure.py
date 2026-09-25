# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Measure one target against the memory-specific attack family.

    python -m agmi.measure --target mem0 --embedder minilm
    python -m agmi.measure --target langgraph-store --embedder minilm
    python -m agmi.measure --target inspeximus
    python -m agmi.measure --target inspeximus-defended
    python -m agmi.measure --target inspeximus-defended-key

Prints the four cells for the target with the provenance line the adapter
reports (library version, embedder, which of the tool's optional ranking
signals were on, platform). That line is what goes next to the row in the
README, so a reader can reproduce the cell rather than take it on trust.

Targets that rank by an embedder are published only when measured with a
real sentence embedder (``--embedder minilm``); ``--embedder hash`` runs the
same code offline and is for exercising the adapter, not for publishing.
inspeximus ranks lexically at this store size and needs no embedder.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from agmi.adapters.semantic_base import SemanticMemoryAdapter
from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS, MemoryAttackResult


def run_memory_attacks(adapter: SemanticMemoryAdapter,
                       filler: int = 0,
                       mutate: bool = False) -> list[MemoryAttackResult]:
    """Run the four memory-specific attacks against one adapter, in
    catalogue order. Each attack resets the adapter itself. ``filler`` adds
    that many unrelated genuine memories before every fixture (the scale
    tier). ``mutate`` also runs each attacker write as its content-evasion
    mutations, so a defence is scored under evasion, not just on the base
    string."""
    return [cls(filler=filler, mutate=mutate) for cls in ALL_MEMORY_ATTACKS] \
        and [cls(filler=filler, mutate=mutate).run(adapter)
             for cls in ALL_MEMORY_ATTACKS]


def format_memory_row(label: str, results: list[MemoryAttackResult],
                      measured_on: str) -> str:
    lines = [f"target      {label}", f"measured on {measured_on}", ""]
    for r in results:
        lines.append(f"  {r.attack:26s}@v{r.version} {r.status:12s} {r.detail or r.error}")
    return "\n".join(lines)


def _mem0(embedder: str):
    from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
    from agmi.embedders import get_embedder
    return Mem0SemanticAdapter(get_embedder(embedder))


def _langgraph_store(embedder: str):
    from agmi.adapters.langgraph_store import LangGraphSqliteStoreAdapter
    from agmi.embedders import get_embedder
    return LangGraphSqliteStoreAdapter(get_embedder(embedder))


def _letta_archival(embedder: str):
    from agmi.adapters.letta_block_history import _ensure_env
    _ensure_env()  # before letta is imported anywhere
    from agmi.adapters.letta_archival import LettaArchivalAdapter
    from agmi.embedders import get_embedder
    return LettaArchivalAdapter(get_embedder(embedder))


def _inspeximus(embedder: str):
    from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
    return InspeximusRecallAdapter()


def _inspeximus_defended(embedder: str):
    """inspeximus with the tool's own provenance and a trust root keyed on
    the label: each memory's channel label is recorded as its ``source``,
    the first-party label is the trust root, and ``trusted_only`` serves
    only what is reachable from it. Whoever writes the label controls it,
    so this holds on the external channel only."""
    from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
    from inspeximus import Inspeximus
    return InspeximusRecallAdapter(
        provenance=True, trust_seeds={Inspeximus._canon_source("user")},
        recall_kwargs={"trusted_only": True}, label="inspeximus-defended")


def _inspeximus_defended_key(embedder: str):
    """The same filter keyed on the attested key instead of the label:
    signed writes are bound to a per-user Ed25519 key on the write, those
    keys are the trust root, and ``trusted_only`` serves only records they
    attested. A label is no longer enough; a valid signature still is."""
    from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
    return InspeximusRecallAdapter(
        provenance=True, attest=True, recall_kwargs={"trusted_only": True},
        label="inspeximus-defended-key")


def _mem0_live(embedder: str):
    """Mem0 with ``infer=True``: its default mode, where a hosted model
    extracts facts before storage. Needs a real OPENAI_API_KEY."""
    from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
    from agmi.embedders import get_embedder
    return Mem0SemanticAdapter(get_embedder(embedder), infer=True,
                               label="mem0-qdrant-local(infer=True)")


#: Target name -> factory taking the embedder name. Add a line here when a
#: new semantic adapter lands so it gets the same command as the others.
TARGETS: dict[str, Callable[[str], SemanticMemoryAdapter]] = {
    "mem0": _mem0,
    "mem0-live": _mem0_live,
    "langgraph-store": _langgraph_store,
    "letta-archival": _letta_archival,
    "inspeximus": _inspeximus,
    "inspeximus-defended": _inspeximus_defended,
    "inspeximus-defended-key": _inspeximus_defended_key,
}


def measure(target: str, embedder: str = "minilm", filler: int = 0,
            mutate: bool = False):
    """Build the adapter for ``target`` and run the family against it.
    Returns ``(results, measured_on)``. Adapters that hold resources are
    closed afterwards. ``filler`` seeds that many unrelated memories before
    every fixture (the scale tier)."""
    try:
        factory = TARGETS[target]
    except KeyError:
        raise ValueError(
            f"unknown target {target!r}; choose one of "
            f"{', '.join(sorted(TARGETS))}") from None
    adapter = factory(embedder)
    try:
        results = run_memory_attacks(adapter, filler=filler, mutate=mutate)
        measured_on = adapter.measured_on()
        if filler:
            measured_on += f", {filler} filler memories before every fixture"
        if mutate:
            measured_on += ", each attacker write also run as its content-evasion mutations"
        return results, measured_on
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()


def main(argv: list[str] | None = None) -> int:
    from agmi.embedders import EMBEDDERS

    parser = argparse.ArgumentParser(
        prog="python -m agmi.measure",
        description="Run the memory-specific attacks against one target "
                    "and print its row with provenance.")
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--embedder", choices=sorted(EMBEDDERS),
                        default="minilm",
                        help="ignored by targets that do not rank by an "
                             "embedder")
    parser.add_argument("--scale", type=int, default=0, metavar="N",
                        help="seed N unrelated memories before every "
                             "fixture (the scale tier); 0 is the default row")
    parser.add_argument("--mutate", action="store_true",
                        help="also run each attacker write as its "
                             "content-evasion mutations")
    args = parser.parse_args(argv)
    try:
        results, measured_on = measure(args.target, args.embedder, args.scale,
                                       args.mutate)
    except NotImplementedError as exc:
        print(f"cannot measure: {exc}", file=sys.stderr)
        return 2
    print(format_memory_row(args.target, results, measured_on))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
