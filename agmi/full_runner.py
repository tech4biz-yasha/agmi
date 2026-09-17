# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Full scorecard across both attack families.

At-rest attacks (storage tampering) apply to any persisted store. Memory
attacks (injection, bleed, hijack, indirect injection) apply only to tools
that do user-scoped semantic retrieval. A tool that lacks one surface simply
scores n/a there, which is itself informative: an audit log cannot be
memory-injected; a bare vector store has no chain to truncate.
"""

from __future__ import annotations


def full_scorecard() -> str:
    from agmi.adapters.openfang import OpenFangAdapter
    from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter
    try:
        from agmi.adapters.mem0_at_rest import Mem0AtRestAdapter
        mem0_row = ("mem0-qdrant-local", Mem0AtRestAdapter(), None)
    except ImportError:
        mem0_row = None
    try:
        from agmi.adapters.letta_block_history import LettaBlockHistoryAdapter
        letta_row = ("letta-block-history", LettaBlockHistoryAdapter(), None)
    except ImportError:
        letta_row = None
    try:
        import inspeximus  # noqa: F401 - the adapter imports it lazily, so probe for it here
        from agmi.adapters.inspeximus_rows import (InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter,
                                                   InspeximusRowsSidecarHeadAdapter)
        inspeximus_rows = [("inspeximus-default", InspeximusDefaultAdapter(), None),
                           ("inspeximus-rcpt+dir", InspeximusRowsSidecarAdapter(), None),
                           ("inspeximus-rcpt+dir+home", InspeximusRowsSidecarHeadAdapter(), None)]
    except ImportError:
        inspeximus_rows = []
    from agmi.adapters.naive_memory import NaiveMemoryAdapter
    from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS
    from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS

    at_rest = [c() for c in ALL_AT_REST_ATTACKS]
    mem = [c() for c in ALL_MEMORY_ATTACKS]
    all_names = [a.name for a in at_rest] + [a.name for a in mem]

    # (label, at-rest adapter or None, semantic adapter or None)
    rows = [
        ("openfang(model,fixed)", OpenFangAdapter(strict_tip=True), None),
        ("langgraph-sqlite", LangGraphSqliteAdapter(), None),
        *([letta_row] if letta_row else []),
        *([mem0_row] if mem0_row else []),
        *inspeximus_rows,
        ("naive-mem(scoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=True)),
        ("naive-mem(unscoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=False)),
    ]

    cells: dict[tuple[str, str], str] = {}
    for label, ar_ad, sm_ad in rows:
        if ar_ad is not None:
            ar_ad.name = label
            for atk in at_rest:
                cells[(label, atk.name)] = atk.run(ar_ad).status
        else:
            for atk in at_rest:
                cells[(label, atk.name)] = "n/a"
        if sm_ad is not None:
            sm_ad.name = label
            for atk in mem:
                cells[(label, atk.name)] = atk.run(sm_ad).status
        else:
            for atk in mem:
                cells[(label, atk.name)] = "n/a"

    short = {
        "tamper": "tamp", "truncate": "trunc", "delete_middle": "delMid",
        "reorder": "reord", "forge": "forge", "memory_injection": "inject",
        "cross_session_bleed": "bleed", "retrieval_hijack": "hijack",
        "indirect_prompt_injection": "promptInj",
    }
    cols = [short[n] for n in all_names]
    label_w = max(len(r[0]) for r in rows) + 1
    col_w = max(max(len(c) for c in cols), 10)

    def c(t): return t.center(col_w)
    head = " " * label_w + "| " + " | ".join(c(x) for x in cols)
    lines = [head, "-" * len(head)]
    for label, _, _ in rows:
        line = [label.ljust(label_w) + "|"]
        line += [c(cells[(label, n)]) for n in all_names]
        lines.append(" ".join(line[:1]) + " " + " | ".join(line[1:]))
    return "\n".join(lines)


if __name__ == "__main__":
    print(full_scorecard())
