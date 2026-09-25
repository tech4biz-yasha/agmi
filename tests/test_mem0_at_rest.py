# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for real Mem0 on its local Qdrant
store. Needs mem0ai and qdrant-client; runs fully offline.
"""

import importlib.metadata as md

import pytest

pytest.importorskip("mem0")
pytest.importorskip("qdrant_client")

from agmi.adapters.mem0_at_rest import Mem0AtRestAdapter, USER  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS, TruncateAttack  # noqa: E402

MEASURED_ON = "mem0ai 2.0.20"


def test_mem0_accepts_every_at_rest_tamper():
    # All eight at-rest edits, including T6/T7/T8, are ACCEPTED here: this
    # store has no integrity check on its records. That is the finding the
    # row records.
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(Mem0AtRestAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert not r.detected, (
            f"{r.attack}: Mem0 now detects this. Re-measure and update the "
            f"scorecard (last measured on {MEASURED_ON}, now "
            f"mem0ai {md.version('mem0ai')})")


def test_truncate_leaves_history_and_store_disagreeing():
    """Mem0 keeps an ADD event per memory in its history table but never
    reconciles it with the vector store. After two memories are removed
    from the store, history still lists five and Mem0 reports nothing."""
    a = Mem0AtRestAdapter()
    a.setup()
    try:
        a.seed(5)
        TruncateAttack().tamper(a)
        a.reload()
        seen = a._mem.get_all(filters={"user_id": USER})["results"]
        assert len(seen) == 3
        assert len(a._order()) == 5
        assert a.verify() is True
    finally:
        a.teardown()
