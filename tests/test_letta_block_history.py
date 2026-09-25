# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for real Letta's block checkpoint
history. Needs letta, asyncpg, psycopg2-binary, pgvector and either
LETTA_PG_URI or the pgserver package. Skips cleanly otherwise.
"""

import importlib.metadata as md

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("psycopg2")

from agmi.adapters.letta_block_history import (  # noqa: E402
    LettaBlockHistoryAdapter, _ensure_env,
)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS, TruncateAttack  # noqa: E402

# Order matters: importing letta binds its DB engine at import time, so the
# URI must be in the environment before letta is ever imported.
try:
    _ensure_env()
except NotImplementedError as exc:
    pytest.skip(str(exc), allow_module_level=True)
pytest.importorskip("letta")

MEASURED_ON = "letta 0.16.8"


def test_letta_block_history_accepts_every_at_rest_tamper():
    # T6/T7/T8 (cross-context replay, rollback, metadata) need adapter
    # hooks this store does not implement yet; they report n/a here and are
    # measured on the stores that have those surfaces. The rest must be
    # ACCEPTED, the finding this row records.
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(LettaBlockHistoryAdapter())
        if r.status == "n/a":
            continue
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert not r.detected, (
            f"{r.attack}: Letta now detects this. Re-measure and update the "
            f"scorecard (last measured on {MEASURED_ON}, now "
            f"letta {md.version('letta')})")


def test_truncate_silently_rewinds_core_memory():
    a = LettaBlockHistoryAdapter()
    a.setup()
    try:
        a.seed(5)
        TruncateAttack().tamper(a)
        from letta.services.block_manager import BlockManager
        import asyncio
        blk = asyncio.run(BlockManager().get_block_by_id_async(
            a._block_id, actor=a._actor))
        assert blk.value == "agmi-seed-2"
        assert a.verify() is True
    finally:
        a.teardown()
