# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for the LlamaIndex Memory (SQLAlchemy chat store).

These are measurements of the actual library, not a model of it. The version
is recorded so a future change in the SDK that adds integrity checking shows
up as a test failure here, which is the signal we want.
"""

import importlib.metadata as md
import json

import pytest

pytest.importorskip("llama_index.core.memory")

from agmi.adapters.llamaindex_memory import (  # noqa: E402
    LlamaIndexMemoryAdapter, SESSION, OTHER_SESSION)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "llama-index-core 0.14.24"


def test_llamaindex_memory_accepts_every_at_rest_edit():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(LlamaIndexMemoryAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert not r.detected, (
            f"{r.attack}: LlamaIndex now detects this. Re-measure and update the "
            f"scorecard (last measured on {MEASURED_ON}, now "
            f"{md.version('llama-index-core')})")


def test_control_clean_reload_verifies():
    a = LlamaIndexMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        a.reload()
        assert a.verify() is True
    finally:
        a.teardown()


def test_every_edit_really_changes_the_store():
    """Each edit must leave a different raw store behind; a no-op edit would
    make an ACCEPTED cell meaningless."""
    for cls in ALL_AT_REST_ATTACKS:
        a = LlamaIndexMemoryAdapter()
        a.setup()
        try:
            a.seed(5)
            if cls().name in ("cross_replay",):
                a.seed_other(5)
            before = [tuple(r.fields[c] for c in ("key", "timestamp", "role", "status", "data"))
                      for r in a.read_all_raw()]
            cls().tamper(a)
            after = [tuple(r.fields[c] for c in ("key", "timestamp", "role", "status", "data"))
                     for r in a.read_all_raw()]
            assert before != after, f"{cls().name} did not change the store"
        finally:
            a.teardown()


def test_cross_replay_serves_other_users_text_as_own():
    a = LlamaIndexMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        donor = a.read_other_raw()[2]
        a.replay_onto(2, donor)
        import asyncio
        msgs = asyncio.run(a._memory(SESSION).aget())
        assert msgs[2].content == json.loads(donor.fields["data"])["blocks"][0]["text"]
        assert msgs[2].content.startswith("agmi-other-")
        assert a.verify() is True
        assert OTHER_SESSION != SESSION
    finally:
        a.teardown()
