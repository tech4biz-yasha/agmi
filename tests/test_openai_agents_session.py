# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for the OpenAI Agents SDK SQLiteSession.

These are measurements of the actual library, not a model of it. The version
is recorded so a future change in the SDK that adds integrity checking shows
up as a test failure here, which is the signal we want.
"""

import importlib.metadata as md
import json

import pytest

pytest.importorskip("agents")

from agmi.adapters.openai_agents_session import (  # noqa: E402
    OpenAIAgentsSessionAdapter, SESSION, OTHER_SESSION)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "openai-agents 0.20.0"


def test_openai_agents_session_accepts_every_at_rest_edit():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(OpenAIAgentsSessionAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert not r.detected, (
            f"{r.attack}: the SDK now detects this. Re-measure and update the "
            f"scorecard (last measured on {MEASURED_ON}, now "
            f"{md.version('openai-agents')})")


def test_control_clean_reload_verifies():
    a = OpenAIAgentsSessionAdapter()
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
        a = OpenAIAgentsSessionAdapter()
        a.setup()
        try:
            a.seed(5)
            if cls().name in ("cross_replay",):
                a.seed_other(5)
            before = [(r.fields["session_id"], r.fields["message_data"], r.fields["created_at"])
                      for r in a.read_all_raw()]
            cls().tamper(a)
            after = [(r.fields["session_id"], r.fields["message_data"], r.fields["created_at"])
                     for r in a.read_all_raw()]
            assert before != after, f"{cls().name} did not change the store"
        finally:
            a.teardown()


def test_cross_replay_serves_other_users_text_as_own():
    a = OpenAIAgentsSessionAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        donor = a.read_other_raw()[2]
        a.replay_onto(2, donor)
        from agents import SQLiteSession
        import asyncio
        s = SQLiteSession(SESSION, str(a._db))
        items = asyncio.run(s.get_items())
        s.close()
        assert items[2]["content"] == json.loads(donor.fields["message_data"])["content"]
        assert items[2]["content"].startswith("agmi-other-")
        assert a.verify() is True
        assert OTHER_SESSION != SESSION
    finally:
        a.teardown()


def test_t8_cell_rewrites_created_at_only():
    """The T8 cell on this store is a created_at rewrite, text untouched."""
    from agmi.attacks.at_rest import MetadataTamperAttack
    a = OpenAIAgentsSessionAdapter()
    a.setup()
    try:
        a.seed(5)
        before = [dict(r.fields) for r in a.read_all_raw()]
        MetadataTamperAttack().tamper(a)
        after = [dict(r.fields) for r in a.read_all_raw()]
        changed = {k for b, x in zip(before, after) for k in b if b[k] != x[k]}
        assert changed == {"created_at"}
    finally:
        a.teardown()


def test_rewritten_session_id_moves_item_to_other_user():
    import asyncio
    from agents import SQLiteSession
    a = OpenAIAgentsSessionAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        a.write_meta(2, {"session_id": OTHER_SESSION})
        s = SQLiteSession(OTHER_SESSION, str(a._db))
        items = asyncio.run(s.get_items())
        s.close()
        assert any(i["content"] == "agmi-seed-2" for i in items)
        assert a.verify() is True
    finally:
        a.teardown()
