# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""T6, T7, T8 are real attacks: a store built to catch them does, and a
store with no integrity does not."""

import pytest

from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter
from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS, CrossContextReplayAttack, MetadataTamperAttack,
    RollbackReplayAttack,
)

REPLAY_META = [CrossContextReplayAttack, RollbackReplayAttack,
               MetadataTamperAttack]


def test_eight_attacks_are_registered():
    names = [a().name for a in ALL_AT_REST_ATTACKS]
    assert len(names) == 8
    assert names[5:] == ["cross_replay", "rollback_replay", "metadata_tamper"]


@pytest.mark.parametrize("cls", REPLAY_META)
def test_reference_store_catches_them(cls):
    r = cls().run(ReferenceAtRestAdapter())
    assert r.detected, f"{cls().name}: reference store missed it ({r.detail})"
    assert r.status == "safe"


@pytest.mark.parametrize("cls", REPLAY_META)
def test_langgraph_sqlite_accepts_them(cls):
    r = cls().run(LangGraphSqliteAdapter())
    assert not r.detected, f"{cls().name}: expected a finding on LangGraph"
    assert r.status == "VULNERABLE"


def test_adapter_without_support_is_not_evaluable():
    class Bare(ReferenceAtRestAdapter):
        supports_replay = False
        supports_metadata = False
    ad = Bare()
    for cls in REPLAY_META:
        r = cls().run(ad)
        assert r.status == "n/a", f"{cls().name} should be n/a without support"
        assert r.error is not None
