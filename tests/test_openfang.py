# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Tests that pin the expected at-rest scorecard for OpenFang.

These lock in the core claim of the suite: a forward-only hash chain
(pre-fix OpenFang) catches modification but NOT tail-truncation, and the
tip-persistence fix closes exactly that one gap without weakening the rest.
"""

from agmi.adapters.openfang import OpenFangAdapter
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS,
    CrossContextReplayAttack,
    MetadataTamperAttack,
    RollbackReplayAttack,
)

# T6/T7/T8 are storage-level edits that need a second context or a
# metadata layer. OpenFang is a single-agent hash chain with neither, so
# those three report n/a on it. The OpenFang scorecard is the five basic
# at-rest edits; the replay/metadata edits are asserted against the stores
# that have those surfaces (see test_replay_metadata.py).
_STORAGE_ONLY = {CrossContextReplayAttack().name, RollbackReplayAttack().name,
                 MetadataTamperAttack().name}


def _run_all(adapter):
    return {cls().name: cls().run(adapter) for cls in ALL_AT_REST_ATTACKS}


def test_prefix_openfang_misses_only_truncation():
    results = _run_all(OpenFangAdapter(strict_tip=False))
    assert results["tamper"].detected
    assert results["delete_middle"].detected
    assert results["reorder"].detected
    assert results["forge"].detected
    # The one real gap: truncation slips past a forward-only walk.
    assert not results["truncate"].detected


def test_fixed_openfang_catches_every_applicable_attack():
    results = _run_all(OpenFangAdapter(strict_tip=True))
    for name, r in results.items():
        if name in _STORAGE_ONLY:
            assert r.status == "n/a", f"{name} should be n/a on OpenFang"
            continue
        assert r.detected, f"fixed OpenFang should detect {name}"


def test_no_applicable_attack_errors_on_openfang():
    for strict in (False, True):
        for name, r in _run_all(OpenFangAdapter(strict_tip=strict)).items():
            if name in _STORAGE_ONLY:
                assert r.status == "n/a", f"{name} should be n/a on OpenFang"
                continue
            assert r.error is None, f"{name} errored: {r.error}"


def test_clean_store_verifies_before_attack():
    a = OpenFangAdapter(strict_tip=True)
    a.setup()
    a.seed(5)
    assert a.verify() is True
    a.teardown()
