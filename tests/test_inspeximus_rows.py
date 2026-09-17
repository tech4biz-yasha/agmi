# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for the real inspeximus store.

Three rows. Receipts off (the default) with the read path as verify(): every attack accepted.
Receipts on with the attacker holding the store's directory (the SQLite file and the receipts
sidecar): `verify_writes()` reports all five, the tail truncation because the store keeps the chain's
head outside its directory. Receipts on with the attacker also holding the config home where that head
lives: four reported, the tail truncation accepted. The version is recorded so a change in inspeximus
that opens or closes a cell shows up here.
"""

import json
import os

import pytest

pytest.importorskip("inspeximus")

import inspeximus  # noqa: E402

from agmi.adapters.inspeximus_rows import (  # noqa: E402
    InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter, InspeximusRowsSidecarHeadAdapter)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "inspeximus 2.38.0"
EXPECTED = {
    InspeximusDefaultAdapter: {"tamper": False, "truncate": False, "delete_middle": False,
                               "reorder": False, "forge": False},
    InspeximusRowsSidecarAdapter: {"tamper": True, "truncate": True, "delete_middle": True,
                                   "reorder": True, "forge": True},
    InspeximusRowsSidecarHeadAdapter: {"tamper": True, "truncate": False, "delete_middle": True,
                                       "reorder": True, "forge": True},
}


def _run_all(adapter_cls):
    return {cls().name: cls().run(adapter_cls()) for cls in ALL_AT_REST_ATTACKS}


@pytest.mark.parametrize("adapter_cls", list(EXPECTED))
def test_the_scorecard_row_is_as_measured(adapter_cls):
    expected = EXPECTED[adapter_cls]
    results = _run_all(adapter_cls)
    assert set(results) == set(expected)
    for name, r in results.items():
        assert r.error is None, f"{adapter_cls.name}/{name} errored: {r.error}"
        assert r.detected == expected[name], (
            f"{adapter_cls.name}/{name}: expected detected={expected[name]}, got {r.detected}; "
            f"re-measure and update the scorecard (last measured on {MEASURED_ON}, "
            f"now inspeximus {inspeximus.__version__})")


def test_a_clean_store_verifies_so_detection_is_not_a_fail_closed_verifier():
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        a.reload()
        assert a.verify() is True
    finally:
        a.teardown()


def test_a_tampered_row_is_named_by_verify_writes_and_still_served_by_recall():
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[2]))
        a.reload()
        ok, problems = a._store.verify_writes(expected_pubkey=a._pk)
        assert ok is False
        assert any(recs[2].fields["id"] in str(p) for p in problems), problems
        texts = [h.get("text", "") for h in a._store.recall("limit", k=10)]
        assert any("agmi-TAMP-" in t for t in texts), (
            "detection is the audit call; recall still serves the row")
    finally:
        a.teardown()


def test_the_sidecar_attacker_removes_exactly_one_receipt_per_deletion():
    """Control for the instrument: if the sidecar format changes, delete_raw raises instead of
    silently dropping nothing, which would flip the directory row for the wrong reason."""
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        before = json.loads(a.receipts_path().read_text(encoding="utf-8"))
        assert len(before) == 5
        victim = a.read_all_raw()[4].fields["id"]
        a.delete_raw(4)
        after = json.loads(a.receipts_path().read_text(encoding="utf-8"))
        assert len(after) == 4
        assert victim not in {r["memory_id"] for r in after}
    finally:
        a.teardown()


def test_the_head_outside_the_directory_is_what_reports_the_truncation():
    """Control: the directory row reports truncate because of the head, not for another reason. The
    head lives outside the store's directory, and removing it is the only difference between the
    two receipts rows."""
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        hp = a._store.head_path()
        assert hp and os.path.exists(hp)
        assert not os.path.abspath(hp).startswith(os.path.abspath(a._dir.name)), \
            "the head must live outside the attacked directory"
        a.delete_raw(4)
        a.delete_raw(3)
        a.reload()
        assert a.verify() is False, "with the head in place the shorter chain is reported"
        os.remove(hp)
        a.reload()
        assert a.verify() is True, "with the head gone the shorter chain is internally consistent"
    finally:
        a.teardown()


def test_an_anchor_off_the_machine_detects_the_truncation_the_head_row_accepts():
    a = InspeximusRowsSidecarHeadAdapter()
    a.setup()
    try:
        a.seed(5)
        anchor = a._store.anchor()          # what a witness would hold
        a.delete_raw(4)
        a.delete_raw(3)
        a.reload()
        assert a.verify() is True, "the accepted cell: a tail cut with its receipts and its head verifies"
        ok, problems = a._store.verify_consistency(anchor)
        assert ok is False
        assert any("shrank" in p for p in problems), problems
    finally:
        a.teardown()
