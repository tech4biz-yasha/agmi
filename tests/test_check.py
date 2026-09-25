# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""agmi-check, the CI entry point: exit codes, verdict words, JSON shape."""

import json

import pytest

from agmi import check

OPENFANG = "agmi.adapters.openfang:OpenFangAdapter"


def test_openfang_model_accepts_truncation_and_fails_the_job(tmp_path):
    out = tmp_path / "r.json"
    code = check.main(["--adapter", OPENFANG, "--json", str(out)])
    assert code == 1
    data = json.loads(out.read_text())
    assert data["tool"] == "openfang"
    edits = {r["edit"][:2]: r["verdict"] for r in data["edits"]}
    assert list(edits) == ["T1", "T2", "T3", "T4", "T5"]
    assert edits["T2"] == "ACCEPTED"
    assert edits["T1"] == "REJECTED"


def test_fail_on_none_never_fails():
    assert check.main(["--adapter", OPENFANG, "--fail-on", "none"]) == 0


def test_bad_spec_is_a_usage_error():
    with pytest.raises(SystemExit):
        check.main(["--adapter", "no-colon-here"])


def test_front_door_adapter_is_refused():
    with pytest.raises(SystemExit):
        check.main(["--adapter", "agmi.adapters.naive_memory:NaiveMemoryAdapter"])
