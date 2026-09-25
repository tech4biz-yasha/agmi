# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""`agmi-check`: run the at-rest edits against one adapter and exit non-zero
if any edit is accepted silently.

This is the entry point a vendor puts in CI. It takes the adapter as a
dotted path (module:Class), runs every at-rest edit with its built-in
control cases, prints one row, and fails the job on any ACCEPTED cell.
Under GitHub Actions it also writes the row to the step summary and emits
an annotation per finding, so the result is visible without opening logs.

Verdict words follow the method proposed for draft-han-bmwg 5.4.7:
REJECTED, REPORTED (audit-time detection) and ACCEPTED. An edit that could
not be run is NOT EVALUABLE and never counts as a pass.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

from agmi.adapters.base import MemoryAdapter
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS
from agmi.attacks.base import AttackResult

# Column labels from the proposed Section 6.6 test method.
LABELS = {
    "tamper": "T1 content tamper",
    "truncate": "T2 tail truncation",
    "delete_middle": "T3 middle deletion",
    "reorder": "T4 reordering",
    "forge": "T5 forged insertion",
    "cross_replay": "T6 cross-context replay",
    "rollback_replay": "T7 rollback replay",
    "metadata_tamper": "T8 metadata tamper",
}


def load_adapter(spec: str) -> MemoryAdapter:
    """Instantiate an adapter from 'package.module:ClassName'."""
    if ":" not in spec:
        raise SystemExit(f"adapter must be module:Class, got {spec!r}")
    mod_name, cls_name = spec.split(":", 1)
    module = importlib.import_module(mod_name)
    cls = getattr(module, cls_name)
    if not (isinstance(cls, type) and issubclass(cls, MemoryAdapter)):
        raise SystemExit(f"{spec} is not an at-rest MemoryAdapter; "
                         "agmi-check runs the storage-level edits only")
    return cls()


def verdict(result: AttackResult, adapter: MemoryAdapter) -> str:
    if result.error is not None:
        return "NOT EVALUABLE"
    if not result.detected:
        return "ACCEPTED"
    if getattr(adapter, "detection_point", "read") == "audit":
        return "REPORTED"
    return "REJECTED"


def run(adapter: MemoryAdapter) -> list[dict]:
    rows = []
    for cls in ALL_AT_REST_ATTACKS:
        attack = cls()
        result = attack.run(adapter)
        rows.append({
            "edit": LABELS.get(attack.name, attack.name),
            "attack": attack.name,
            "attack_version": attack.version,
            "verdict": verdict(result, adapter),
            "detail": result.error or result.detail or "",
        })
    return rows


def render(tool: str, rows: list[dict]) -> str:
    w = max(len(r["edit"]) for r in rows)
    out = [f"agmi-check: {tool}", "-" * (w + 20)]
    for r in rows:
        out.append(f"{r['edit'].ljust(w)}  {r['verdict']}")
    return "\n".join(out)


def gha_report(tool: str, rows: list[dict]) -> None:
    """Step summary and annotations, only when running under GitHub Actions."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"### agmi-check: {tool}\n\n| Edit | Verdict |\n|---|---|\n")
            for r in rows:
                fh.write(f"| {r['edit']} | {r['verdict']} |\n")
            fh.write("\nVerdicts follow the method proposed for IETF "
                     "draft-han-bmwg-agent-security-benchmark metric 5.4.7.\n")
    for r in rows:
        if r["verdict"] == "ACCEPTED":
            print(f"::error title=agmi {r['edit']}::{tool} served the edited "
                  f"memory as genuine with no signal")
        elif r["verdict"] == "NOT EVALUABLE":
            print(f"::warning title=agmi {r['edit']}::{r['detail']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agmi-check",
        description="Run the at-rest edits against one memory-store adapter "
                    "and fail on any silently accepted edit.")
    ap.add_argument("--adapter", required=True, metavar="MODULE:CLASS",
                    help="adapter to test, e.g. "
                         "agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter")
    ap.add_argument("--fail-on", choices=["accepted", "none"],
                    default="accepted",
                    help="exit 1 on any ACCEPTED edit (default), or never")
    ap.add_argument("--json", metavar="PATH", help="write the row as JSON")
    args = ap.parse_args(argv)

    adapter = load_adapter(args.adapter)
    rows = run(adapter)
    print(render(adapter.name, rows))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        gha_report(adapter.name, rows)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"tool": adapter.name, "edits": rows}, fh, indent=2)

    accepted = [r for r in rows if r["verdict"] == "ACCEPTED"]
    not_eval = [r for r in rows if r["verdict"] == "NOT EVALUABLE"]
    if not_eval and len(not_eval) == len(rows):
        print("agmi-check: no edit could be evaluated", file=sys.stderr)
        return 2
    if accepted and args.fail_on == "accepted":
        print(f"agmi-check: {len(accepted)} of {len(rows)} edits accepted "
              f"silently", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
