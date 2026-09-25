# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The five at-rest attacks.

All five assume the attacker has gained write access to the backing store
(the SQLite file, the Postgres rows, the JSON blob) but NOT access to the
tool's own signing keys or in-process integrity logic. This is the standard
"database compromise / privileged write at rest" threat model behind the
real LangGraph checkpointer CVEs.

Each attack mutates the raw store, then the harness reloads the tool and
asks whether it noticed.
"""

from __future__ import annotations

from agmi.adapters.base import MemoryAdapter
from agmi.attacks.base import Attack


class TamperAttack(Attack):
    """Modify the contents of one existing entry in place."""

    name = "tamper"
    description = "Alter the payload of a stored entry without touching its links."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to tamper with")
        target = records[len(records) // 2]
        # The adapter knows how to change meaning without breaking encoding.
        adapter.write_raw(adapter.mutate_payload(target))


class TruncateAttack(Attack):
    """Delete entries from the END of the chain.

    This is the one that slipped past OpenFang: forward-only link checks
    stay valid because the surviving prefix still chains correctly.
    """

    name = "truncate"
    description = "Remove the most recent entries from the tail of the store."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to truncate")
        # Drop the last two entries, tail first, so adapters that address
        # rows by ordinal position stay valid after the first delete.
        for rec in reversed(records[-2:]):
            adapter.delete_raw(rec.seq)


class DeleteMiddleAttack(Attack):
    """Remove a single entry from the MIDDLE of the chain."""

    name = "delete_middle"
    description = "Remove one interior entry, leaving a gap in the sequence."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 3:
            raise RuntimeError("need at least 3 records to delete a middle one")
        victim = records[len(records) // 2]
        adapter.delete_raw(victim.seq)


class ReorderAttack(Attack):
    """Swap the position of two adjacent entries."""

    name = "reorder"
    description = "Exchange two entries so events appear in the wrong order."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to reorder")
        i = len(records) // 2
        a, b = records[i - 1], records[i]
        a_seq = a.seq
        b_seq = b.seq
        a.seq, b.seq = b_seq, a_seq
        adapter.write_raw(a)
        adapter.write_raw(b)


class ForgeAttack(Attack):
    """Insert a brand-new entry that mimics a legitimate one."""

    name = "forge"
    description = "Append a fabricated entry crafted to look authentic."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to base a forgery on")
        adapter.write_raw(adapter.forge_record(records[-1]))


class CrossContextReplayAttack(Attack):
    """T6. Copy a genuine record from a SECOND context over a record in the
    first, keeping the first record's identity. Real bytes, wrong owner.

    Passes through any at-rest encryption that does not bind ciphertext to
    the record's place: the donor bytes decrypt and verify. Only a store
    that binds a record to its context (thread/user/session) rejects it."""

    name = "cross_replay"
    description = ("Replay a genuine record from another context onto this "
                   "one, keeping the victim's identity.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_replay", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not model a second context",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        adapter.seed_other(self.seed_count)
        donors = adapter.read_other_raw()
        victims = adapter.read_all_raw()
        if not donors or not victims:
            raise RuntimeError("need records in both contexts to replay")
        adapter.replay_onto(victims[-1].seq, donors[-1])


class RollbackReplayAttack(Attack):
    """T7. Copy an OLDER genuine record of the SAME context over its newest,
    winding the context back in time. Every record is genuine; only the
    order is rewritten. AAD that binds a record to its own place does not
    catch this; catching it needs coverage of the sequence."""

    name = "rollback_replay"
    description = ("Replay an older genuine record of this context over its "
                   "newest, rolling state back.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_replay", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not support replay",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to roll back")
        adapter.replay_onto(records[-1].seq, records[0])


class MetadataTamperAttack(Attack):
    """T8. Change a record's metadata (owner, source, role, timestamp) and
    leave its content untouched. A store that authenticates content but not
    its labels serves the record with the attacker's metadata, enough to
    move a record to another user or mark an untrusted source as trusted."""

    name = "metadata_tamper"
    description = ("Alter a record's owner/source/timestamp without changing "
                   "its content.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_metadata", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not expose record metadata",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to tamper metadata on")
        seq = records[len(records) // 2].seq
        meta = adapter.read_meta(seq)
        meta["agmi_meta_tampered"] = True
        adapter.write_meta(seq, meta)


ALL_AT_REST_ATTACKS: list[type[Attack]] = [
    TamperAttack,
    TruncateAttack,
    DeleteMiddleAttack,
    ReorderAttack,
    ForgeAttack,
    CrossContextReplayAttack,
    RollbackReplayAttack,
    MetadataTamperAttack,
]
