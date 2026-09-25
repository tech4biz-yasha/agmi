# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The contract every memory-store adapter must satisfy.

An adapter is the only thing that knows tool-specific details: where the
memory is stored, how to read a raw record, how to write one back, and how
to ask the tool whether its stored state is still trustworthy.

Attacks are written against this interface alone. That is the whole point:
one attack, written once, runs against every tool that has an adapter.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Record:
    """One stored memory/audit entry, in a tool-neutral shape.

    `seq` is the position in the chain/log (0-indexed). `fields` is the
    tool's own column/key values for that entry, opaque to the attacks
    except that they can be mutated and written back via the adapter.
    """

    seq: int
    fields: dict


class MemoryAdapter(ABC):
    """Wraps one memory/checkpoint tool so attacks can operate on it.

    Lifecycle used by every attack:
        setup()            -> fresh, empty store
        seed(n)            -> tool writes n legitimate entries through its
                              own normal API (so hashes/signatures are real)
        snapshot()         -> record the tool's own "is this trustworthy?"
                              answer while the store is still clean
        <attack mutates the raw store via read_raw / write_raw / delete_raw>
        reload()           -> simulate a restart: tool re-opens the store
        verify()           -> tool's own integrity answer after tampering

    An attack PASSES (the tool is safe) when verify() reports a problem
    after the raw store was tampered with. It FAILS when verify() still
    says the tampered store is fine.
    """

    #: Short tool name for the scorecard, e.g. "openfang".
    name: str
    #: Set by verify() when it returns False: the tool's own reason, in one
    #: line (the exception it raised, or which check failed). Printed in
    #: the cell's detail so a deliberate refusal can be told from a crash.
    verify_detail: str | None = None

    @abstractmethod
    def setup(self) -> None:
        """Create a fresh, empty store for one test run."""

    @abstractmethod
    def teardown(self) -> None:
        """Dispose of the store and any temp files."""

    @abstractmethod
    def seed(self, n: int) -> None:
        """Write `n` legitimate entries through the tool's normal API."""

    @abstractmethod
    def read_all_raw(self) -> list[Record]:
        """Read every stored entry directly from the backing store,
        bypassing the tool. This is how attacks see the raw bytes."""

    @abstractmethod
    def write_raw(self, record: Record) -> None:
        """Write a (possibly mutated) record back to the raw store,
        bypassing the tool's own write path and integrity hooks."""

    @abstractmethod
    def delete_raw(self, seq: int) -> None:
        """Delete the entry at `seq` directly from the raw store."""

    @abstractmethod
    def reload(self) -> None:
        """Re-open the store as the tool would on a restart, so any
        load-time integrity check runs against the tampered data."""

    @abstractmethod
    def verify(self) -> bool:
        """Return True if the tool reports its stored state is intact,
        False if it detects tampering. Attacks invert this into pass/fail."""

    # --- optional payload hooks --------------------------------------
    # Content-level attacks (tamper, forge) need to change what an entry
    # SAYS without corrupting how it is ENCODED. Only the adapter knows
    # that. The defaults work for row-per-entry stores with plain string
    # columns; blob-based stores override them.

    def mutate_payload(self, record: Record) -> Record:
        """Return `record` with its human-meaningful content altered."""
        for key, value in record.fields.items():
            if isinstance(value, str) and key not in ("hash", "prev_hash"):
                record.fields[key] = value + "  [TAMPERED]"
                return record
        raise RuntimeError("no mutable string field in record")

    def forge_record(self, template: Record) -> Record:
        """Return a new record that would sit after `template` and passes
        as authentic on inspection."""
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        return self.mutate_payload(forged)

    # --- optional hooks for the replay and metadata attacks (T6-T8) ---
    # T6 (cross-context replay), T7 (rollback replay) and T8 (metadata
    # tamper) need three things the five basic attacks do not: a SECOND
    # context (another thread/user/session) to lift a genuine record from,
    # a way to copy a genuine record's bytes onto another record's slot
    # keeping that slot's identity, and a way to change a record's metadata
    # (owner, source, timestamp) without touching its content. Only the
    # adapter knows how its store expresses these. An adapter that does not
    # implement them reports the affected cell as "not evaluable", never as
    # a pass. `supports_replay` and `supports_metadata` say which apply.

    supports_replay: bool = False
    supports_metadata: bool = False

    def seed_other(self, n: int) -> None:
        """Seed a SECOND, isolated context in the same store with `n`
        legitimate entries, each carrying a distinct marker. For T6."""
        raise NotImplementedError

    def read_other_raw(self) -> list[Record]:
        """Read the raw records of the second context seeded by seed_other."""
        raise NotImplementedError

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Copy the genuine `donor` record's content bytes onto the record
        at ordinal `victim_seq` in the FIRST context, keeping the victim
        slot's own identity. Real bytes, wrong place. T6 and T7."""
        raise NotImplementedError

    def read_meta(self, seq: int) -> dict:
        """Return the metadata fields of the record at `seq` (owner, source,
        role, timestamp), separate from its content. For T8."""
        raise NotImplementedError

    def write_meta(self, seq: int, meta: dict) -> None:
        """Write metadata fields back to the record at `seq`, leaving its
        content untouched. For T8."""
        raise NotImplementedError
