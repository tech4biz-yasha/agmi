# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for LangGraph's SqliteSaver checkpointer (the real library).

This is the first adapter in the suite that drives an actual third-party
store rather than a Python model of one. Every result it produces is a
measurement of `langgraph-checkpoint-sqlite` at the pinned version, seeded
through its own `put()` API and read back through its own `get()`/`list()`.

Store layout (as created by SqliteSaver.setup()):
    checkpoints(thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id,
                type, checkpoint BLOB, metadata BLOB)
    writes(...)

Ordering: checkpoint_id is a time-ordered UUID6, so "seq" in this adapter is
the ordinal position of a row in checkpoint_id order for the test thread.

What "verify" means here: LangGraph has no integrity check on its store. The
only thing that can fail on reload is deserialization. So verify() returns
True when the tool loads the thread and deserializes the latest checkpoint
without error, and False only when the tool itself raises. That is the
tool's honest answer, not ours.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

THREAD = "agmi-thread"
OTHER_THREAD = "agmi-thread-B"
OTHER_TOKEN = "agmi-other-"
SEED_TOKEN = "agmi-seed-"


class LangGraphSqliteAdapter(MemoryAdapter):
    name = "langgraph-sqlite"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._db: Path | None = None
        self._saver = None
        self._config = None

    # --- lifecycle -----------------------------------------------------
    def setup(self) -> None:
        from langgraph.checkpoint.sqlite import SqliteSaver
        self._dir = tempfile.TemporaryDirectory()
        self._db = Path(self._dir.name) / "checkpoints.db"
        conn = sqlite3.connect(self._db, check_same_thread=False)
        self._saver = SqliteSaver(conn)
        self._saver.setup()
        self._config = {"configurable": {"thread_id": THREAD,
                                         "checkpoint_ns": ""}}

    def teardown(self) -> None:
        if self._saver is not None:
            try:
                self._saver.conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._saver = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    # --- normal tool API (used to seed legitimately) -------------------
    def seed(self, n: int) -> None:
        from langgraph.checkpoint.base import (
            empty_checkpoint, create_checkpoint,
        )
        cfg = self._config
        cp = empty_checkpoint()
        for i in range(n):
            cp = create_checkpoint(cp, {"state": f"{SEED_TOKEN}{i}"}, i)
            cp["channel_values"] = {"state": f"{SEED_TOKEN}{i}"}
            cfg = self._saver.put(
                cfg, cp, {"source": "loop", "step": i, "writes": {}}, {},
            )

    # --- raw store access (used by attacks) ----------------------------
    COLS = ("thread_id", "checkpoint_ns", "checkpoint_id",
            "parent_checkpoint_id", "type", "checkpoint", "metadata")

    def read_all_raw(self) -> list[Record]:
        conn = self._raw()
        rows = conn.execute(
            "SELECT thread_id, checkpoint_ns, checkpoint_id, "
            "parent_checkpoint_id, type, checkpoint, metadata "
            "FROM checkpoints WHERE thread_id = ? ORDER BY checkpoint_id ASC",
            (THREAD,),
        ).fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(self.COLS, r)))
                for i, r in enumerate(rows)]

    def _id_at(self, seq: int) -> str | None:
        recs = self.read_all_raw()
        return recs[seq].fields["checkpoint_id"] if seq < len(recs) else None

    def write_raw(self, record: Record) -> None:
        """Write payload columns to the row at ordinal `record.seq`.

        If no row exists at that position (forge appends past the tail) a
        new row is inserted using the record's own ids.
        """
        f = record.fields
        target_id = self._id_at(record.seq)
        conn = self._raw()
        if target_id is None:
            conn.execute(
                "INSERT INTO checkpoints (thread_id, checkpoint_ns, "
                "checkpoint_id, parent_checkpoint_id, type, checkpoint, "
                "metadata) VALUES (?,?,?,?,?,?,?)",
                (f["thread_id"], f["checkpoint_ns"], f["checkpoint_id"],
                 f["parent_checkpoint_id"], f["type"], f["checkpoint"],
                 f["metadata"]),
            )
        else:
            conn.execute(
                "UPDATE checkpoints SET type=?, checkpoint=?, metadata=? "
                "WHERE thread_id=? AND checkpoint_id=?",
                (f["type"], f["checkpoint"], f["metadata"], THREAD, target_id),
            )
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        target_id = self._id_at(seq)
        if target_id is None:
            return
        conn = self._raw()
        conn.execute("DELETE FROM checkpoints WHERE thread_id=? AND "
                     "checkpoint_id=?", (THREAD, target_id))
        conn.execute("DELETE FROM writes WHERE thread_id=? AND "
                     "checkpoint_id=?", (THREAD, target_id))
        conn.commit()
        conn.close()

    # --- payload hooks used by content-level attacks -------------------
    def mutate_payload(self, record: Record) -> Record:
        """Change the stored state inside the msgpack blob without breaking
        the encoding, so the change is semantic rather than a corruption."""
        blob: bytes = record.fields["checkpoint"]
        for i in range(100):
            token = f"{SEED_TOKEN}{i}".encode()
            if token in blob:
                # Same byte length keeps the msgpack string header valid.
                record.fields["checkpoint"] = blob.replace(
                    token, f"agmi-TAMP-{i}".encode(), 1)
                return record
        raise RuntimeError("seed token not found in checkpoint blob")

    def forge_record(self, template: Record) -> Record:
        """Build a plausible new tip: fresh UUID6 id, parent = old tip,
        payload copied and altered."""
        # LangGraph orders checkpoints by id string; a UUID6 later than the
        # tip is enough. Build it from the tip so it sorts after it.
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["parent_checkpoint_id"] = template.fields["checkpoint_id"]
        forged.fields["checkpoint_id"] = self._later_id(
            template.fields["checkpoint_id"])
        return self.mutate_payload(forged)

    @staticmethod
    def _later_id(tip_id: str) -> str:
        """Return a UUID-shaped id that sorts after `tip_id` as text, which
        is exactly how SqliteSaver picks the latest checkpoint."""
        head, _, tail = tip_id.rpartition("-")
        bumped = format(int(tail, 16) + 1, "012x")
        return f"{head}-{bumped}"

    # --- hooks for T6/T7/T8 -------------------------------------------
    def seed_other(self, n: int) -> None:
        from langgraph.checkpoint.base import empty_checkpoint, create_checkpoint
        cfg = {"configurable": {"thread_id": OTHER_THREAD, "checkpoint_ns": ""}}
        cp = empty_checkpoint()
        for i in range(n):
            cp = create_checkpoint(cp, {"state": f"{OTHER_TOKEN}{i}"}, i)
            cp["channel_values"] = {"state": f"{OTHER_TOKEN}{i}"}
            cfg = self._saver.put(cfg, cp, {"source": "loop", "step": i,
                                            "writes": {}}, {})

    def read_other_raw(self) -> list[Record]:
        conn = self._raw()
        rows = conn.execute(
            "SELECT thread_id, checkpoint_ns, checkpoint_id, "
            "parent_checkpoint_id, type, checkpoint, metadata "
            "FROM checkpoints WHERE thread_id = ? ORDER BY checkpoint_id ASC",
            (OTHER_THREAD,),
        ).fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(self.COLS, r)))
                for i, r in enumerate(rows)]

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target_id = self._id_at(victim_seq)
        if target_id is None:
            raise RuntimeError("no victim row at that position")
        conn = self._raw()
        conn.execute(
            "UPDATE checkpoints SET type=?, checkpoint=?, metadata=? "
            "WHERE thread_id=? AND checkpoint_id=?",
            (donor.fields["type"], donor.fields["checkpoint"],
             donor.fields["metadata"], THREAD, target_id),
        )
        conn.commit()
        conn.close()

    def read_meta(self, seq: int) -> dict:
        import json
        recs = self.read_all_raw()
        raw = recs[seq].fields["metadata"]
        try:
            return json.loads(raw) if isinstance(raw, (str, bytes)) else dict(raw)
        except Exception:  # noqa: BLE001
            return {"_raw": raw}

    def write_meta(self, seq: int, meta: dict) -> None:
        import json
        target_id = self._id_at(seq)
        if target_id is None:
            raise RuntimeError("no row at that position")
        conn = self._raw()
        conn.execute(
            "UPDATE checkpoints SET metadata=? WHERE thread_id=? AND checkpoint_id=?",
            (json.dumps(meta).encode(), THREAD, target_id),
        )
        conn.commit()
        conn.close()

    # --- reload + verify (the tool's own integrity answer) -------------
    def reload(self) -> None:
        from langgraph.checkpoint.sqlite import SqliteSaver
        try:
            self._saver.conn.close()
        except Exception:  # noqa: BLE001
            pass
        conn = sqlite3.connect(self._db, check_same_thread=False)
        self._saver = SqliteSaver(conn)

    def verify(self) -> bool:
        cfg = {"configurable": {"thread_id": THREAD}}
        self.verify_detail = None
        try:
            latest = self._saver.get(cfg)
            if latest is None:
                self.verify_detail = "get() returned no checkpoint"
                return False
            # Force a full walk so any undecodable row surfaces.
            list(self._saver.list(cfg))
            return True
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
