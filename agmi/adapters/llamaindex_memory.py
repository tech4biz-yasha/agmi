# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Adapter for LlamaIndex `Memory` on its SQLAlchemy chat store (the real library).

`Memory` is LlamaIndex's chat memory: every message is a row in
`llama_index_memory`, keyed by session, and `aget()` reads the active rows
back in id order to build the model's context. Every result here is a
measurement of `llama-index-core` at the pinned version, seeded through
`Memory.aput_messages()` and read back through `Memory.aget()`.

Store layout (as created by the library):
    llama_index_memory(id PK, key, timestamp, role, status, data JSON)

Ordering: `id`, so `seq` is the ordinal position of a row for the victim
session in id order.

What "verify" means here: the library has no integrity check on its store.
verify() returns True when a fresh `Memory` on the same file returns from
`aget()` without raising, and False only when the library itself raises.

T8 metadata: `key` (owner session), `timestamp`, `role` and `status` are
the row's metadata. write_meta() applies a changed key, role or status
directly; any other change is applied as a rewritten timestamp, so the
edit is real on disk.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

SESSION = "agmi-user-A"
OTHER_SESSION = "agmi-user-B"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
COLS = ("id", "key", "timestamp", "role", "status", "data")
TABLE = "llama_index_memory"


def _run(coro):
    return asyncio.run(coro)


class LlamaIndexMemoryAdapter(MemoryAdapter):
    name = "llamaindex-memory-sqlite"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._db: Path | None = None
        self._seeded = 0

    def setup(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db = Path(self._dir.name) / "memory.db"
        self._seeded = 0

    def teardown(self) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _memory(self, sid: str):
        from llama_index.core.memory import Memory
        return Memory.from_defaults(session_id=sid, token_limit=100_000,
                                    async_database_uri=f"sqlite+aiosqlite:///{self._db}")

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    def _put(self, sid: str, texts: list[str]) -> None:
        from llama_index.core.llms import ChatMessage
        msgs = [ChatMessage(role="user" if i % 2 == 0 else "assistant", content=t)
                for i, t in enumerate(texts)]
        _run(self._memory(sid).aput_messages(msgs))

    def seed(self, n: int) -> None:
        self._put(SESSION, [f"{SEED_TOKEN}{i}" for i in range(n)])
        self._seeded = n

    def _rows(self, sid: str) -> list[Record]:
        conn = self._raw()
        rows = conn.execute(
            f'SELECT id, "key", timestamp, role, status, data FROM {TABLE} '
            'WHERE "key" = ? ORDER BY id ASC', (sid,)).fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(COLS, r))) for i, r in enumerate(rows)]

    def read_all_raw(self) -> list[Record]:
        return self._rows(SESSION)

    def _id_at(self, seq: int) -> int | None:
        recs = self.read_all_raw()
        return recs[seq].fields["id"] if seq < len(recs) else None

    def write_raw(self, record: Record) -> None:
        f = record.fields
        target = self._id_at(record.seq)
        conn = self._raw()
        if target is None:
            conn.execute(
                f'INSERT INTO {TABLE} ("key", timestamp, role, status, data) VALUES (?,?,?,?,?)',
                (f["key"], f["timestamp"] + 1, f["role"], f["status"], f["data"]))
        else:
            conn.execute(f"UPDATE {TABLE} SET role=?, status=?, data=? WHERE id=?",
                         (f["role"], f["status"], f["data"], target))
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._id_at(seq)
        if target is None:
            return
        conn = self._raw()
        conn.execute(f"DELETE FROM {TABLE} WHERE id=?", (target,))
        conn.commit()
        conn.close()

    def reload(self) -> None:
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        try:
            msgs = _run(self._memory(SESSION).aget())
        except Exception as e:  # noqa: BLE001
            self.verify_detail = f"{type(e).__name__}: {e}"
            return False
        if len(msgs) < self._seeded:
            self.verify_detail = f"aget returned {len(msgs)} of {self._seeded}, no error raised"
        return True

    def mutate_payload(self, record: Record) -> Record:
        data = json.loads(record.fields["data"])
        for block in data.get("blocks", []):
            for i in range(100):
                if block.get("text") == f"{SEED_TOKEN}{i}":
                    block["text"] = f"agmi-TAMP-{i}"
                    record.fields["data"] = json.dumps(data)
                    return record
        raise RuntimeError("seed token not found in data")

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["id"] = None
        return self.mutate_payload(forged)

    def seed_other(self, n: int) -> None:
        self._put(OTHER_SESSION, [f"{OTHER_TOKEN}{i}" for i in range(n)])

    def read_other_raw(self) -> list[Record]:
        return self._rows(OTHER_SESSION)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._id_at(victim_seq)
        if target is None:
            raise RuntimeError("no victim row at that position")
        conn = self._raw()
        conn.execute(f"UPDATE {TABLE} SET role=?, data=? WHERE id=?",
                     (donor.fields["role"], donor.fields["data"], target))
        conn.commit()
        conn.close()

    def read_meta(self, seq: int) -> dict:
        r = self.read_all_raw()[seq].fields
        return {"key": r["key"], "timestamp": r["timestamp"], "role": r["role"], "status": r["status"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._id_at(seq)
        if target is None:
            raise RuntimeError("no row at that position")
        cur = self.read_meta(seq)
        key = meta.get("key", cur["key"])
        ts = meta.get("timestamp", cur["timestamp"])
        role = meta.get("role", cur["role"])
        status = meta.get("status", cur["status"])
        if set(meta) - set(cur) and (key, ts, role, status) == tuple(cur.values()):
            ts = 0  # no column for the extra key: rewrite the timestamp so the edit is real
        conn = self._raw()
        conn.execute(f'UPDATE {TABLE} SET "key"=?, timestamp=?, role=?, status=? WHERE id=?',
                     (key, ts, role, status, target))
        conn.commit()
        conn.close()
