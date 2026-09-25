# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Adapter for the OpenAI Agents SDK `SQLiteSession` (the real library).

`SQLiteSession` is the SDK's persistent conversation memory: every item the
agent sees or produces is appended to `agent_messages` and read back in id
order by `get_items()` on the next run. Every result here is a measurement
of `openai-agents` at the pinned version, seeded through its own
`add_items()` and read back through its own `get_items()`.

Store layout (as created by the SDK):
    agent_sessions(session_id PK, created_at, updated_at)
    agent_messages(id AUTOINCREMENT, session_id, message_data TEXT,
                   created_at)

Ordering: `id`, so `seq` is the ordinal position of a row for the victim
session in id order.

What "verify" means here: the SDK has no integrity check on its store. The
only thing that can fail on reload is JSON decoding of `message_data`,
which the SDK skips silently for malformed rows. So verify() returns True
when `get_items()` returns without raising and every seeded position is
still present, and False only when the SDK itself raises. That is the
tool's honest answer, not ours.

T8 metadata: the only per-record metadata the store keeps is `session_id`
(who owns the row) and `created_at`. The generic T8 edit adds a key no
column can hold, so write_meta() applies it as a rewritten `created_at`:
that is what the T8 cell measures. A changed `session_id` (moving the row
to another user) is measured separately in the pinned tests.
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
COLS = ("id", "session_id", "message_data", "created_at")


def _run(coro):
    return asyncio.run(coro)


class OpenAIAgentsSessionAdapter(MemoryAdapter):
    name = "openai-agents-sqlite-session"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._db: Path | None = None
        self._seeded = 0

    # --- lifecycle ------------------------------------------------------
    def setup(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db = Path(self._dir.name) / "session.db"
        self._seeded = 0

    def teardown(self) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _session(self, sid: str):
        from agents import SQLiteSession
        return SQLiteSession(sid, str(self._db))

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    def seed(self, n: int) -> None:
        items = [{"role": "user" if i % 2 == 0 else "assistant",
                  "content": f"{SEED_TOKEN}{i}"} for i in range(n)]
        s = self._session(SESSION)
        _run(s.add_items(items))
        s.close()
        self._seeded = n

    # --- raw access -----------------------------------------------------
    def _rows(self, sid: str) -> list[Record]:
        conn = self._raw()
        rows = conn.execute(
            "SELECT id, session_id, message_data, created_at FROM agent_messages "
            "WHERE session_id = ? ORDER BY id ASC", (sid,)).fetchall()
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
                "INSERT INTO agent_messages (session_id, message_data, created_at) "
                "VALUES (?,?,?)", (f["session_id"], f["message_data"], f["created_at"]))
        else:
            conn.execute(
                "UPDATE agent_messages SET message_data=?, created_at=? WHERE id=?",
                (f["message_data"], f["created_at"], target))
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._id_at(seq)
        if target is None:
            return
        conn = self._raw()
        conn.execute("DELETE FROM agent_messages WHERE id=?", (target,))
        conn.commit()
        conn.close()

    def reload(self) -> None:
        # Nothing is cached in process: every SQLiteSession call opens the
        # file. A restart is therefore a fresh session object, made in verify.
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        try:
            s = self._session(SESSION)
            items = _run(s.get_items())
            s.close()
        except Exception as e:  # noqa: BLE001
            self.verify_detail = f"{type(e).__name__}: {e}"
            return False
        if len(items) < self._seeded:
            # The SDK drops rows whose JSON does not decode, silently. It did
            # not raise, so this is still "accepted" at the read path; the
            # detail records what came back for the report.
            self.verify_detail = f"get_items returned {len(items)} of {self._seeded}, no error raised"
        return True

    # --- payload hooks --------------------------------------------------
    def mutate_payload(self, record: Record) -> Record:
        data = json.loads(record.fields["message_data"])
        for i in range(100):
            if data.get("content") == f"{SEED_TOKEN}{i}":
                data["content"] = f"agmi-TAMP-{i}"
                record.fields["message_data"] = json.dumps(data)
                return record
        raise RuntimeError("seed token not found in message_data")

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["id"] = None
        return self.mutate_payload(forged)

    # --- hooks for T6/T7/T8 ---------------------------------------------
    def seed_other(self, n: int) -> None:
        items = [{"role": "user" if i % 2 == 0 else "assistant",
                  "content": f"{OTHER_TOKEN}{i}"} for i in range(n)]
        s = self._session(OTHER_SESSION)
        _run(s.add_items(items))
        s.close()

    def read_other_raw(self) -> list[Record]:
        return self._rows(OTHER_SESSION)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._id_at(victim_seq)
        if target is None:
            raise RuntimeError("no victim row at that position")
        conn = self._raw()
        conn.execute("UPDATE agent_messages SET message_data=? WHERE id=?",
                     (donor.fields["message_data"], target))
        conn.commit()
        conn.close()

    def read_meta(self, seq: int) -> dict:
        r = self.read_all_raw()[seq].fields
        return {"session_id": r["session_id"], "created_at": r["created_at"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._id_at(seq)
        if target is None:
            raise RuntimeError("no row at that position")
        current = self.read_meta(seq)
        sid = meta.get("session_id", current["session_id"])
        created = meta.get("created_at", current["created_at"])
        if set(meta) - {"session_id", "created_at"} and created == current["created_at"]:
            # No column can hold the extra key: apply the tamper to the
            # timestamp instead, so the metadata edit is real on disk.
            created = "2000-01-01 00:00:00"
        conn = self._raw()
        conn.execute("UPDATE agent_messages SET session_id=?, created_at=? WHERE id=?",
                     (sid, created, target))
        conn.commit()
        conn.close()
