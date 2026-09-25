# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapters for inspeximus (the real library, `pip install inspeximus`).

inspeximus stores memories in a SQLite file with one `records(id TEXT PRIMARY KEY, ord INTEGER, doc
TEXT)` row per memory. With receipts turned on it also keeps a sidecar `<store>.receipts.json`: one
receipt per write, each committing to the record's text, key, type and attribution, chained by hash
to the previous receipt, and Ed25519-signed when a key is given (signing needs the `cryptography`
package: `pip install "inspeximus[crypto]"`, which the `inspeximus` extra here pulls). After every
receipt the store also writes the chain's head (first receipt, count, tip) to the user's config
home, outside the store's directory.

Three rows come out of this file, because the answer depends on the configuration and on what the
attacker holds.

`inspeximus (default, read path)`: receipts off, which is how a fresh store ships. `verify()` is
the agent's own read after a restart, the same shape the LangGraph and Mem0 adapters use: the store
loads, `recall()` answers, `history()` answers. Nothing checks the rows, so every attack is
accepted.

`inspeximus receipts+key, attacker holds the store's directory`: receipts on with a fresh signing
key. The attacker has write access to the store's directory, which is agmi's threat model, so every
deletion is mirrored into the receipts sidecar. `verify()` is `verify_writes()`, the store's own
audit method (also its `verify_writes` MCP tool). Tamper, reorder and forge are reported because
the receipts are signed and the attacker has no key. delete_middle is reported because the receipt
after the gap names the missing one as its predecessor, and `prev` is inside the signed payload, so
it cannot be re-linked. truncate is reported because the chain on disk is shorter than the head the
store keeps outside the directory, and the agent's own later writes do not lower that head.

`inspeximus receipts+key, attacker holds the store's directory and the config home`: the same
attacker also removes the head file, so the attacker is everything the same OS user writes. tamper,
delete_middle, reorder and forge stay reported; truncate is accepted: cutting records and receipts
from the tail leaves a shorter chain that is internally consistent, and no file outside the
attacker's reach records the earlier length. Any anchor the same user account can write, wherever
it sits, shares that limit; only an anchor off the machine does not. The remedy inspeximus offers
for that attacker is `anchor()` handed to a witness plus `verify_consistency()`; agmi does not
model an anchor off the machine, so the cell stays accepted.

Two things to read the receipts rows honestly. First, detection is the audit call: after any of the
five attacks the store still loads and `recall()` serves the altered record. Second, a receipt
commits to text, key, type and attribution; an at-rest edit to a field outside that set, such as
the timestamp, verifies clean.

Receipts are off by default. Off, `verify_writes()` refuses to vouch for any store, touched or not,
which would score every attack "detected" for the wrong reason: a fail-closed verifier is not
detection. The receipts rows therefore seed with receipts on and a fresh key, and the clean-store
check in `Attack.run` passes on the untouched store first.

Measured on inspeximus 2.38.0, 2026-09-16, submitted by the inspeximus maintainer; reproduced
independently by agmi on inspeximus 3.0.0 (macOS, Python 3.12), 2026-09-20.
"""



from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"


class InspeximusRowsAdapter(MemoryAdapter):
    """Receipts on, signed; the attacker holds the SQLite file only."""

    name = "inspeximus-rows"
    supports_replay = True
    supports_metadata = True

    #: True: the attacker also holds the receipts sidecar and removes the matching receipt on
    #: delete_raw. Models write access to the store's directory (still not the signing key).
    attacker_holds_sidecar = False

    #: True: the attacker also holds the user's config home and removes the chain head the store
    #: keeps there after every receipt. Models an attacker with the whole user account.
    attacker_holds_head = False

    #: False: the default configuration, no receipts; verify() is the read path.
    receipts = True

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._path: Path | None = None
        self._store = None
        self._sk = None
        self._pk = None

    # --- lifecycle -----------------------------------------------------
    def _open(self):
        from inspeximus import Inspeximus
        if self.receipts:
            return Inspeximus(str(self._path), receipts=True, receipt_key=self._sk)
        return Inspeximus(str(self._path))

    def setup(self) -> None:
        from inspeximus import new_receipt_keypair
        self._dir = tempfile.TemporaryDirectory()
        self._path = Path(self._dir.name) / "memory.json"
        if self.receipts:
            self._sk, self._pk = new_receipt_keypair()
        self._store = self._open()

    def teardown(self) -> None:
        self._store = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    # --- normal tool API (used to seed legitimately) -------------------
    def seed(self, n: int) -> None:
        for i in range(n):
            self._store.remember(f"{SEED_TOKEN}{i}: the limit is {50 + i}", key=f"fact::{i}")

    # --- raw store access (used by attacks) ----------------------------
    def read_all_raw(self) -> list[Record]:
        conn = self._raw()
        try:
            rows = conn.execute("SELECT id, ord, doc FROM records ORDER BY ord ASC").fetchall()
        finally:
            conn.close()
        return [Record(seq=i, fields={"id": rid, "ord": ordv, "doc": json.loads(doc)})
                for i, (rid, ordv, doc) in enumerate(rows)]

    def _row_at(self, seq: int):
        recs = self.read_all_raw()
        return recs[seq].fields if seq < len(recs) else None

    def write_raw(self, record: Record) -> None:
        """Write the record's doc into the row at ordinal `record.seq`, keeping that row's id (the
        contents move, the primary key does not, so the row stays valid to the tool). With no row at
        that position (forge appends past the tail) a new row is inserted with the record's own
        id."""
        target = self._row_at(record.seq)
        doc = dict(record.fields["doc"])
        conn = self._raw()
        try:
            if target is None:
                conn.execute("INSERT INTO records (id, ord, doc) VALUES (?, ?, ?)",
                             (doc["id"], int(record.fields.get("ord", record.seq)),
                              json.dumps(doc)))
            else:
                doc["id"] = target["id"]
                conn.execute("UPDATE records SET doc = ? WHERE id = ?",
                             (json.dumps(doc), target["id"]))
            conn.commit()
        finally:
            conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._row_at(seq)
        if target is None:
            return
        conn = self._raw()
        try:
            conn.execute("DELETE FROM records WHERE id = ?", (target["id"],))
            conn.commit()
        finally:
            conn.close()
        if self.attacker_holds_sidecar:
            self._drop_receipt(target["id"])
        if self.attacker_holds_head:
            self._drop_head()

    def _drop_head(self) -> None:
        """Remove the chain head the store keeps outside its directory. Raises if the store never
        wrote one, so a store that stopped writing heads fails loudly instead of scoring the row for
        the wrong reason; a second deletion in the same attack finds it already gone, which is fine."""
        hp = self._store.head_path()
        if not hp:
            raise RuntimeError("no chain head outside the store; re-measure the head row")
        if os.path.exists(hp):
            os.remove(hp)
            self._head_dropped = True
        elif not getattr(self, "_head_dropped", False):
            raise RuntimeError("the store wrote no chain head; re-measure the head row")

    def receipts_path(self) -> Path:
        return Path(str(self._path) + ".receipts.json")

    def _drop_receipt(self, memory_id: str) -> None:
        """Remove the one receipt for `memory_id`. Raises if the sidecar format no longer matches,
        so a format change fails loudly instead of flipping the sidecar row to 5 of 5."""
        rp = self.receipts_path()
        if not rp.exists():
            raise RuntimeError(f"no receipts sidecar at {rp}; re-measure the sidecar row")
        chain = json.loads(rp.read_text(encoding="utf-8"))
        kept = [r for r in chain if r.get("memory_id") != memory_id]
        if len(kept) != len(chain) - 1:
            raise RuntimeError(f"sidecar format changed: expected to drop one receipt for "
                               f"{memory_id}, dropped {len(chain) - len(kept)}; re-measure the "
                               f"sidecar row")
        rp.write_text(json.dumps(kept), encoding="utf-8")

    # --- hooks for T6/T7/T8 -------------------------------------------
    def seed_other(self, n: int) -> None:
        """Seed a second context (a different meta.uid) in the same store."""
        for i in range(n):
            self._store.remember(f"{OTHER_TOKEN}{i}: the limit is {90 + i}",
                                 key=f"other::{i}", user_id="ctx-B")

    def read_other_raw(self) -> list[Record]:
        conn = self._raw()
        try:
            rows = conn.execute("SELECT id, ord, doc FROM records "
                                "ORDER BY ord ASC").fetchall()
        finally:
            conn.close()
        out = []
        j = 0
        for rid, ordv, doc in rows:
            d = json.loads(doc)
            if (d.get("meta") or {}).get("uid") == "ctx-B":
                out.append(Record(seq=j, fields={"id": rid, "ord": ordv, "doc": d}))
                j += 1
        return out

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Copy the donor doc onto the victim row, keeping the victim row's
        id and ord. Genuine bytes, wrong place."""
        target = self._row_at(victim_seq)
        if target is None:
            raise RuntimeError("no victim row at that position")
        doc = dict(donor.fields["doc"])
        doc["id"] = target["id"]
        conn = self._raw()
        try:
            conn.execute("UPDATE records SET doc = ? WHERE id = ?",
                         (json.dumps(doc), target["id"]))
            conn.commit()
        finally:
            conn.close()

    def read_meta(self, seq: int) -> dict:
        row = self._row_at(seq)
        if row is None:
            return {}
        doc = row["doc"]
        return {"source": doc.get("source"), "meta": doc.get("meta"),
                "ts": doc.get("ts"), "iso": doc.get("iso")}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._row_at(seq)
        if target is None:
            raise RuntimeError("no row at that position")
        doc = dict(target["doc"])
        # move the record to another owner and flip its source to trusted,
        # content untouched.
        doc["meta"] = {**(doc.get("meta") or {}), "uid": "ctx-B",
                       "agmi_meta_tampered": True}
        doc["source"] = {"doc": "user"}
        conn = self._raw()
        try:
            conn.execute("UPDATE records SET doc = ? WHERE id = ?",
                         (json.dumps(doc), target["id"]))
            conn.commit()
        finally:
            conn.close()

    # --- payload hooks -------------------------------------------------
    def mutate_payload(self, record: Record) -> Record:
        doc = dict(record.fields["doc"])
        doc["text"] = doc["text"].replace(SEED_TOKEN, "agmi-TAMP-", 1) + "  [TAMPERED]"
        record.fields["doc"] = doc
        return record

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1,
                        fields={"id": None, "ord": int(template.fields["ord"]) + 1,
                                "doc": dict(template.fields["doc"])})
        forged.fields["doc"]["id"] = "f0" + os.urandom(4).hex()
        forged.fields["doc"]["key"] = "fact::planted"
        forged.fields["id"] = forged.fields["doc"]["id"]
        return self.mutate_payload(forged)

    # --- restart + the tool's own answer -------------------------------
    def reload(self) -> None:
        self._store = self._open()

    def verify(self) -> bool:
        self.verify_detail = None
        if not self.receipts:
            return self._read_path_ok()
        ok, problems = self._store.verify_writes(expected_pubkey=self._pk)
        if not ok:
            self.verify_detail = f"verify_writes: {str(problems)[:140]}"
        return bool(ok)

    def _read_path_ok(self) -> bool:
        """The agent's own read after a restart: the store loads, recall and history answer."""
        try:
            _ = list(self._store.items)
            self._store.recall("limit", k=10)
            self._store.history("fact::0")
        except Exception as exc:  # noqa: BLE001 - a raise here is the tool refusing, which is detection
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
        return True


class InspeximusRowsSidecarAdapter(InspeximusRowsAdapter):
    """Receipts on, signed; the attacker holds the store's directory (the SQLite file and the
    receipts sidecar)."""

    name = "inspeximus-rows+sidecar"
    attacker_holds_sidecar = True
    # verify() here is the store's audit call, not its read path: after any of the five attacks
    # the store still loads and recall() serves the altered record. full_runner prints a detection
    # on an audit call as "reported" and shows "audit" in the checkedAt column.
    detection_point = "audit"


class InspeximusRowsSidecarHeadAdapter(InspeximusRowsSidecarAdapter):
    """Receipts on, signed; the attacker holds the store's directory and the config home where the
    chain head lives."""

    name = "inspeximus-rows+sidecar+head"
    attacker_holds_head = True
    detection_point = "audit"


class InspeximusDefaultAdapter(InspeximusRowsAdapter):
    """Receipts off, as a fresh store ships; verify() is the read path."""

    name = "inspeximus-default"
    receipts = False
