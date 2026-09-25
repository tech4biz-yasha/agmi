# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for Letta's core-memory block checkpoint history (the real library).

Letta (0.16.x) keeps an agent's core memory in `block` rows and gives each
block an undo/redo history in `block_history`, one row per checkpoint with a
`sequence_number`. `block.current_history_entry_id` points at the checkpoint
the block is currently sitting on. This is the closest thing Letta has to a
checkpoint chain, so it is what the at-rest attacks target.

Store layout (Postgres, Letta is Postgres only since 0.13):
    block(id, label, value, version, current_history_entry_id, ...)
    block_history(id, block_id, sequence_number, value, actor_id, ...)

Seeding goes through Letta's own BlockManager: create the block, then for
each step update its value and call checkpoint_block_async(), exactly as an
agent editing its own memory would. Attacks then edit the Postgres rows
directly.

What "verify" means here: Letta has no integrity check on this history. Its
undo()/redo() are written to tolerate missing sequence numbers ("if older
sequences have been pruned, we jump..."), so gaps are by design invisible.
verify() loads the block through Letta, walks undo to the earliest checkpoint
and redo back to the latest, and returns True if Letta raised nothing. That
is the tool's honest answer.

Database: set LETTA_PG_URI to a Postgres you control (e.g. the docker
`pgvector/pgvector:pg16` image). If it is unset, the adapter starts an
embedded Postgres via the `pgserver` package so the suite still runs in CI
with no Docker. Either way the adapter creates and drops only the four tables
it needs, so it never touches a real Letta install.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import psycopg2

from agmi.adapters.base import MemoryAdapter, Record

SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
# Letta's ORM joins across many tables even for a simple block read, so the
# whole schema is created. It is dropped again on teardown.


def _ensure_env() -> str:
    """Make sure Letta will connect to a Postgres we control. Must run
    before `letta` is imported anywhere in the process."""
    import sys
    os.environ.setdefault("LETTA_DISABLE_SQLALCHEMY_POOLING", "true")
    uri = os.environ.get("LETTA_PG_URI")
    if uri:
        return uri
    if "letta.server.db" in sys.modules:
        raise NotImplementedError(
            "letta was imported before this adapter set LETTA_PG_URI; its "
            "engine is already bound. Import the adapter first, or set "
            "LETTA_PG_URI yourself before importing letta.")
    try:
        import pgserver
    except ImportError as exc:
        raise NotImplementedError(
            "set LETTA_PG_URI to a Postgres, or `pip install pgserver` "
            "for an embedded one") from exc
    import logging
    logging.getLogger("pgserver").setLevel(logging.ERROR)
    pgdata = os.path.join(tempfile.gettempdir(), "agmi-letta-pg")
    server = pgserver.get_server(pgdata)
    # pgserver hands out a passwordless unix-socket URI. Letta's URI
    # rewriter drops the username when the password is empty and needs a
    # hostname present, so set a password and spell the URI out in full.
    server.psql("ALTER USER postgres PASSWORD 'agmi';")
    sock = server.get_uri().split("host=")[-1]
    uri = f"postgresql://postgres:agmi@localhost/postgres?host={sock}"
    os.environ["LETTA_PG_URI"] = uri
    _ensure_env.server = server  # keep alive for the process
    return uri


class LettaBlockHistoryAdapter(MemoryAdapter):
    name = "letta-block-history"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._uri: str | None = None
        self._actor = None
        self._block_id: str | None = None
        self._other_block_id: str | None = None
        self._tables = None

    # --- lifecycle -----------------------------------------------------
    def setup(self) -> None:
        self._uri = _ensure_env()
        import letta.orm  # noqa: F401  registers every table on Base
        from letta.orm.base import Base
        from letta.server.db import engine
        from sqlalchemy import text
        self._tables = True

        async def _init():
            async with engine.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
            from letta.services.organization_manager import OrganizationManager
            from letta.services.user_manager import UserManager
            org = await OrganizationManager().create_default_organization_async()
            return await UserManager().create_default_actor_async(org_id=org.id)

        self._actor = asyncio.run(_init())

    def teardown(self) -> None:
        if self._tables is None:
            return
        from letta.orm.base import Base
        from letta.server.db import engine

        async def _drop():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
        try:
            asyncio.run(_drop())
        except Exception:  # noqa: BLE001
            pass

    def _raw(self):
        return psycopg2.connect(self._uri)

    # --- normal tool API (used to seed legitimately) -------------------
    def seed(self, n: int) -> None:
        from letta.schemas.block import Block, BlockUpdate
        from letta.services.block_manager import BlockManager

        async def _seed():
            bm = BlockManager()
            blk = await bm.create_or_update_block_async(
                Block(label="human", value=f"{SEED_TOKEN}0"), actor=self._actor)
            blk = await bm.checkpoint_block_async(blk.id, actor=self._actor)
            for i in range(1, n):
                await bm.update_block_async(
                    blk.id, BlockUpdate(value=f"{SEED_TOKEN}{i}"),
                    actor=self._actor)
                blk = await bm.checkpoint_block_async(blk.id, actor=self._actor)
            return blk.id

        self._block_id = asyncio.run(_seed())

    # --- raw store access (used by attacks) ----------------------------
    COLS = ("id", "block_id", "sequence_number", "value", "label",
            "limit", "actor_type", "actor_id", "organization_id")

    def read_all_raw(self) -> list[Record]:
        conn = self._raw()
        cur = conn.cursor()
        cur.execute(
            'SELECT id, block_id, sequence_number, value, label, "limit", '
            "actor_type, actor_id, organization_id FROM block_history "
            "WHERE block_id = %s ORDER BY sequence_number ASC",
            (self._block_id,),
        )
        rows = cur.fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(self.COLS, r)))
                for i, r in enumerate(rows)]

    def _repoint(self, cur, history_id: str | None, value: str | None) -> None:
        """Move the block onto a history row the way an attacker with DB
        write access would, so the FK stays satisfied."""
        if history_id is None:
            cur.execute("UPDATE block SET current_history_entry_id = NULL "
                        "WHERE id = %s", (self._block_id,))
        else:
            cur.execute("UPDATE block SET current_history_entry_id = %s, "
                        "value = %s WHERE id = %s",
                        (history_id, value, self._block_id))

    def write_raw(self, record: Record) -> None:
        f = record.fields
        recs = self.read_all_raw()
        conn = self._raw()
        cur = conn.cursor()
        if record.seq < len(recs):
            target = recs[record.seq].fields["id"]
            cur.execute("UPDATE block_history SET value = %s WHERE id = %s",
                        (f["value"], target))
            # If the block currently sits on this row, its live value
            # follows the history row (that is what undo/redo would load).
            cur.execute("SELECT current_history_entry_id FROM block "
                        "WHERE id = %s", (self._block_id,))
            if cur.fetchone()[0] == target:
                cur.execute("UPDATE block SET value = %s WHERE id = %s",
                            (f["value"], self._block_id))
        else:
            cur.execute(
                "INSERT INTO block_history (id, block_id, sequence_number, "
                'value, label, "limit", actor_type, actor_id, '
                "organization_id, created_at, updated_at, is_deleted) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),now(),false)",
                (f["id"], f["block_id"], f["sequence_number"], f["value"],
                 f["label"], f["limit"], f["actor_type"], f["actor_id"],
                 f["organization_id"]),
            )
            self._repoint(cur, f["id"], f["value"])
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        recs = self.read_all_raw()
        if seq >= len(recs):
            return
        victim = recs[seq].fields["id"]
        conn = self._raw()
        cur = conn.cursor()
        cur.execute("SELECT current_history_entry_id FROM block WHERE id = %s",
                    (self._block_id,))
        if cur.fetchone()[0] == victim:
            # Deleting the tip: point the block at the new tail first.
            survivors = [r for r in recs if r.fields["id"] != victim]
            tail = survivors[-1].fields if survivors else None
            self._repoint(cur, tail["id"] if tail else None,
                          tail["value"] if tail else None)
        cur.execute("DELETE FROM block_history WHERE id = %s", (victim,))
        conn.commit()
        conn.close()

    # --- hooks for T6/T7/T8 -------------------------------------------
    def seed_other(self, n: int) -> None:
        """Seed a SECOND block (another block_id) the same legitimate way,
        so its history rows are genuine and can be replayed onto the first."""
        from letta.schemas.block import Block, BlockUpdate
        from letta.services.block_manager import BlockManager

        async def _seed():
            bm = BlockManager()
            blk = await bm.create_or_update_block_async(
                Block(label="persona", value=f"{OTHER_TOKEN}0"), actor=self._actor)
            blk = await bm.checkpoint_block_async(blk.id, actor=self._actor)
            for i in range(1, n):
                await bm.update_block_async(
                    blk.id, BlockUpdate(value=f"{OTHER_TOKEN}{i}"),
                    actor=self._actor)
                blk = await bm.checkpoint_block_async(blk.id, actor=self._actor)
            return blk.id

        self._other_block_id = asyncio.run(_seed())

    def read_other_raw(self) -> list[Record]:
        conn = self._raw()
        cur = conn.cursor()
        cur.execute(
            'SELECT id, block_id, sequence_number, value, label, "limit", '
            "actor_type, actor_id, organization_id FROM block_history "
            "WHERE block_id = %s ORDER BY sequence_number ASC",
            (self._other_block_id,),
        )
        rows = cur.fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(self.COLS, r)))
                for i, r in enumerate(rows)]

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Copy the donor history row's genuine value onto the victim row in
        the first block, keeping the victim row's id/block_id/sequence. If
        the block currently sits on the victim row, its live value follows,
        which is what undo/redo would load."""
        recs = self.read_all_raw()
        if victim_seq >= len(recs):
            raise RuntimeError("no victim row at that position")
        target = recs[victim_seq].fields["id"]
        conn = self._raw()
        cur = conn.cursor()
        cur.execute("UPDATE block_history SET value = %s WHERE id = %s",
                    (donor.fields["value"], target))
        cur.execute("SELECT current_history_entry_id FROM block WHERE id = %s",
                    (self._block_id,))
        if cur.fetchone()[0] == target:
            cur.execute("UPDATE block SET value = %s WHERE id = %s",
                        (donor.fields["value"], self._block_id))
        conn.commit()
        conn.close()

    def read_meta(self, seq: int) -> dict:
        recs = self.read_all_raw()
        f = recs[seq].fields
        return {"actor_id": f["actor_id"], "actor_type": f["actor_type"],
                "organization_id": f["organization_id"], "label": f["label"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        recs = self.read_all_raw()
        if seq >= len(recs):
            raise RuntimeError("no row at that position")
        target = recs[seq].fields["id"]
        conn = self._raw()
        cur = conn.cursor()
        # Reassign the checkpoint to a different actor, content untouched.
        cur.execute("UPDATE block_history SET actor_id = %s WHERE id = %s",
                    (str(meta.get("actor_id", "")) + "-agmi", target))
        conn.commit()
        conn.close()

    # --- payload hooks -------------------------------------------------
    def mutate_payload(self, record: Record) -> Record:
        v = record.fields["value"]
        record.fields["value"] = v.replace(SEED_TOKEN, "agmi-TAMP-", 1)
        return record

    def forge_record(self, template: Record) -> Record:
        import uuid
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["id"] = f"block_hist-{uuid.uuid4()}"
        forged.fields["sequence_number"] = template.fields["sequence_number"] + 1
        return self.mutate_payload(forged)

    # --- reload + verify (the tool's own integrity answer) -------------
    def reload(self) -> None:
        # Letta reads every request from the database; nothing is cached
        # in-process between calls, so a reload is a no-op.
        pass

    def verify(self) -> bool:
        from letta.services.block_manager import BlockManager

        async def _walk():
            bm = BlockManager()
            blk = await bm.get_block_by_id_async(self._block_id, actor=self._actor)
            if blk is None:
                return False
            steps = 0
            while True:
                try:
                    await bm.undo_checkpoint_block(self._block_id, actor=self._actor)
                    steps += 1
                except Exception as exc:  # noqa: BLE001
                    if "earliest checkpoint" in str(exc):
                        break
                    raise
            for _ in range(steps):
                await bm.redo_checkpoint_block(self._block_id, actor=self._actor)
            return True

        self.verify_detail = None
        try:
            ok = asyncio.run(_walk())
            if not ok:
                self.verify_detail = "block not found"
            return ok
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
