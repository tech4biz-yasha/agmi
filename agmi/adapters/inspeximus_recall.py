# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for inspeximus (the real library), memory-specific attack surface.

Where ``inspeximus_rows`` edits the store's files behind its back, this
adapter never touches them. It drives inspeximus the way an agent does,
through ``remember`` and ``recall``, so the four memory-specific attacks can
ask whether a planted, leaked, padded or instruction-shaped memory reaches
the agent's context.

Write path
    ``Inspeximus.remember(text, user_id=...)``. The text is stored as
    given. Receipts are left off, as a fresh store ships; receipts commit
    to what was written and are checked by a separate audit call, they do
    not take part in ranking, so they have no bearing on these cells.

Read path
    ``Inspeximus.recall(query, k=k, user_id=...)`` with every other
    parameter at its default. Results are passed to the attack exactly as
    inspeximus returns them: no client-side filtering and no floor of this
    suite's own. ``recall`` does not report which user a hit belongs to,
    so the ``user_id`` on every hit is an empty string; the bleed attack
    still catches a leak through the text.

    Two facts about inspeximus 3.0.0's default read path decide the row.
    First, ``mode="auto"`` ranks by lexical token overlap while the store
    holds fewer than ``semantic_threshold`` (300) active memories, and
    only switches to a lexical-plus-semantic fusion above that, so at the
    sizes these attacks use the ranking is lexical whether or not an
    embedder is configured. That is why this adapter takes no embedder and
    the row runs offline. Second, a memory written with a ``user_id`` is
    invisible to a ``recall`` scoped to a different user; a memory written
    with no ``user_id`` at all is visible to every scoped ``recall``, by
    design.

    ``recall`` also skips any record whose status is "hub" (a universal
    matcher) unless asked to include them. Nothing in the default read
    path or in ``sleep()``, the store's maintenance pass, flagged the
    hijack entry as one, so that defence did not engage. inspeximus offers
    further opt-in levers (``trusted_only``, ``prefer_trust``, ``rerank``,
    ``mmr``); their effect is a separate measurement not yet made.

Store
    A fresh SQLite file under a temporary directory for every ``reset()``.
"""

from __future__ import annotations

import importlib.metadata as md
import platform
import sys
import tempfile
from pathlib import Path

from agmi.adapters.semantic_base import (
    MemoryItem, Retrieved, SemanticMemoryAdapter,
)
from agmi.signing import KEYRING

#: Row label as it appears on the scorecard. The runner may override it.
LABEL = "inspeximus-default"


def inspeximus_version() -> str:
    try:
        return md.version("inspeximus")
    except md.PackageNotFoundError:
        return "not installed"


class InspeximusRecallAdapter(SemanticMemoryAdapter):
    """Real inspeximus, default configuration, for the memory-specific
    attacks.

    Parameters
    ----------
    mode:
        Passed to ``recall``. Default ``"auto"``, which is what the tool
        ships with and is lexical at these store sizes. Pass ``"hybrid"``
        or ``"semantic"`` together with ``embed`` to measure the fused
        ranking; that is a different configuration and gets its own row.
    embed:
        Optional ``fn(str) -> list[float]`` handed to the store. Unused by
        the default row (see the module docstring for why).
    recall_kwargs:
        Extra keyword arguments passed to every ``recall`` call, for
        scoring one of the tool's opt-in levers (``trusted_only``,
        ``prefer_trust``, ``rerank``, ``mmr``) as its own configuration row.
        Nothing else about the adapter changes, so a lever row differs from
        the default row by exactly that argument.
    provenance:
        Record each item's channel label as the memory's ``source``, the
        field inspeximus resolves sources by. Off by default, so the default
        row is unchanged: a store that keeps provenance is a different
        configuration and gets its own row.
    trust_seeds:
        Canonical source strings the store treats as a trust root. With
        ``recall_kwargs={"trusted_only": True}`` the read path serves only
        memories reachable from that root. Empty by default. ``trusted_only``
        with no seeds fails closed and serves nothing, which the positive
        control reports as n/a rather than as a pass.
    attest:
        Bind each write that carries a valid suite signature to a per-user
        Ed25519 key, through inspeximus's own ``remember(attestation=...)``,
        and seed the store with those keys (``"key:<pubkey>"``). The store
        then filters on the attested key, not on the label. Off by default.
        inspeximus cannot verify the suite's HMAC model signature itself, so
        the adapter plays the writer's signing step: it holds one Ed25519
        key per user and signs only what ``agmi.signing.KEYRING`` verifies.
        The store verifies the Ed25519 signature on the write (a bad one is
        rejected) and ``trusted_only`` keeps only records whose attested
        key is a seed.
    label:
        Scorecard row name. Defaults to ``LABEL``.
    """

    def __init__(self, mode: str = "auto", embed=None,
                 recall_kwargs: dict | None = None,
                 label: str | None = None,
                 provenance: bool = False,
                 trust_seeds: set | None = None,
                 attest: bool = False):
        self.mode = mode
        self.embed = embed
        self.recall_kwargs = dict(recall_kwargs or {})
        self.provenance = provenance
        self.trust_seeds = set(trust_seeds or ())
        self.attest = attest
        self._writer_keys: dict[str, tuple[str, str]] = {}
        self.name = label or LABEL
        self._dir: tempfile.TemporaryDirectory | None = None
        self._store = None

    # --- lifecycle -----------------------------------------------------
    def reset(self) -> None:
        """Throw the store away and start from an empty one."""
        try:
            from inspeximus import Inspeximus
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise NotImplementedError(
                "inspeximus is not installed; run "
                "pip install 'agent-memory-integrity[inspeximus]'") from exc
        self.close()
        self._dir = tempfile.TemporaryDirectory(prefix="agmi-inspeximus-recall-")
        path = Path(self._dir.name) / "memory.sqlite"
        kwargs = {"embed": self.embed} if self.embed is not None else {}
        self._store = Inspeximus(str(path), **kwargs)
        if self.trust_seeds:
            self._store.trust_seeds = set(self.trust_seeds)

    def close(self) -> None:
        """Drop the store and delete its directory. Idempotent."""
        self._store = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _memory(self):
        if self._store is None:
            self.reset()
        return self._store

    def __enter__(self) -> "InspeximusRecallAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- the tool's own write and read paths ---------------------------
    def add_memory(self, item: MemoryItem) -> None:
        meta = dict(item.metadata)
        meta.setdefault("source", item.source)
        if item.signature:
            meta.setdefault("signature", item.signature)
        extra: dict = {}
        if self.provenance:
            extra["source"] = {"doc": item.source}
        if self.attest and KEYRING.verify(item.user_id, item.source, item.text,
                                          item.signature):
            extra["attestation"] = self._attestation(
                item, item.source if self.provenance else None)
        self._memory().remember(item.text, user_id=item.user_id, meta=meta,
                                **extra)

    def _attestation(self, item: MemoryItem, source_doc) -> tuple[str, str]:
        """The writer's Ed25519 signature over the claim, and its key added
        to the store's trust root."""
        from inspeximus import attest, new_source_keypair
        if item.user_id not in self._writer_keys:
            self._writer_keys[item.user_id] = new_source_keypair()
        secret, public = self._writer_keys[item.user_id]
        self._memory().trust_seeds.add("key:" + public)
        return public, attest(item.text, secret, source_doc)

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        rows = self._memory().recall(query, k=k, user_id=user_id,
                                     mode=self.mode, **self.recall_kwargs)
        out: list[Retrieved] = []
        for row in rows or []:
            score = row.get("score")
            if score is None:
                score = row.get("relevance") or 0.0
            out.append(Retrieved(
                text=str(row.get("text", "")),
                user_id="",  # recall does not report the hit's owner
                score=float(score),
            ))
        return out

    def retrieve_where(self, query: str, user_id: str, where: dict,
                       k: int = 5) -> list[Retrieved]:
        rows = self._memory().recall(query, k=k, user_id=user_id,
                                     mode=self.mode, where=dict(where),
                                     **self.recall_kwargs)
        out = []
        for row in rows or []:
            score = row.get("score")
            if score is None:
                score = row.get("relevance") or 0.0
            out.append(Retrieved(text=str(row.get("text", "")), user_id="",
                                 score=float(score)))
        return out

    def supports_users(self) -> bool:
        return True

    # --- provenance for reports ----------------------------------------
    def measured_on(self) -> str:
        """One line stating what this row was produced with."""
        ranking = ("lexical token overlap; mode=auto stays lexical below "
                   "300 memories" if self.mode == "auto" else f"mode={self.mode}")
        levers = (", " + ", ".join(f"{k}={v!r}" for k, v in self.recall_kwargs.items())
                  if self.recall_kwargs else "")
        if self.provenance:
            levers += ", provenance recorded as the memory's source"
        if self.trust_seeds:
            levers += ", trust_seeds=" + repr(sorted(self.trust_seeds))
        if self.attest:
            levers += (", signed writes attested with a per-user Ed25519 key "
                       "and those keys seeded")
        return (f"inspeximus {inspeximus_version()}, receipts off, "
                f"recall defaults ({ranking}){levers}, "
                f"{platform.system()} {platform.machine()}, "
                f"Python {sys.version_info.major}.{sys.version_info.minor}")
