# Changelog

## Unreleased
- inspeximus adapter (inspeximus 2.38.0, SQLite store with an opt-in signed
  receipt chain and a chain head kept in the user's config home), three rows:
  receipts off reads like LangGraph, five accepted; receipts on with the
  attacker holding the store's directory, five reported; receipts on with the
  attacker also holding the config home, four reported and a tail truncation
  accepted. Detection is the tool's audit call, not the read path.

## 0.5.0 (2026-09-14)
- License (MIT), authorship, file headers, contributing and security
  policy, CI workflow.
- README rewritten: headline table, threat model, measurement sequence,
  architecture diagrams, attack catalogue, per-target method, adapter guide.

## 0.4.0 (2026-09-14)
- Mem0 adapter (mem0ai 2.0.20, local Qdrant store, fully offline).
- All five at-rest attacks accepted silently on Mem0; history table and
  vector store left disagreeing after truncate.

## 0.3.0 (2026-09-14)
- Letta adapter (letta 0.16.8, core memory block checkpoint history).
- Embedded Postgres via pgserver so the Letta row runs without Docker.
- Fixed the truncate attack, which removed one entry instead of two on
  stores that address rows by position.

## 0.2.0 (2026-09-14)
- First real target: LangGraph SqliteSaver (langgraph-checkpoint-sqlite
  3.1.1). All five at-rest attacks accepted silently.
- Adapters now own payload mutation so blob-based stores can be attacked
  without corrupting their encoding.

## 0.1.0
- Attack catalogue, adapter interface, Python model of the OpenFang audit
  chain, naive memory reference target.
