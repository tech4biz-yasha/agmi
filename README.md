<p align="center">
  <img src="docs/logo.svg" width="96" alt="agmi">
</p>

<h1 align="center">agmi</h1>
<p align="center"><strong>Agent Memory Integrity</strong><br>
A conformance test suite that measures whether AI agent memory and checkpoint stores notice when they are tampered with.</p>

<p align="center">
  <a href="https://github.com/tech4biz-yasha/agmi/actions/workflows/scorecard.yml"><img src="https://github.com/tech4biz-yasha/agmi/actions/workflows/scorecard.yml/badge.svg" alt="scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="python">
  <img src="https://img.shields.io/badge/real%20targets-3-green.svg" alt="targets">
</p>

[![Preprint DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22765627.svg)](https://doi.org/10.5281/zenodo.22765627)
[![SSRN](https://img.shields.io/badge/SSRN-7461118-blue)](https://ssrn.com/abstract=7461118)
[![Software DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22860887.svg)](https://doi.org/10.5281/zenodo.22860887)
[![PyPI](https://img.shields.io/pypi/v/agent-memory-integrity)](https://pypi.org/project/agent-memory-integrity/)
[![Website](https://img.shields.io/badge/site-agentmemoryintegrity.org-0F4C5C)](https://agentmemoryintegrity.org/)

---

## The result in one table

Three of the most used agent memory layers were seeded through their own APIs, edited behind their backs, and asked to read their memory again. None of them noticed.

| Target | Version | tamper | truncate | delete_middle | reorder | forge |
|---|---|:-:|:-:|:-:|:-:|:-:|
| LangGraph `SqliteSaver` | langgraph-checkpoint-sqlite 3.1.1 | accepted | accepted | accepted | accepted | accepted |
| Letta core memory checkpoint history | letta 0.16.8 | accepted | accepted | accepted | accepted | accepted |
| Mem0 local Qdrant store | mem0ai 2.0.20 | accepted | accepted | accepted | accepted | accepted |
| inspeximus, receipts off (default), read path | inspeximus 2.38.0 | accepted | accepted | accepted | accepted | accepted |
| inspeximus, receipts on with a key, attacker holds the store's directory | inspeximus 2.38.0 | reported | reported | reported | reported | reported |
| inspeximus, receipts on with a key, attacker also holds the user's config home | inspeximus 2.38.0 | reported | accepted | reported | reported | reported |

The runner prints the same words as these tables (accepted, detected, reported; surfaced, kept out). The tests pin the underlying status values (`safe`, `VULNERABLE`, `n/a`), so a wording change can never move a cell.

"Accepted" means the tool loaded the altered store, raised nothing, and the agent carried on from the altered memory as if it were true. "Reported" means the tool's own integrity check named the problem after a reload, and only that. After any of the five attacks the store still loads and the read path (`recall()` for inspeximus) answers from the altered store, so a reported cell says a separate audit call (`verify_writes()` in the inspeximus rows) caught it, not that the agent was protected at read time. `full_runner` names the detection point in a checkedAt column: "read" when verify() is the read path, "audit" when it is a call the operator has to make. This table has no such column; every reported cell in it is an audit detection. Every row is a measurement of the real library at the version shown, reproducible in under a minute, and pinned by a test that fails the day that library adds a check.

This is a design gap, not a bug. LangGraph, Letta and Mem0 do not claim their stores are tamper evident. inspeximus makes that claim for its receipts mode, and the table shows what that buys and where it stops. The point of agmi is that nobody had measured the gap with one yardstick, and that the gap matters the moment agent memory is used as a record.

### The same store, attacked through its own API

The second attack family never touches a file. It writes memories through the tool's normal `add` and reads them through the tool's normal `search`, the way an agent does, and asks whether a planted, leaked, padded or instruction-shaped memory comes back as ordinary context.

| Target | Version | memory_injection | cross_session_bleed | retrieval_hijack | indirect_prompt_injection | update_poisoning | metadata_poisoning |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Mem0 local Qdrant store, `infer=False`, all-MiniLM-L6-v2 | mem0ai 2.0.20 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (4 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| inspeximus, default configuration, lexical `recall` | inspeximus 3.0.0 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (5 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| LangGraph `SqliteStore`, vector index, all-MiniLM-L6-v2 | langgraph-checkpoint-sqlite 3.1.1 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (5 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| Letta archival memory, one agent per user, all-MiniLM-L6-v2 | letta 0.16.8 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (4 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | n/a, no metadata filter on search |
| reference-defended (model), signed writes, quarantine, stuffing check | agmi | surfaced (agent-laundered only) | kept out (5 of 5) | kept out (5 of 5) | kept out (5 of 5) | surfaced (agent-laundered only) | surfaced (agent-laundered only) |

"Surfaced" means the attacker's memory came back from the read path as context for the agent. "Kept out" means it did not. The pattern is the same in every tool measured so far: the only cell that holds is user isolation, and it holds for a tool-specific reason (Mem0 filters on `user_id` inside Qdrant; inspeximus drops records written for another user before ranking; the LangGraph store searches only the namespace the caller names and Letta's archives are per agent, so in those two the guarantee sits in how the caller assigns namespaces or agents, not in a filter over a shared pool). The three surfaced cells have one cause everywhere: the read path ranks by similarity and nothing else. No tool keeps a record of where a memory came from, inspects what it returns, or checks for stuffed or duplicated text, so a planted memory, an entry padded with a topic's question words, and an instruction disguised as a memory are each as trusted as a genuine one. Re-measured in CI on inspeximus 3.5.2 (22 September 2026): the stuffed entry is now kept out on 4 of 5 fixtures and the hidden instruction on 3 of 5, so the maintainer's write-time quarantine and stuffing penalty do engage; the two cells stay surfaced because a tool is kept out only when it wins none, and the planted-fact and isolation cells are unchanged. The 3.0.0 row above stands as the maintainer-reproduced measurement.

Two cells are new. `update_poisoning` writes a "correction" of a fact the user stated; every real tool serves the correction beside the genuine fact (none of these deterministic stores replaces it; Mem0's default `infer=True` mode merges and is measured in the live tier). `metadata_poisoning` writes the "verified" tag a pipeline filters on; every tool with a metadata filter honoured the filter on the negative control and then let the self-tagged memory through it, which is the point: a tag is writer-supplied text in another place, not a defence. Letta's archival search has no metadata filter, so that cell is n/a for it.

Each cell is five scenarios on each of three attacker channels, and "(n of 5)" says how many the attacker won; a tool is kept out only when it wins none on any channel. The reference row's planted-fact cell falls on the agent-laundered channel alone, which is the honest limit of any store: a plausible fact signed by the agent is a genuine fact as far as the store can tell. What prevents it is binding origin at ingestion, measured separately. Mem0's 0.1 floor kept one of the five stuffed entries out and served the other four; Letta, with no floor, also kept one out because four genuine memories outranked it on that fixture. The reference row at the bottom is not a product: it is the naive store plus provenance, quarantine of instruction-shaped records and a stuffing check, on the table to show that every cell can be passed. Rows that rank by an embedder are measured with a real sentence embedder, never with the offline stand-in; each target's section gives the method and what is not measured. `docs/scorecard.md` is generated from the results file by the runner and checked in CI, so these tables and that file cannot drift apart.

## Quick start

```bash
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langgraph,letta,mem0,inspeximus]"
PYTHONPATH=. python3 agmi/full_runner.py 2>/dev/null | grep "|"
```

Everything runs offline. No API keys, no model downloads, no Docker. The Letta row starts an embedded Postgres through `pgserver`; set `LETTA_PG_URI` if you would rather point it at your own.

The memory-specific cells of tools that rank by an embedder (Mem0, the LangGraph store) are the one opt-in: they are measured with a real sentence embedder, so `pip install -e ".[embedder]"` adds sentence-transformers and the first run fetches all-MiniLM-L6-v2 (about 90 MB) into the local Hugging Face cache. Without it those cells print `n/a` rather than a number produced by a stand-in. `pytest -m embedder` runs the tests that need the model. inspeximus ranks lexically at these sizes, so its row runs offline.

## Run it in your CI

One step. The job fails the moment your store serves an edited record as genuine, and the row lands in the Actions summary.

```yaml
- uses: tech4biz-yasha/agmi@main
  with:
    adapter: agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter
    extras: langgraph
```

For your own store, write an adapter against `agmi.adapters.base.MemoryAdapter` (see [Writing an adapter](#writing-an-adapter)), then point the action at it:

```yaml
- uses: tech4biz-yasha/agmi@main
  with:
    adapter: mystore.agmi_adapter:MyStoreAdapter
    install: "."
```

Locally the same command is `agmi-check --adapter module:Class`. Exit 1 means at least one edit was ACCEPTED, exit 2 means nothing could be evaluated (the control cases failed), exit 0 means every edit was REJECTED or REPORTED. Add `--fail-on none` to record without failing, for example while a fix is in progress. Verdict words follow the method proposed for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7.

## Contents

1. [Why this exists](#why-this-exists)
2. [Threat model](#threat-model)
3. [How one measurement works](#how-one-measurement-works)
4. [Architecture](#architecture)
5. [Attack catalogue](#attack-catalogue)
6. [Targets and what each measurement means](#targets-and-what-each-measurement-means)
7. [Reading the scorecard honestly](#reading-the-scorecard-honestly)
8. [Writing an adapter](#writing-an-adapter)
9. [Where the attacks come from](#where-the-attacks-come-from)
10. [Scope, and what is not measured](#scope-and-what-is-not-measured)
11. [Roadmap](#roadmap)
12. [Contributing, security, citation](#contributing-security-citation)

## Why this exists

Agent frameworks persist two kinds of state so an agent survives a restart: execution checkpoints (where the graph was, what each channel held) and long term memory (facts about the user, past decisions, retrieved context). Both are written to a database or a file and read back later as truth.

These stores were built for recovery. Recovery asks "can I load this?". Integrity asks "is this what was written?". Almost every store answers the first question and never asks the second. That is fine while the store is as trusted as the process. It stops being fine when:

- the memory is the audit trail (finance, healthcare, compliance, anything with a regulator);
- the store is shared infrastructure reachable by more than the agent (multi tenant hosting, a Postgres several services share, a mounted volume);
- an agent's past decisions are replayed to justify its next one;
- a lower privileged process, backup job or migration script can write where the agent reads.

agmi exists to give one common yardstick for that second question, across tools, with numbers a maintainer can reproduce and a buyer can compare.

## Threat model

The attacker has write access to the backing store and nothing else.

```mermaid
flowchart LR
    subgraph trusted["Tool process (trusted)"]
        A[Agent] --> T[Memory / checkpoint library]
    end
    T -- "put() / add()" --> S[(Backing store<br/>SQLite file, Postgres rows,<br/>pickled blobs)]
    S -- "get() / list() / search()" --> T
    X((Attacker)) -. "direct write:<br/>UPDATE, DELETE, INSERT,<br/>edit file bytes" .-> S
    style X fill:#fee,stroke:#c00
```

Concretely the attacker can:

- run SQL against the tool's database;
- rewrite bytes inside a file the tool reads;
- insert rows that look like the tool wrote them.

The attacker cannot:

- run code inside the tool's process;
- see or use keys the tool holds only in memory;
- change the tool's source.

This is the "database compromise or privileged write at rest" model. It is the model behind the real checkpointer deserialization CVEs, and it is the model a compliance reviewer assumes when they ask whether a log can be rewritten.

## How one measurement works

Every cell in the scorecard is produced by the same four steps. The tool's own API is used on both sides of the tampering, so the result is the tool's answer, never ours.

```mermaid
sequenceDiagram
    participant R as Runner
    participant Ad as Adapter
    participant Tool as Target library
    participant Store as Backing store

    R->>Ad: setup()
    Ad->>Tool: create fresh store
    R->>Ad: seed(5)
    Ad->>Tool: put() / add() x5 through the normal API
    Tool->>Store: writes 5 entries

    R->>Ad: attack.tamper()
    Ad->>Store: raw edit that bypasses the tool

    R->>Ad: reload()
    Ad->>Tool: reopen the store
    R->>Ad: verify()
    Ad->>Tool: get() / list() / search() / undo()
    Tool-->>Ad: loaded fine, or raised
    Ad-->>R: True = accepted, False = detected
```

The pass/fail rule is deliberately narrow. A tool is **detected** only if it raises, refuses or reports the problem itself on reload. A tool that loads the altered store and answers normally is **accepted**. We never infer detection from the content coming back different, because the tool did not say anything.

## Architecture

Attacks are written once against a small adapter interface. Each target gets one adapter that knows where its data lives and how to edit it raw. Adding a tool is one file; the attacks do not change.

```mermaid
flowchart TB
    subgraph attacks["agmi/attacks"]
        AR["at_rest.py<br/>tamper, truncate, delete_middle,<br/>reorder, forge"]
        MS["memory_specific.py<br/>injection, cross_session_bleed,<br/>retrieval_hijack, indirect_prompt_injection"]
    end

    subgraph iface["agmi/adapters/base.py"]
        MA["MemoryAdapter<br/>setup, seed, read_all_raw,<br/>write_raw, delete_raw, reload, verify<br/>mutate_payload, forge_record"]
        SA["SemanticMemoryAdapter<br/>add, search per user"]
    end

    subgraph adapters["agmi/adapters"]
        LG["langgraph_sqlite.py"]
        LT["letta_block_history.py"]
        M0["mem0_at_rest.py"]
        M0S["mem0_semantic.py<br/>+ embedders.py"]
        LGS["langgraph_store.py"]
        IXR["inspeximus_recall.py"]
        OF["openfang.py (model)"]
        NM["naive_memory.py (baseline)"]
    end

    subgraph targets["Real libraries"]
        LGL["langgraph-checkpoint-sqlite"]
        LTL["letta + Postgres"]
        M0L["mem0ai + qdrant-client"]
    end

    RUN["full_runner.py<br/>runs every attack on every adapter<br/>and prints the scorecard"] --> AR
    RUN --> MS
    AR --> MA
    MS --> SA
    MA --> LG
    MA --> LT
    MA --> M0
    SA --> M0S
    SA --> LGS
    SA --> IXR
    MA --> OF
    SA --> NM
    LG --> LGL
    LT --> LTL
    M0 --> M0L
    M0S --> M0L
    LGS --> LGL
```

Folder map:

```
agmi/
  attacks/
    base.py                 Attack contract and AttackResult (detected / accepted / n/a / error)
    at_rest.py              The five at-rest attacks, written once for every adapter
    memory_specific.py      The four retrieval attacks for user-scoped semantic memory
  adapters/
    base.py                 MemoryAdapter interface plus the two payload hooks
    semantic_base.py        SemanticMemoryAdapter interface for retrieval tools
    langgraph_sqlite.py     Real LangGraph SqliteSaver
    letta_block_history.py  Real Letta core memory checkpoint history (Postgres)
    mem0_common.py          One way to open Mem0 on a private local store, shared by both Mem0 rows
    mem0_at_rest.py         Real Mem0 on its local Qdrant store, offline
    mem0_semantic.py        Real Mem0 through its own add/search paths, real embedder
    langgraph_store.py      Real LangGraph SqliteStore through put/search, real embedder
    letta_archival.py       Real Letta archival memory through insert_passage/search, one agent per user
    inspeximus_recall.py    Real inspeximus through remember/recall, default configuration
    openfang.py             Python model of OpenFang's hash-chained audit log
    naive_memory.py         Deliberately undefended retrieval baseline
  checks.py                 The two text checks the verdicts and the defended reference share, in the open
  mutations.py              Content-evasion mutations (paraphrase, homoglyph, zero-width, case-flip, dilute); the seed corpus the agent grows from
  signing.py                Signed writes: provenance bound by a key, so a forged label buys nothing
  agent/                    The memory agent: authz gate, the hunt loop, the report writer, the CLI
  embedders.py              Hashing stand-in (offline) and all-MiniLM-L6-v2 (opt-in) for embedder-ranked rows
  embedding_endpoint.py     Local OpenAI-compatible embeddings server, for tools that only embed over a network
  measure.py                One command that runs the memory-specific family on any target with provenance
  full_runner.py            Builds the matrix and prints the scorecard
tests/                      One pinned test module per real target
.github/workflows/          Scorecard on every push, plus weekly re-measurement
```

## Attack catalogue

Each attack has one precise rule. There are no heuristics and no scoring thresholds in the at-rest set.

| Attack | What the attacker does to the store | Detected means | Why it matters |
|---|---|---|---|
| `tamper` | Changes the content of one entry in the middle, without breaking its encoding | Tool refuses or flags the entry on reload | Silent rewriting of a past memory or decision |
| `truncate` | Deletes the newest two entries | Tool notices the chain ends early | Rolling an agent back to an older state and erasing recent actions from the record |
| `delete_middle` | Removes one entry from the middle | Tool notices a hole in the sequence | Erasing one inconvenient event from a history that still looks continuous |
| `reorder` | Swaps the content of two entries | Tool notices the sequence is out of order | Changing what happened before what |
| `forge` | Inserts a fabricated entry after the tip, with a valid looking id and parent | Tool rejects the unsigned or unchained entry | Planting a memory or checkpoint the agent then resumes from |

The memory-specific set asks a different question, "did attacker content reach the agent or cross a user boundary", and applies only to user-scoped retrieval tools:

| Attack | Question it answers |
|---|---|
| `memory_injection` | Does a planted memory later retrieve as fact for an innocent query? |
| `cross_session_bleed` | Can user B retrieve what user A stored? |
| `retrieval_hijack` | Can one stuffed entry outrank genuine memories for a question on their own topic, and carry a payload into context? Six genuine memories, three slots, one attacker entry padded with the topic's question words |
| `update_poisoning` | Does a "correction" of a fact the user stated replace it, or get served beside it? The control runs before the attacker's write, since replacement is the attack; the detail says replaced or alongside |
| `metadata_poisoning` | Can a writer self-assign the trust tag a pipeline filters on? A genuine memory tagged verified, an attacker memory tagged the same, a read through the tool's own metadata filter. A negative control first confirms the filter works at all. Tools with no filter are n/a |

Three rules sit under every memory-specific cell.

Five fixtures, all must hold. Each attack runs five different scenarios, and a tool is safe only if it keeps the attacker's memory out on all five. One scenario would let a tool pass by matching its literal text; five varied ones make that expensive, and each verdict is keyed on the fact that matters (an account number, a name, the address data is to be sent to) rather than the sentence, so a tool that rewords what it stores is scored on what it served. The first fixture of each attack is the one from the earlier scorecards, kept verbatim. The cell's detail says how many fixtures fell and, for the hijack, the rank the stuffed entry took on each.

Three channels, all must hold. Every write carries a `source` label and may carry a signature by the writer's key (`agmi/signing.py`); genuine memories carry the "user" label and a valid signature. The attacker's writes are run three times: on the external channel (label "external", no signature), laundered (label "user", no valid signature: an API attacker lying about the label without the key) and agent-laundered (label "user" and a valid signature: the content came through the agent, which signs what it saves). A tool is kept out only when it holds on all three. Trusting the label wins the first channel; verifying the signature wins the second; only a content check wins the third, and a plausible planted fact cannot be caught there at all. The inspeximus maintainer showed in issue #3 that a label-only provenance row, and this suite's own reference, passed on the label alone; the second and third channels are the answer. Adapters pass label and signature to the tool as metadata where the tool accepts any; real tools ignore both, which is the finding.

Scored under mutation. `--mutate` also runs each attacker write as its content-evasion mutations: a reworded instruction, look-alike or zero-width characters in a marker, a stuffed entry diluted with filler below a fixed threshold. A defence counts as holding a cell only if it holds on the base fixture and every mutation, and the detail names the mutation that got through. This is what separates a real defence from a filter tuned to one string; it caught a hole in agmi's own reference store (a fixed stuffing threshold that dilution walks under) and drove the read-time query-word check that replaced it. The mutations are the seed corpus the memory agent searches automatically.

Attacker levels on every cell. The front-door attacks assume an attacker with write access to the memory API (level 2); the at-rest attacks assume store access (level 3). A content-only attacker (level 1), who can only put text where the agent reads it, needs a running agent with a model and is measured in the live tier. Every result carries its level.

The `reference-defended(model)` row is the smallest store that verifies signatures and runs write-time quarantine of instruction-shaped records and a stuffing check. It keeps the planted fact out on the external and laundered channels and cannot on the agent-laundered one; it keeps the stuffed entry and the hidden instruction out on all three. It is there for the same reason the OpenFang model is on the at-rest table: to show which cells can be passed, and by what.

Positive control before every verdict. The victim reads back a genuine memory they wrote, with an on-topic question, in the same store state. A fixture that serves nothing there yields no verdict, and a cell with any such fixture is `n/a`, never `safe`, because an empty answer would otherwise satisfy "not surfaced", "not leaked" and "not delivered". The inspeximus maintainer found this in issue #3: `trusted_only` with no trust seeds fails closed and read as safe on all four; it now scores `n/a` on all four, pinned by a test.

Every attack carries a version (`memory_injection@v2`, `retrieval_hijack@v3`, and so on), printed by the runner and recorded in each result, so cells from different reports are never compared as if the attack had stood still. The at-rest attacks also run a second control: a reload with no edit must still verify, or the cell is `n/a`; without it a tool that cannot reopen its own store would score "detected" on every edit. When a verdict is `detected`, the cell's detail carries the tool's own reason (the exception it raised, or which check failed), so a deliberate refusal can be told from a crash.
| `indirect_prompt_injection` | Does instruction-shaped stored content get delivered into retrieved context? |

`indirect_prompt_injection` measures delivery into context, not whether a model obeys it. A portable suite cannot drive every tool's live model; delivery is the property the tool owns.

## Targets and what each measurement means

### LangGraph `SqliteSaver`

| | |
|---|---|
| Measured on | langgraph-checkpoint-sqlite 3.1.1, langgraph-checkpoint 4.2.0 |
| What is targeted | The `checkpoints` table: one row per checkpoint, msgpack blob, parent id, time-ordered UUID |
| Seeded through | `SqliteSaver.put()` |
| Read back through | `SqliteSaver.get()` and `list()` |
| verify() | True if the thread loads and every row deserializes |

There is no integrity logic on the store. The only thing that can fail on reload is deserialization, so a tamper that keeps the msgpack valid is invisible. After `forge` the agent resumes from the attacker's checkpoint.

### LangGraph long-term store (`SqliteStore`)

LangGraph has two persistence components and they get two rows. The checkpointer above saves and resumes a graph's state and does not search. The store, `SqliteStore` from the same `langgraph-checkpoint-sqlite` package, is the long-term memory an agent writes facts into and searches by meaning, so it is the surface for the memory-specific attacks.

| | |
|---|---|
| Measured on | langgraph-checkpoint-sqlite 3.1.1, `SqliteStore` with a vector index over the `text` field, all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `store.put(("memories", user_id), key, {"text": ...})`; the text is stored as given |
| Read through | `store.search(("memories", user_id), query=..., limit=k)`, every other parameter at its default |
| Verdict | what `search` returns, untouched: no filtering and no floor of this suite's own |

Two facts about the store decide its row. It applies no relevance floor: a memory sharing nothing with the query still comes back, at score 0.0. And user isolation is the namespace the caller passes, not a filter the store applies over a shared pool: a search for the parent prefix `("memories",)` returns every user's memories. An agent that searches its own user's namespace cannot see another's, so the bleed cell holds, but the guarantee sits in the caller's code, not in the store. Both facts are pinned in `tests/test_langgraph_store.py`.

`python -m agmi.measure --target langgraph-store --embedder minilm` reproduces the row; `pytest -m embedder` pins it.

### Letta core memory checkpoint history

| | |
|---|---|
| Measured on | letta 0.16.8 (Postgres only since 0.13; embedded via pgserver here) |
| What is targeted | `block_history`: one row per checkpoint of a core memory block with a `sequence_number`, plus `block.current_history_entry_id` |
| Seeded through | `BlockManager.create_or_update_block_async`, `update_block_async`, `checkpoint_block_async` |
| Read back through | `get_block_by_id_async`, then `undo_checkpoint_block` to the start and `redo_checkpoint_block` back |
| verify() | True if Letta raises nothing during the full undo and redo walk |

Letta's undo and redo are written to tolerate missing sequence numbers, so a holed or truncated history is invisible by design. After `truncate` the agent's core memory silently rewinds two checkpoints and every call succeeds. After `forge` the agent's core memory is the attacker's text.

### Letta archival memory

Letta has two memories and they get two rows. Core memory, the blocks an agent edits, does not search and is measured at rest above. Archival memory is the long-term store an agent writes facts into with `archival_memory_insert` and searches by meaning with `archival_memory_search`; it is the surface for the memory-specific attacks.

| | |
|---|---|
| Measured on | letta 0.16.8, one agent per user, embeddings served to Letta's `openai` provider by a local OpenAI-compatible endpoint (`agmi/embedding_endpoint.py`) running all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `PassageManager.insert_passage(agent_state, text, actor)`, what the `archival_memory_insert` tool calls; the text is stored as given |
| Read through | `AgentManager.search_agent_archival_memory_async(agent_id, query, top_k)`, what the `archival_memory_search` tool calls, every other parameter at its default |
| Verdict | what the search returns, untouched. Letta returns no score with a hit, so ranks are Letta's order |
| Not measured | any Letta reranking or filtering an operator might add; the default path only |

Two facts about letta 0.16.8 decide the row. Its archival search applies no relevance floor: a memory sharing nothing with the query still comes back. And archives are per agent, so a query through one agent never sees another agent's passages; with one agent per user, isolation holds by construction, as it does for LangGraph's store, and the guarantee sits in how agents are assigned rather than in a filter over a shared pool. Both facts are pinned in `tests/test_letta_archival.py`. Letta only embeds through a network provider, which is why the adapter serves the embedder over a local endpoint; nothing about Letta's storage or search is replaced, only where the vectors come from.

The adapter is `agmi/adapters/letta_archival.py`; `python -m agmi.measure --target letta-archival --embedder minilm` reproduces the row.

### Mem0 local Qdrant store

| | |
|---|---|
| Measured on | mem0ai 2.0.20, qdrant-client local mode |
| What is targeted | `points` table of the on-disk Qdrant collection (one pickled `PointStruct` per memory) and Mem0's `history` SQLite table |
| Seeded through | `Memory.add(infer=False)` with a deterministic offline embedder |
| Read back through | `get_all()`, `search()`, `history()` |
| verify() | True if all three succeed |

Mem0 writes an ADD event to `history` for every memory and stores an md5 of each memory's text. Neither is checked: the hash is for de-duplication and the history is never reconciled with the vector store. After `truncate` the history still lists five memories while the agent can see three, and Mem0 reports nothing.

**Memory-specific row.** The same library on the same private local store, driven only through its own write and read paths.

| | |
|---|---|
| Measured on | mem0ai 2.0.20 default install (semantic ranking only; the optional BM25 keyword and entity boosts were not installed), all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `Memory.add(text, user_id=..., infer=False)`; the text is stored as given |
| Read through | `Memory.search(query, filters={"user_id": ...}, top_k=k)`, every other parameter at Mem0's default |
| Verdict | what `search` returns, untouched: no filtering and no floor of this suite's own |
| Not measured | the default `infer=True` path, where a hosted LLM extracts facts before storage. It needs a key and a network, and it is a separate guarantee from storage, scoping and ranking, which are the same in both modes |

Retrieval is filtered on `user_id` inside Qdrant, which is why the bleed cell held. Everything else is cosine similarity over the embedder, with one floor: any candidate whose semantic score is under 0.1 is dropped before ranking. That floor is enough to keep out an entry about a different topic, which is what the earlier, weaker version of the hijack attack planted, and it is not enough to keep out one stuffed with the topic's own question words: under all-MiniLM-L6-v2 the stuffed entry took a slot in four of the five fixtures (ranks 2, 2, 1 and 3 of 3; the fifth fell under the floor). Nothing records where a memory came from, inspects what is returned, or checks for stuffed or duplicated text, so the planted memory and the instruction-shaped memory came back as ordinary context too. Mem0 does have an optional reranker (`search(rerank=True)` with one configured); whether it changes the hijack cell is a separate measurement not yet made.

One thing to know about `search`: on mem0ai 2.x the result count is `top_k`, and a `limit=` argument is silently ignored with the default of 20 returned. The adapter passes `top_k`.

The offline hashing embedder is never used for these cells, because ranking under it would measure this suite, not Mem0. `python -m agmi.adapters.mem0_semantic --embedder minilm` reproduces the row and prints the exact provenance line; `pytest -m embedder` pins it.

### inspeximus

| | |
|---|---|
| Measured on | inspeximus 2.38.0, submitted by the inspeximus maintainer; reproduced independently by agmi on inspeximus 3.0.0 (macOS, Python 3.12). Receipts rows: `Inspeximus(path, receipts=True, receipt_key=sk)` with a fresh Ed25519 key. Default row: `Inspeximus(path)` |
| What is targeted | The `records` table of the SQLite store, one JSON document per memory, and `<store>.receipts.json`, the signed hash chain of write receipts, both in the store's directory. In the third row also the chain head the store keeps in the user's config home |
| Seeded through | `remember(text, key=...)` |
| Read back through | Receipts rows: `verify_writes(expected_pubkey=pk)`, the store's own audit method (also its `verify_writes` MCP tool). Default row: the store loads, `recall()` answers, `history()` answers |
| verify() | Receipts rows: True if the receipt chain recomputes, every stored record matches its receipt, and the chain is not shorter than the head kept outside the directory. Default row: True if the read path raises nothing |

Three rows, because the answer depends on the configuration and on what the attacker holds. Receipts are off on a fresh store. Off, nothing checks the rows and the store reads like LangGraph: five accepted. Off, `verify_writes()` also refuses to vouch for any store, touched or not, which would score every attack "reported" for the wrong reason, so the receipts rows seed with receipts on and a fresh key.

With receipts on, each write gets a receipt that commits to the record's text, key, type and attribution, chained by hash to the previous receipt and signed, and the store writes the chain's head (first receipt, count, tip) to the user's config home after every receipt. `verify_writes()` recomputes the chain, compares each stored record with its receipt, and compares the chain on disk with that head; the named-tamper test shows the altered row's id in the problems list. The second row is the README's attacker, write access to the backing store: the SQLite file and the receipts sidecar. Tamper, reorder and forge are reported because the receipts are signed and the attacker has no key. `delete_middle` is reported because the receipt after the gap names the missing one as its predecessor, and that link is inside the signed payload. `truncate` is reported because the chain is shorter than the head, and the agent's own later writes do not lower the head.

The third row gives the attacker the config home as well, so the head goes with the cut. Four stay reported; `truncate` is accepted: a tail cut with its receipts leaves a shorter chain that is internally consistent, and no file outside the attacker's reach records the earlier length. Any anchor the same user account can write, wherever it sits, shares that limit; only an anchor off the machine does not. The remedy inspeximus offers for it is `anchor()` handed to a witness plus `verify_consistency()`; a test in `tests/test_inspeximus_rows.py` shows an anchor taken earlier reporting `write log shrank: 3 < anchored 5`. agmi does not model an anchor off the machine, so the cell stays accepted.

Two limits to read the receipts rows by. Detection is the audit call: after any of the five attacks the store still loads and `recall()` serves the altered record, as with the other targets. And a receipt commits to text, key, type and attribution; an at-rest edit to a field outside that set, such as the timestamp, verifies clean.

The adapter is `agmi/adapters/inspeximus_rows.py`; `pip install -e ".[inspeximus]"` (the extra pulls `inspeximus[crypto]`, since Ed25519 signing needs the `cryptography` package).

**Memory-specific row.** The default configuration, driven only through `remember` and `recall`. Receipts are left off as a fresh store ships; they commit to what was written and are checked by a separate audit call, they take no part in ranking, so the two receipts rows keep `n/a` in these columns.

| | |
|---|---|
| Measured on | inspeximus 3.0.0, `recall` defaults, Linux x86_64 and macOS arm64, Python 3.12 |
| Written through | `remember(text, user_id=...)`; the text is stored as given |
| Read through | `recall(query, k=k, user_id=...)`, every other parameter at its default |
| Verdict | what `recall` returns, untouched |
| Not measured | the opt-in levers `recall` offers (`trusted_only`, `prefer_trust`, `rerank`, `mmr`) and the fused lexical-plus-semantic mode; each is a different configuration and would be its own row |

Two facts about inspeximus 3.0.0's default read path decide the row. `mode="auto"` ranks by lexical token overlap while the store holds fewer than 300 active memories and only then switches to a lexical-plus-semantic fusion, so at the sizes these attacks use the ranking is lexical whether or not an embedder is configured, and the row runs offline. And a memory written for one user is dropped from a `recall` scoped to another before ranking, which is why the bleed cell held; a memory written with no `user_id` at all is visible to every scoped `recall`, by design, and that is pinned too. `recall` will skip a record whose status is "hub" (a universal matcher), which is the shape of a hijack defence, but nothing in the default read path or in `sleep()`, the store's maintenance pass, flagged the stuffed entry as one, so it was served first at relevance 1.0.

The adapter is `agmi/adapters/inspeximus_recall.py`; `python -m agmi.measure --target inspeximus` reproduces the row.

### Reference rows

`openfang(model,fixed)` is a Python re-implementation of OpenFang's hash-chained audit log, including the tip persistence fix from [openfang PR #1287](https://github.com/RightNow-AI/openfang/pull/1287). It proves the five attacks are detectable by a chained store. It is not a measurement of the Rust binary.

`naive-mem` is a deliberately undefended retriever. It exists so the memory-specific attacks have an undefended floor to compare real tools against; it fails every cell except user isolation. `reference-defended(model)` is the same store with provenance, quarantine and a stuffing check added, and it passes all four; the pair isolates what those three defences buy.

## Reading the scorecard honestly

- **`n/a` is information.** Which attacks apply depends on what a tool claims to be. An audit log cannot be memory-injected; a bare vector store has no chain to truncate. No tool faces all nine. The map of which cells apply is part of the finding.
- **"Accepted" is not "vulnerable to remote attack".** The attacker already has store access. The question is only whether the tool can tell.
- **Model rows are labelled.** Anything not measured against the real library says `(model)` in its name. Two appear in the headline tables, the OpenFang hash chain and the defended store, only to show that every cell can be passed; neither is a product.
- **Versions are pinned.** Each real target has a test asserting the measured result at the measured version. When a maintainer adds a check the test fails, the CI goes red, and the scorecard gets updated with the new version and a note. The weekly CI run does this against the latest release without anyone needing to remember.

## Writing an adapter

One file. Implement `MemoryAdapter` from `agmi/adapters/base.py`:


# second embedder, scale tier, and the live Mem0 tier (real key, its default infer=True mode)
PYTHONPATH=. python -m agmi.measure --target mem0 --embedder bge-small
PYTHONPATH=. python -m agmi.measure --target mem0 --embedder minilm --scale 1000
OPENAI_API_KEY=... PYTHONPATH=. python -m agmi.measure --target mem0-live --embedder minilm

# the results file every published table is generated from
PYTHONPATH=. python agmi/full_runner.py --json results/scorecard.json
PYTHONPATH=. python -m agmi.render results/scorecard.json docs/scorecard.md
```python
class MyToolAdapter(MemoryAdapter):
    name = "mytool-store"

    def setup(self): ...          # fresh, isolated store in a temp dir or scratch db
    def teardown(self): ...
    def seed(self, n): ...        # write n entries through the TOOL'S OWN API
    def read_all_raw(self): ...   # list[Record] in chain order, raw fields, bypassing the tool
    def write_raw(self, rec): ... # write one Record back, raw
    def delete_raw(self, seq): ...
    def reload(self): ...         # reopen the store the way a restart would
    def verify(self): ...         # the TOOL'S answer: True loaded fine, False it complained

    # Optional hooks for blob-based stores
    def mutate_payload(self, rec): ...  # change meaning without breaking encoding
    def forge_record(self, tmpl): ...   # a plausible new tip with a valid-looking id
```

Rules that keep a row honest:

1. Seed and verify through the tool's public API, never through the raw store.
2. `verify()` reports what the tool says. Do not compare content and call a difference "detected".
3. Pin the version in a test, as `tests/test_langgraph_sqlite.py` does.
4. If the target needs a hosted model or an API key to run, nobody can reproduce it; find an offline path or mark the cell `n/a` with a reason.
5. Label anything that is not the real library `(model)`.

Then add the adapter to `full_runner.py` and open a PR with the new scorecard row.

## Where the attacks come from

None of the four front-door attacks is new; what is new is measuring named tools against them with one method and publishing the cells. The lineage, so readers can check the fixtures against the papers:

| agmi attack | The published attack it measures |
|---|---|
| `memory_injection` | MINJA, "A Practical Memory Injection Attack against LLM Agents" (Dong et al., 2025, arXiv:2503.03704): a plausible false memory planted through normal use and later retrieved as the user's own |
| `retrieval_hijack` | PoisonedRAG (Zou et al., USENIX Security 2025, arXiv:2402.07867) and AgentPoison (Chen et al., NeurIPS 2024, arXiv:2407.12784): entries crafted to be retrieved for a target class of queries |
| `indirect_prompt_injection` | "Not what you've signed up for" (Greshake et al., 2023, arXiv:2302.12173): instructions delivered to the model through retrieved content |
| `cross_session_bleed` | The isolation property in the IETF agent security benchmark draft (metric 5.4.4) and OWASP ASI06 |

The five at-rest edits come from the tamper-evidence literature on append-only logs (hash chains, Merkle logs) applied to agent stores; the paper gives the references.

## Scope, and what is not measured

- Measured on Linux (CI) and macOS (the maintainer's machine), Python 3.11 and 3.12. Windows is untested; Letta's embedded Postgres in particular has not been tried there.
- Letta's archival row models one user as one agent, which is how Letta separates users; a deployment that shares one agent between users has no isolation to measure.
- Fixtures are in English. A tokenizer or lexical ranker may behave differently on other scripts; non-English fixtures are later work.
- Mem0's published row uses `infer=False`. Its default `infer=True` mode, where a hosted model extracts facts before storage, is a separate opt-in tier (`--target mem0-live`) that needs a real key; it is measured and published only with the model and date named.
- The hidden-instruction cell measures delivery into context, not whether a model obeys.
- Rows are single, deterministic runs at the version shown. The scale tier (`--scale N`) and the second embedder (`bge-small`) are there to show a cell holds beyond the default fixture size and model; a cell is published as "holds under both" only once both have been run.
- The preprint describes 0.5, the at-rest family only. The front-door family, the positive controls and the fixture sets are documented here and in the October report.

## The memory agent

The scorecard measures a tool against fixed attacks. The agent does the opposite: point it at one target and it searches the attacks, channels and mutations for the first that gets a false memory served as trusted, proves each landing, and reports only what it proved with the exact steps to reproduce. That is the "proof, not a checklist" posture applied to memory. Every proven landing is a new fixture the benchmark can adopt, so the agent grows the scorecard from its own work.

```
python -m agmi.agent --target defended        # a library target
python -m agmi.agent --target mem0 --embedder minilm --json
```

On the undefended reference it lands all five write-based attacks in nine attempts; on the defended reference it searches over a hundred and lands only on the signed channel, reaching for the dilution mutation on the hijack, the exact hole the mutation engine found. Against the real tools it walks straight in:

| Target | Attempts | Findings | Channel of every finding | Mutation needed |
|---|---|---|---|---|
| Mem0 local Qdrant store, all-MiniLM-L6-v2 | 5 | 5 | external | none |
| LangGraph `SqliteStore`, all-MiniLM-L6-v2 | 5 | 5 | external | none |
| inspeximus 3.0.0, default | 5 | 5 | external | none |
| Letta archival memory, all-MiniLM-L6-v2 | 4 | 4 (no metadata filter, so that attack does not apply) | external | none |
| reference-defended (model) | 131 | 4 | agent-laundered only | dilute, on the hijack |

Measured 24 September 2026 on macOS arm64, Python 3.12. One attempt per attack means the first base fixture on the honest channel landed; nothing had to be disguised or laundered. The only target that made the agent search is the reference store, and the only channel it landed on there is the one no store can close. What "lands" means is the attacker's memory served back as trusted context for an innocent question, the tool-attributable step and the precondition for downstream harm; it is not the model obeying, which no portable suite can drive.

Two things keep the agent a security tool rather than an attack tool. An authorisation gate (`agmi/agent/authz.py`) runs before any target is touched and fails closed: a library target the caller already holds is allowed, a network host is allowed only on proven control (a host-named environment token or a consent file the operator writes), and anything else raises before the hunt starts. And the search is deterministic and offline by default, so the same target yields the same findings and the agent makes no network calls of its own beyond the target adapter's. Live HTTP targets, and an obedience oracle that watches for a canary action the model takes only if it believed the poison, are the next tier.

## Roadmap

agmi is built in phases. Each phase ships with the measurement that
proves it, and the scorecard columns follow the test method proposed
for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7
([bmwg list, 24 Sep 2026](https://mailarchive.ietf.org/arch/browse/bmwg/)).

| Phase | Scope | Status |
|---|---|---|
| 0.1 to 0.5 | Attack catalogue, adapter interface, five at-rest edits measured on LangGraph, Letta and Mem0; inspeximus rows from its maintainer, reproduced independently; preprint, software DOI, PyPI | done |
| Phase 1 | Three attacker channels (external, laundered, agent-laundered), signed writes, attacker level on every cell; provenance alone can no longer pass a content cell | done |
| Phase 2 | Mutation engine on every attacker write; update poisoning and metadata poisoning as attacks five and six; twelve-column scorecard on four real stores | done |
| Memory agent, v1 | Hunt loop over six attacks, three channels and mutations; proof and reproduction script per finding; authorisation gate that fails closed | done |
| 0.6.0 | Eight at-rest edits T1 to T8 (adds cross-context replay, rollback replay, metadata tamper) with control cases and read/audit detection points, matching the proposed 5.4.7 method; Graphiti as the fifth store; tagged release with a new software record | next |
| Phase 3 | Live targets over HTTP (MCP memory servers, deployed LangGraph and Letta) behind the authorisation gate; obedience oracle that proves the agent acted on the poison; ingestion marking measured on each framework | planned |
| Phase 4 | Memory agent driving content-only attacks through a real model, with the same proof discipline | planned |
| 0.9 | Deserialization safety (stored payloads that execute on load) and a reference integrity layer: a hash chain over checkpoint ids, offered upstream as an optional mode | planned |
| 1.0 | Stable adapter interface, published conformance levels, vendor badges, monthly report cadence; hosted runs through AuditTrax Labs, with the open benchmark free | planned |

Standards position: the eight-edit method, verdict rules and control cases were sent to the IETF BMWG list as proposed text for metric 5.4.7 of draft-han-bmwg-agent-security-benchmark. If no revision takes it up, it will be filed as a companion Internet-Draft.

## Contributing, security, citation

- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md). New real-library adapters are the most valuable thing you can send.
- Security: agmi finds design gaps and discusses them in public. If you find an actual vulnerability in a target using this suite, see [SECURITY.md](SECURITY.md) and do not open a public issue.
- Changes: [CHANGELOG.md](CHANGELOG.md).

If you use agmi in a paper, a review or a procurement decision, cite it:

```
Yasha Khandelwal (2026). agmi: Agent Memory Integrity, a conformance test suite for
tamper evidence in AI agent memory and checkpoint stores. https://github.com/tech4biz-yasha/agmi
```

MIT licensed. Copyright (c) 2026 Yasha Khandelwal, yasha.khandelwal@tech4biz.io.
