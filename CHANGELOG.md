# Changelog

## Unreleased
- Two defended inspeximus rows on the scorecard, from its maintainer's
  PR #4: the tool's own provenance plus a trust root keyed on the label,
  and the same filter keyed on a per-user Ed25519 key the writer attests
  with. Label holds on external only; the key also holds on laundered;
  agent-laundered lands on both. Both controls from issue #3 are tests.
- `agmi-check` and a GitHub Action (`action.yml`): one command, one CI
  step, runs the at-rest edits against a single adapter and fails the job
  on any ACCEPTED edit. Labels are T1 to T5 and verdicts are REJECTED,
  REPORTED (audit-time detection) or ACCEPTED, the words proposed for
  IETF draft-han-bmwg-agent-security-benchmark 5.4.7. Exit 2 when no edit
  could be evaluated, so a store that cannot reopen never scores a pass.
  Front-door adapters are refused with a clear message. Writes a step
  summary and one annotation per finding under GitHub Actions.
- The memory agent (`agmi/agent/`, `python -m agmi.agent`): searches the
  six attacks, three channels and content-evasion mutations for the first
  that gets a false memory served as trusted, proves each landing, and
  reports only what it proved with reproduction steps. Lands all five
  write-based attacks on the undefended reference in nine attempts; on the
  defended reference it searches 131 and lands only on the signed channel,
  reaching for the dilution mutation on the hijack. An authorisation gate
  (`agmi/agent/authz.py`) runs before any target is touched and fails
  closed: library targets allowed, network hosts only on proven control
  (host-named env token or a consent file), else it raises. The search is
  deterministic and offline; live HTTP targets and an obedience oracle are
  the next tier.
- Two new front-door attacks. `update_poisoning`: a "correction" of a fact
  the user stated; the control runs before the attacker's write since
  replacement is the attack; detail says replaced or alongside. Every real
  tool serves the correction alongside. `metadata_poisoning`: the attacker
  self-assigns the trust tag a pipeline filters on; a negative control
  first confirms the tool's own metadata filter works; every tool with a
  filter (Mem0, LangGraph store, inspeximus) then let the self-tagged
  memory through; Letta has no filter and is n/a. `retrieve_where` added
  to the adapter interface with the default meaning "no filter".
- Mutation engine (`agmi/mutations.py`, `--mutate`): every attacker write
  is also run as its content-evasion mutations (paraphrase, homoglyph,
  zero-width, case-flip, dilute), and a defence holds a cell only if it
  holds on the base fixture and every mutation. It immediately found a hole
  in agmi's own reference store: a fixed stuffing threshold that dilution
  walks under. Replaced it with a read-time query-word-count check (an
  entry carrying more of the query's words than its peers is demoted),
  which holds every base fixture and four of five under dilution; the fifth
  is recorded as the measured limit of a content-only defence, closed only
  by ingestion provenance or a learned detector. Every mutation preserves
  the verdict key, pinned by a test.
- Three attacker channels on every front-door attack (external; laundered:
  forged "user" label, no key; agent-laundered: forged label with a valid
  signature), a tool kept out only when it holds on all three. Found by
  DanceNitra in issue #3: a label-only provenance row and this suite's own
  reference passed on the label alone, with the content checks never
  exercised. Signed writes (`agmi/signing.py`) bind provenance to a key
  so a forged label buys nothing; the reference store verifies them. The
  honest limit is recorded: a plausible planted fact signed by the agent
  cannot be caught by any store. A regression test switches the content
  checks off and requires the agent-laundered channel to fail. Attack
  versions bump: memory_injection@v3, retrieval_hijack@v4,
  indirect_prompt_injection@v3. Attacker level (write-access,
  store-access) is carried on every result and in the results file.
- Letta archival memory (`letta_archival.py`): the fourth real tool with
  all four front-door cells. Real Letta through `insert_passage` and
  `search_agent_archival_memory_async`, one agent per user, embeddings
  served to Letta's `openai` provider by a new local OpenAI-compatible
  endpoint (`agmi/embedding_endpoint.py`), since Letta only embeds over a
  network. Facts pinned: no relevance floor; archives are per agent.
  `--target letta-archival` in `agmi.measure`; CI's embedder job now
  installs Letta and measures the row. Measured with all-MiniLM-L6-v2:
  planted fact 5 of 5, isolation held 5 of 5, hijack 4 of 5, hidden
  instruction 5 of 5. Letta's own INFO logging and deprecation notices
  are silenced in agmi's runs.
- CI, installing the newest inspeximus (3.5.2), showed the hijack cell
  move: the stuffed entry is kept out on 4 of 5 fixtures and the hidden
  instruction on 3 of 5. Statuses unchanged (a tool is kept out only when
  it wins none); fixture-level detail is now pinned only on the version it
  was measured on, statuses on every version. Recorded in the README.
- Measurement robustness and process, from the same audit:
  - A second real embedder (`bge-small`, BAAI/bge-small-en-v1.5) for every
    rank-dependent cell, and a scale tier (`--scale N`) that seeds N
    unrelated memories before every fixture; both opt-in, both reported in
    the provenance line.
  - A live tier for Mem0's default `infer=True` mode (`--target
    mem0-live`), which runs only with a real key and is never measured
    with a stand-in.
  - The runner writes the run as JSON (`--json`); `agmi.render` generates
    `docs/scorecard.md` from it and CI fails if the two drift, or if CI's
    own run disagrees with the committed file on any cell both measured.
    No published table is typed by hand any more.
  - CI runs the embedder-tier rows on a machine nobody owns, runs ruff
    (correctness rules only), and a conformance suite every semantic
    adapter must pass (write, read back, honour k, reset, scope, report
    provenance, close).
  - The runner prints the words the tables use (accepted, detected,
    reported; surfaced, kept out); tests still pin the status values.
  - A "Dispute a cell" issue template, a configuration-row rule in
    CONTRIBUTING.md, a related-work table naming the papers each attack
    measures, and a scope section stating what is not measured.
- Verdict integrity, five changes, all found by asking how a tool could
  earn a pass without doing the right thing:
  1. Every memory-specific attack now runs five fixtures and a tool is
     safe only if all five hold; verdicts are keyed on the fact that
     matters, not the sentence, so literal-string blocking and rewording
     both stop working as routes to a pass. Attack versions bump:
     memory_injection@v2, cross_session_bleed@v2, retrieval_hijack@v3,
     indirect_prompt_injection@v2. The naive baseline's prompt-injection
     cell goes from safe to VULNERABLE (4 of 5 fixtures delivered); it
     was safe before only because one query happened not to overlap.
  2. At-rest attacks run a second control: a reload with no edit must
     still verify, or the cell is n/a. A tool that cannot reopen its own
     store no longer reads as tamper-evident.
  3. When verify() says no, the tool's own reason is recorded in the cell
     detail, so a deliberate refusal can be told from a crash.
  4. Every attack carries a version, printed by the runner and stored in
     results and reports, so cells across reports are never compared as if
     the attack had stood still.
  5. Provenance: every write carries a `source` ("user" or "external"),
     passed to tools as metadata. `reference-defended(model)`, the naive
     store plus provenance, write-time quarantine and a stuffing check,
     passes all four cells and is on the scorecard to show each is
     winnable. The two checks live in `agmi/checks.py`, shared with the
     verdicts, in the open.
- Base classes gain `close()` and `measured_on()` with defaults, so an
  adapter never has to guess what the runner will call.
- Positive control on every memory-specific attack: the victim must read
  back a genuine memory with an on-topic question in the same store state,
  or the cell is n/a rather than safe. Closes the route where a read path
  that returns nothing passes every cell. Found by DanceNitra (issue #3):
  inspeximus `trusted_only` with no trust seeds fails closed and read as
  safe on all four; it now scores n/a on all four, pinned by a test. The
  hidden-instruction fixture gained a genuine memory beside the payload so
  the control has something to read; verdict rule unchanged.
- `InspeximusRecallAdapter(recall_kwargs=...)` scores one of the tool's
  opt-in recall levers as its own configuration row.
- Two more targets for the memory-specific family. `inspeximus_recall.py`
  drives real inspeximus through `remember`/`recall` in its default
  configuration; `recall` ranks lexically below 300 memories, so the row
  runs offline and lands in the inspeximus default row. `langgraph_store.py`
  drives LangGraph's `SqliteStore` with a vector index through
  `put`/`search`; it is a separate row from the checkpointer because they
  are different components, and its cells are published only with a real
  embedder. Facts pinned: the store applies no relevance floor and its user
  isolation is the caller's namespace; inspeximus drops another user's
  records before ranking and shares records written with no user.
- `agmi/measure.py`: one command for the memory-specific family on any
  target, printing the row with its provenance line.
- `retrieval_hijack` rebuilt so a relevance floor cannot pass it. The
  victim holds six genuine memories on one topic and the agent takes three;
  the attacker's single entry is stuffed with the topic's question words
  around an unrelated payload, so it is on topic by construction and can
  only appear by outranking a genuine memory. The earlier version padded
  toward a different topic, which any score floor kept out for free. The
  naive baseline now fails this cell at rank 1, as an undefended ranker
  should; earlier scorecards showed it as safe. Mem0's cell is re-measured
  in this release.
- CI actions moved to `actions/checkout@v5` and `actions/setup-python@v6`
  (the v4/v5 tags run on Node 20, which GitHub is retiring).
- Mem0 memory-specific adapter (`mem0_semantic.py`): real Mem0 driven
  through its own `add(infer=False)` and `search(filters, top_k)` paths on
  a private local Qdrant store, for the injection, bleed, hijack and
  indirect-prompt-injection attacks. The embedder is pluggable
  (`agmi/embedders.py`): the offline hashing embedder for plumbing and the
  bleed cell, all-MiniLM-L6-v2 via sentence-transformers (new `embedder`
  extra) for every cell that depends on ranking. Rows carry a
  `measured_on()` line naming the Mem0 version, embedder and which of
  Mem0's optional ranking signals were on.
- Recorded two facts about mem0ai 2.0.20's default read path that the row
  depends on: it drops candidates whose semantic score is under 0.1 before
  ranking, and its result count is `top_k` (a `limit=` argument is silently
  ignored and 20 returned).
- Shared Mem0 plumbing moved into `mem0_common.py`; the at-rest adapter
  now opens its store through it. Measured behaviour unchanged.
- pytest tiers: the default run stays offline; `pytest -m embedder` runs
  tests that need the cached model.
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
