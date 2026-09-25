# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Build agentmemoryintegrity.org from results/scorecard.json.

    python site/build.py            -> writes docs/site/
    python site/build.py --check    -> exit 1 if docs/site/ is stale

Every cell on the site comes from the committed results file, so the web
table can never drift from what was measured. Content that is not a
measurement (what each edit is, how to run, how to cite) lives in this
file next to the code that renders it.
"""
from __future__ import annotations

import html
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "scorecard.json"
OUT = ROOT / "docs" / "site"
SITE = "https://agentmemoryintegrity.org"
VERSION = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)

# ---------------------------------------------------------------- content
AT_REST = [
    ("tamper", "T1", "Content tamper", "Change the text inside one existing record, keeping its encoding intact.",
     "Silent rewriting of a past memory or decision."),
    ("truncate", "T2", "Tail truncation", "Delete the newest records so an earlier state becomes current.",
     "Rolling the agent back and erasing its recent actions from the record."),
    ("delete_middle", "T3", "Middle deletion", "Remove one record from the middle of the history.",
     "Erasing one inconvenient event from a history that still looks continuous."),
    ("reorder", "T4", "Reordering", "Swap the position of two records by editing their order keys or parent links.",
     "Changing what happened before what."),
    ("forge", "T5", "Forged insertion", "Insert a new record of the attacker's authorship, in the store's own format.",
     "Planting a memory or checkpoint the agent then resumes from."),
    ("cross_replay", "T6", "Cross-context replay", "Copy a genuine record from another user or thread over this one, keeping this one's identity.",
     "Real bytes, wrong owner. Passes any encryption that does not bind a record to its place."),
    ("rollback_replay", "T7", "Rollback replay", "Copy an older genuine record of the same context over its newest.",
     "Every record is genuine; only the order is rewound. Needs the sequence covered, not just each record."),
    ("metadata_tamper", "T8", "Metadata tamper", "Change a record's owner, source or timestamp and leave its content untouched.",
     "Moves a record to another user or marks an untrusted source as trusted."),
]
FRONT_DOOR = [
    ("memory_injection", "Planted fact", "Write a false fact through the tool's own API and see whether recall serves it as the user's own.",
     "The cheapest attack there is: talk to the agent and wait."),
    ("cross_session_bleed", "Cross-user leak", "Write as one user, read as another.",
     "The only cell that holds anywhere, and it holds for a tool-specific reason each time."),
    ("retrieval_hijack", "Retrieval hijack", "Stuff an entry with a topic's question words so it outranks the genuine memory.",
     "The read path ranks by similarity and nothing else."),
    ("indirect_prompt_injection", "Hidden instruction", "Store an instruction disguised as a memory and see whether it comes back as context.",
     "A memory that tells the agent what to do next."),
    ("update_poisoning", "Update poisoning", "Write a 'correction' of a fact the user stated.",
     "Every real tool serves the correction alongside the original."),
    ("metadata_poisoning", "Metadata poisoning", "Self-assign the trust tag a pipeline filters on.",
     "Every tool with a filter let the self-tagged memory through."),
]
ROW_NAMES = {
    "openfang(model,fixed)": ("OpenFang model, tip-persistence fix", "reference model of a hash chain"),
    "langgraph-sqlite": ("LangGraph SqliteSaver", "langgraph-checkpoint-sqlite 3.1.1"),
    "langgraph-sqlite-store": ("LangGraph SqliteStore", "langgraph-checkpoint-sqlite 3.1.1"),
    "openai-agents-sqlite-session": ("OpenAI Agents SDK SQLiteSession", "openai-agents 0.20.0"),
    "letta-block-history": ("Letta block checkpoint history", "letta 0.16.8"),
    "letta-archival": ("Letta archival memory", "letta 0.16.8"),
    "mem0-qdrant-local": ("Mem0 local Qdrant store", "mem0ai 2.0.20"),
    "inspeximus-default": ("inspeximus, receipts off (default)", "inspeximus 3.0.0"),
    "inspeximus-rcpt+dir": ("inspeximus, receipts on, attacker holds the store directory", "inspeximus 3.0.0"),
    "inspeximus-rcpt+dir+home": ("inspeximus, receipts on, attacker also holds the config home", "inspeximus 3.0.0"),
    "inspeximus-defended": ("inspeximus, trust root keyed on the label", "inspeximus 3.0.0, maintainer-contributed"),
    "inspeximus-defended-key": ("inspeximus, trust root keyed on an attested key", "inspeximus 3.0.0, maintainer-contributed"),
    "naive-mem(scoped)": ("Reference store, user-scoped", "no defence, for calibration"),
    "naive-mem(unscoped)": ("Reference store, unscoped", "no defence, for calibration"),
    "reference-defended(model)": ("Reference store, defended", "signed writes, quarantine, stuffing check"),
}
FINDINGS = [
    ("Four of four stores accept all eight at-rest edits", "2026-09-25",
     "LangGraph SqliteSaver, Letta block history, Mem0 local Qdrant and inspeximus in its default configuration all serve every one of the eight storage-level edits as genuine. None of the four checks anything on read.",
     None),
    ("A receipt does not bind the owning user (inspeximus)", "2026-09-25",
     "With receipts on, inspeximus's audit catches seven of the eight edits, but not T6: a genuine signed record lifted from another user's context still passes, because the receipt commits to the record's text and key and not to who it belongs to. Rollback (T7) and metadata edits (T8) are caught. Raised with the maintainer.",
     None),
    ("Encryption without identity binding (LangGraph #9004)", "2026-09-24",
     "LangGraph's EncryptedSerializer authenticates the ciphertext but not the record's place, so a genuine encrypted checkpoint from one thread verifies in another (T6) and an older one verifies over the newest (T7). A proposed fix binding thread, checkpoint id and channel as AEAD associated data rejects both; deleting the head row (T2) still rolls the thread back, because binding a record to its place cannot see a record that has been removed.",
     "https://github.com/langchain-ai/langgraph/issues/9004"),
    ("A vendor fix, caught by re-measurement (inspeximus 3.5.2)", "2026-09-22",
     "After the maintainer shipped a write-time quarantine and a stuffing penalty, the hidden-instruction and retrieval-hijack cells moved from surfaced on all five fixtures to surfaced on one and two. The cells stay surfaced, since a tool is kept out only when the attacker wins none, but the defence is engaging and the change is on record.",
     None),
    ("A forward-only hash chain misses truncation (OpenFang)", "2026-09-14",
     "A chain that walks forward from the first record verifies every link and never notices that the last two are gone. Persisting the tip closes exactly that gap. This was the first result the suite produced and the reason the reference model exists.",
     None),
]

DIAG_PIPELINE = '''<figure class="diag"><svg viewBox="0 0 900 220" role="img" aria-labelledby="dp-t"><title id="dp-t">How one cell is measured</title>
<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" class="ahead"/></marker></defs>
<g class="step"><rect x="10" y="60" width="150" height="80" rx="10" class="box"/><text x="85" y="92" class="bt">Seed</text><text x="85" y="114" class="bs">through the tool's</text><text x="85" y="130" class="bs">own API</text></g>
<path d="M162 100 H188" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="192" y="60" width="150" height="80" rx="10" class="box box-attack"/><text x="267" y="92" class="bt">Edit</text><text x="267" y="114" class="bs">one change to the</text><text x="267" y="130" class="bs">store, no keys</text></g>
<path d="M344 100 H370" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="374" y="60" width="150" height="80" rx="10" class="box"/><text x="449" y="92" class="bt">Restart</text><text x="449" y="114" class="bs">nothing cached</text><text x="449" y="130" class="bs">in process</text></g>
<path d="M526 100 H552" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="556" y="60" width="150" height="80" rx="10" class="box"/><text x="631" y="92" class="bt">Read</text><text x="631" y="114" class="bs">through the tool's</text><text x="631" y="130" class="bs">own read path</text></g>
<path d="M708 100 H734" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="738" y="40" width="152" height="120" rx="10" class="box box-verdict"/><text x="814" y="70" class="bt">Verdict</text>
<text x="814" y="96" class="bv v-rej-t">rejected</text><text x="814" y="118" class="bv v-rep-t">reported</text><text x="814" y="140" class="bv v-acc-t">accepted</text></g>
<text x="85" y="185" class="bn">control: a reload with no edit must still verify, or the cell is n/a</text>
<text x="631" y="185" class="bn">the verdict is what the tool does, never what we infer</text>
</svg><figcaption>How one cell is measured. The attacker's edit is the only thing that changes between seed and read; the tool's own behaviour on read is the verdict.</figcaption></figure>'''

DIAG_THREAT = '''<figure class="diag"><svg viewBox="0 0 900 300" role="img" aria-labelledby="dt-t"><title id="dt-t">Where the attacker stands</title>
<rect x="330" y="30" width="240" height="240" rx="14" class="box box-agent"/><text x="450" y="62" class="bt">The agent</text>
<rect x="360" y="84" width="180" height="56" rx="8" class="box"/><text x="450" y="108" class="bt">write path</text><text x="450" y="128" class="bs">remember, add, put</text>
<rect x="360" y="156" width="180" height="56" rx="8" class="box"/><text x="450" y="180" class="bt">read path</text><text x="450" y="200" class="bs">recall, search, resume</text>
<rect x="360" y="228" width="180" height="30" rx="8" class="box box-store"/><text x="450" y="248" class="bs">memory store</text>
<g><rect x="20" y="40" width="250" height="88" rx="10" class="box box-attack"/><text x="145" y="68" class="bt">Front door</text><text x="145" y="90" class="bs">can only talk to the agent</text><text x="145" y="108" class="bs">six attacks, three channels</text></g>
<path d="M272 84 C 300 84, 320 112, 358 112" class="flow" marker-end="url(#ah)"/>
<g><rect x="20" y="182" width="250" height="88" rx="10" class="box box-attack"/><text x="145" y="210" class="bt">At rest</text><text x="145" y="232" class="bs">can write to the store, holds no keys</text><text x="145" y="250" class="bs">eight edits, T1 to T8</text></g>
<path d="M272 240 C 300 240, 320 243, 358 243" class="flow" marker-end="url(#ah)"/>
<g><rect x="630" y="100" width="250" height="100" rx="10" class="box"/><text x="755" y="130" class="bt">What agmi records</text><text x="755" y="152" class="bs">what came back from the read path</text><text x="755" y="170" class="bs">the tool's own verdict, its detail,</text><text x="755" y="188" class="bs">the version, the reproduction</text></g>
<path d="M542 184 C 580 184, 590 150, 628 150" class="flow" marker-end="url(#ah)"/>
</svg><figcaption>Two attacker positions. The front-door attacker writes through the agent and is scored on whether the planted memory comes back as context. The at-rest attacker edits the store directly and is scored on whether the tool notices on read.</figcaption></figure>'''

DIAG_ARCH = '''<figure class="diag"><svg viewBox="0 0 900 340" role="img" aria-labelledby="da-t"><title id="da-t">How the suite is put together</title>
<rect x="20" y="30" width="200" height="130" rx="12" class="box"/><text x="120" y="58" class="bt">Attacks</text>
<text x="120" y="82" class="bs">8 at-rest edits</text><text x="120" y="100" class="bs">6 front-door attacks</text><text x="120" y="118" class="bs">5 fixtures, 3 channels</text><text x="120" y="136" class="bs">content mutations</text>
<path d="M222 95 H258" class="flow" marker-end="url(#ah)"/>
<rect x="262" y="30" width="200" height="130" rx="12" class="box box-agent"/><text x="362" y="58" class="bt">Adapter interface</text>
<text x="362" y="82" class="bs">seed, read raw, write raw</text><text x="362" y="100" class="bs">delete raw, reload, verify</text><text x="362" y="118" class="bs">seed other, replay onto</text><text x="362" y="136" class="bs">read meta, write meta</text>
<path d="M464 95 H500" class="flow" marker-end="url(#ah)"/>
<rect x="504" y="18" width="376" height="154" rx="12" class="box box-store"/><text x="692" y="44" class="bt">Real stores, pinned versions</text>
<g class="chips">
<rect x="524" y="60" width="160" height="30" rx="6" class="chip"/><text x="604" y="80" class="bs">LangGraph SqliteSaver</text>
<rect x="700" y="60" width="160" height="30" rx="6" class="chip"/><text x="780" y="80" class="bs">Letta block history</text>
<rect x="524" y="98" width="160" height="30" rx="6" class="chip"/><text x="604" y="118" class="bs">Mem0 local Qdrant</text>
<rect x="700" y="98" width="160" height="30" rx="6" class="chip"/><text x="780" y="118" class="bs">inspeximus, 5 rows</text>
<rect x="524" y="136" width="336" height="28" rx="6" class="chip chip-ref"/><text x="692" y="155" class="bs">reference stores: naive, defended, at-rest</text>
</g>
<path d="M362 162 V196" class="flow" marker-end="url(#ah)"/>
<rect x="262" y="200" width="200" height="56" rx="12" class="box"/><text x="362" y="224" class="bt">full_runner</text><text x="362" y="244" class="bs">every store, every attack</text>
<path d="M464 228 H500" class="flow" marker-end="url(#ah)"/>
<rect x="504" y="200" width="180" height="56" rx="12" class="box box-verdict"/><text x="594" y="224" class="bt">scorecard.json</text><text x="594" y="244" class="bs">one results file, committed</text>
<path d="M686 228 H722" class="flow" marker-end="url(#ah)"/>
<rect x="726" y="184" width="154" height="88" rx="12" class="box"/><text x="803" y="208" class="bt">rendered</text><text x="803" y="228" class="bs">README tables</text><text x="803" y="246" class="bs">docs/scorecard.md</text><text x="803" y="264" class="bs">this website</text>
<path d="M594 258 V294" class="flow" marker-end="url(#ah)"/>
<rect x="434" y="298" width="320" height="32" rx="8" class="box box-attack"/><text x="594" y="319" class="bs">CI re-measures on every change; fails if any cell drifts</text>
<rect x="20" y="200" width="200" height="72" rx="12" class="box"/><text x="120" y="224" class="bt">Memory agent</text><text x="120" y="244" class="bs">hunts for the first landing,</text><text x="120" y="262" class="bs">proves it, behind an authz gate</text>
<path d="M222 236 H258" class="flow" marker-end="url(#ah)"/>
</svg><figcaption>One attack is written once against the adapter interface and runs against every store. Everything published, the README, the scorecard file and this site, is rendered from one committed results file, and CI fails if they ever disagree.</figcaption></figure>'''

DIAG_CI = '''<figure class="diag"><svg viewBox="0 0 900 150" role="img" aria-labelledby="dc-t"><title id="dc-t">One step in a vendor's CI</title>
<rect x="20" y="40" width="190" height="70" rx="10" class="box"/><text x="115" y="70" class="bt">your pull request</text><text x="115" y="92" class="bs">any change to the store</text>
<path d="M212 75 H248" class="flow" marker-end="url(#ah)"/>
<rect x="252" y="40" width="210" height="70" rx="10" class="box box-agent"/><text x="357" y="70" class="bt">the agmi Action</text><text x="357" y="92" class="bs">runs T1 to T8 on your adapter</text>
<path d="M464 75 H500" class="flow" marker-end="url(#ah)"/>
<rect x="504" y="20" width="170" height="50" rx="10" class="box box-rej"/><text x="589" y="41" class="bt">all rejected</text><text x="589" y="59" class="bs">job passes</text>
<rect x="504" y="82" width="170" height="50" rx="10" class="box box-acc"/><text x="589" y="103" class="bt">one accepted</text><text x="589" y="121" class="bs">job fails, cell annotated</text>
<path d="M676 45 H712" class="flow" marker-end="url(#ah)"/><path d="M676 107 H712" class="flow" marker-end="url(#ah)"/>
<rect x="716" y="40" width="164" height="70" rx="10" class="box"/><text x="798" y="70" class="bt">Actions summary</text><text x="798" y="92" class="bs">the eight-row table</text>
</svg><figcaption>The Action fails a vendor's build the moment their store serves an edited record as genuine, and writes the row into the job summary.</figcaption></figure>'''

DIAG_TIMELINE = '''<figure class="diag"><svg viewBox="0 0 900 262" role="img" aria-labelledby="dl-t"><title id="dl-t">The eight edits on two users' histories</title>
<text x="14" y="86" class="bn" style="text-anchor:start">user A</text><text x="14" y="176" class="bn" style="text-anchor:start">user B</text>
<rect x="70" y="64" width="58" height="34" rx="6" class="rec"/><text x="99" y="86" class="rt">A0</text><rect x="146" y="64" width="58" height="34" rx="6" class="rec rec-gone"/><text x="175" y="86" class="rt">A1</text><rect x="222" y="64" width="58" height="34" rx="6" class="rec rec-x"/><text x="251" y="86" class="rt">A2</text><rect x="298" y="64" width="58" height="34" rx="6" class="rec"/><text x="327" y="86" class="rt">A3</text><rect x="374" y="64" width="58" height="34" rx="6" class="rec rec-gone"/><text x="403" y="86" class="rt">A4</text><rect x="450" y="64" width="58" height="34" rx="6" class="rec rec-gone"/><text x="479" y="86" class="rt">A5</text>
<rect x="70" y="154" width="58" height="34" rx="6" class="rec"/><text x="99" y="176" class="rt">B0</text><rect x="146" y="154" width="58" height="34" rx="6" class="rec rec-moved"/><text x="175" y="176" class="rt">B1</text><rect x="222" y="154" width="58" height="34" rx="6" class="rec rec-moved"/><text x="251" y="176" class="rt">B2</text><rect x="298" y="154" width="58" height="34" rx="6" class="rec rec-moved"/><text x="327" y="176" class="rt">B3</text><rect x="374" y="154" width="58" height="34" rx="6" class="rec rec-moved"/><text x="403" y="176" class="rt">B4</text><rect x="450" y="154" width="58" height="34" rx="6" class="rec rec-x"/><text x="479" y="176" class="rt">B5</text><rect x="526" y="154" width="58" height="34" rx="6" class="rec rec-att"/><text x="555" y="176" class="rt">B6</text>
<g class="tags"><text x="175" y="40" class="tag tag-acc">T3 remove A1</text><path d="M175 46 V60" class="flow"/><text x="251" y="20" class="tag tag-acc">T1 change A2</text><path d="M251 26 V60" class="flow"/><text x="441" y="40" class="tag tag-acc">T2 cut the tail: A4, A5</text><path d="M441 46 V60" class="flow"/><text x="213" y="220" class="tag tag-teal">T4 swap B1 and B2</text><path d="M213 190 V212" class="flow"/><text x="555" y="220" class="tag tag-acc">T5 forge B6</text><path d="M555 190 V212" class="flow"/><path d="M251 100 C 251 130, 403 120, 403 150" class="parrow"/><text x="327" y="128" class="tag tag-teal" dx="60" dy="-12">T6 copy A2 onto B4</text><path d="M99 190 C 99 256, 327 256, 327 190" class="parrow"/><text x="213" y="250" class="tag tag-teal">T7 copy B0 onto B3</text><text x="479" y="130" class="tag tag-acc">T8 change owner of B5</text><text x="479" y="146" class="bn">text untouched</text></g></svg><figcaption>Eight edits on two users' histories. T1, T5 and T8 change or add bytes. T2 and T3 remove them. T4, T6 and T7 move only genuine bytes, which is why encryption and per-record signatures do not catch them.</figcaption></figure>'''

DIAG_ECO = '''<figure class="diag"><svg viewBox="0 0 900 330" role="img" aria-labelledby="de-t"><title id="de-t">Where agmi sits</title>
<rect x="330" y="120" width="240" height="90" rx="14" class="box box-agent"/><text x="450" y="152" class="bt">agmi</text><text x="450" y="174" class="bs">the measurement</text><text x="450" y="192" class="bs">open, MIT, reproducible</text>
<rect x="20" y="20" width="250" height="80" rx="10" class="box"/><text x="145" y="46" class="bt">Standards</text><text x="145" y="66" class="bs">IETF BMWG 5.4.7 method text</text><text x="145" y="84" class="bs">OWASP agentic security, ASI06</text>
<path d="M272 60 C 300 60, 320 130, 358 140" class="flow" marker-end="url(#ah)"/>
<rect x="630" y="20" width="250" height="80" rx="10" class="box"/><text x="755" y="46" class="bt">Vendors</text><text x="755" y="66" class="bs">LangGraph, Letta, Mem0, inspeximus</text><text x="755" y="84" class="bs">issues, fixes, re-measured rows</text>
<path d="M628 60 C 600 60, 580 130, 542 140" class="flow" marker-end="url(#ah)"/>
<rect x="20" y="230" width="250" height="80" rx="10" class="box"/><text x="145" y="256" class="bt">Contributors</text><text x="145" y="276" class="bs">maintainers submit adapters and rows</text><text x="145" y="294" class="bs">with the control cases as tests</text>
<path d="M272 270 C 300 270, 320 200, 358 190" class="flow" marker-end="url(#ah)"/>
<rect x="630" y="230" width="250" height="80" rx="10" class="box"/><text x="755" y="256" class="bt">Assessments</text><text x="755" y="276" class="bs">hosted runs and vendor badges</text><text x="755" y="294" class="bs">through AuditTrax Labs, from 1.0</text>
<path d="M628 270 C 600 270, 580 200, 542 190" class="flow" marker-end="url(#ah)"/>
</svg><figcaption>The measurement in the middle; standards, vendors, contributors and assessments around it. The open benchmark stays free. Hosted runs and badges are the paid layer, from 1.0.</figcaption></figure>'''

# Plain-English explainers for each edit: story, three panels, what stops it.
# Record states: n = genuine, x = bytes changed, g = removed, m = genuine bytes moved, a = attacker-authored
EXPLAIN = {
    "tamper": dict(
        story="The user told the agent last week that the wire goes to account 4471. The attacker opens the store and changes one number inside that record. Nothing else moves.",
        before=[("A", "nnnnn")], after=[("A", "nnxnn")], note="one field in A2 rewritten",
        sees="The agent reads A2 back with the new number and treats it as what the user said.",
        stops="Any authentication over each record's bytes: a MAC, a signature or an authenticated cipher. This is the edit every defence catches first.",
        beats="Plain encryption without authentication, and any store that only checks that the record still parses."),
    "truncate": dict(
        story="The agent made two decisions yesterday. The attacker deletes both records, so the newest record is now the one from the day before.",
        before=[("A", "nnnnn")], after=[("A", "nnngg")], note="A3 and A4 deleted, head is now A2",
        sees="The agent resumes from A2 as if yesterday never happened, and repeats or reverses what it did.",
        stops="A signed head pointer: the store must know which record is supposed to be newest, not just that each record is valid.",
        beats="Per-record signatures and per-record encryption, because every record left is genuine."),
    "delete_middle": dict(
        story="One event in the middle of the history is inconvenient. The attacker removes just that record and points its successor at its predecessor.",
        before=[("A", "nnnnn")], after=[("A", "nngnn")], note="A2 removed, A3 now follows A1",
        sees="The history reads A0, A1, A3, A4. It is shorter, continuous and wrong.",
        stops="A chain: each record carries a tag over the previous record, so a missing link is a broken link.",
        beats="Per-record checks, and stores that store the parent id as plain data."),
    "reorder": dict(
        story="The user set a rule, then made an exception. The attacker swaps the two records, so the exception now comes first and the rule overrides it.",
        before=[("A", "nnnnn")], after=[("A", "nmnmn")], note="A1 and A3 change places",
        sees="What happened before what is reversed. Every byte is genuine.",
        stops="Position inside the authenticated data: the record's tag must cover where it sits, not only what it says.",
        beats="Everything that authenticates content alone."),
    "forge": dict(
        story="The attacker writes a brand-new record in the store's own format, with a valid-looking id and the right parent, saying the user approved something.",
        before=[("A", "nnnnn")], after=[("A", "nnnnna")], note="A5 written by the attacker",
        sees="The agent resumes from A5 and acts on an approval nobody gave.",
        stops="A key the attacker does not hold: records are signed or MACed with something that is not in the store directory.",
        beats="Stores where the only check is that the record is well formed."),
    "cross_replay": dict(
        story="User A's memory says their password hint. The attacker copies A's genuine record over one of user B's, keeping B's ids. Every byte, including its signature, is real.",
        before=[("A", "nnnnn"), ("B", "nnnnn")], after=[("A", "nnnnn"), ("B", "nnmnn")], note="A2 copied onto B2, B's ids kept",
        sees="User B is served user A's memory as their own. Encryption verifies, the signature verifies.",
        stops="The owning context inside the authenticated data: the tag must cover whose record this is and which thread it belongs to.",
        beats="Encrypted checkpointers and per-record signatures that do not bind the record to its owner. This is the edit that separates real integrity from encryption."),
    "rollback_replay": dict(
        story="The user revoked an access last week. The attacker copies the record from before the revocation over the newest record of the same user.",
        before=[("B", "nnnnn")], after=[("B", "nnnnm")], note="B0 copied over B4, ids kept",
        sees="The user is rewound to an older state and the revocation is gone. Every record is genuine and in this user's own history.",
        stops="Position plus a signed head: the sequence itself must be covered, not the records one by one.",
        beats="Any store that verifies records independently, even with the owner bound in."),
    "metadata_tamper": dict(
        story="A record from an untrusted web page sits in the store marked source: web. The attacker changes that one tag to source: user and touches nothing else.",
        before=[("B", "nnnnn")], after=[("B", "nnnxn")], note="source tag of B3 changed, text untouched",
        sees="A pipeline that filters on the tag now serves the record as trusted, or serves it to a different user.",
        stops="Metadata inside the authenticated data: owner, source and time are covered by the same tag as the content.",
        beats="Every store that signs content and keeps metadata as plain columns."),
}

def explainer(key):
    e = EXPLAIN[key]
    def row(y, label, states):
        out = f'<text x="14" y="{y+22}" class="bn" style="text-anchor:start">user {label}</text>'
        for i, st in enumerate(states):
            cls = {"n": "rec", "x": "rec rec-x", "g": "rec rec-gone", "m": "rec rec-moved", "a": "rec rec-att"}[st]
            out += f'<rect x="{62+i*38}" y="{y}" width="32" height="30" rx="5" class="{cls}"/><text x="{78+i*38}" y="{y+20}" class="rt">{label}{i}</text>'
        return out
    def panel(x, title, rows, cls):
        body = ""
        for j, (label, states) in enumerate(rows):
            body += row(46 + j*44, label, states)
        return (f'<g transform="translate({x} 0)"><g class="xp {cls}"><rect x="0" y="0" width="290" height="160" rx="10" class="pbox"/>'
                f'<text x="14" y="26" class="pt">{title}</text>{body}</g></g>')
    two = len(e["before"]) == 2
    sees_lines = []
    words = e["sees"].split()
    line = ""
    for w in words:
        if len(line) + len(w) > 34:
            sees_lines.append(line.strip()); line = ""
        line += w + " "
    sees_lines.append(line.strip())
    sees = "".join(f'<text x="14" y="{56+i*18}" class="bs" style="text-anchor:start">{esc(l)}</text>' for i, l in enumerate(sees_lines))
    svg = (f'<svg viewBox="0 0 900 175" role="img" aria-label="{esc(e["note"])}">'
           + panel(0, "Before", e["before"], "xp-before")
           + '<path d="M292 80 H 302" class="flow"/>'
           + panel(305, "The edit", e["after"], "xp-edit").replace('</g></g>', f'<text x="14" y="148" class="bs" style="text-anchor:start">{esc(e["note"])}</text></g></g>')
           + '<path d="M597 80 H 607" class="flow"/>'
           + f'<g transform="translate(610 0)"><g class="xp xp-read"><rect x="0" y="0" width="290" height="160" rx="10" class="pbox pbox-read"/><text x="14" y="26" class="pt">What the agent reads back</text>{sees}</g></g>'
           + '</svg>')
    return svg

def verdict_groups(rows, keys, attack):
    groups = {"rejected": [], "reported": [], "accepted": [], "surfaced": [], "kept out": []}
    for k in keys:
        c = rows[k]["cells"].get(attack)
        if not c or c["verdict"] not in groups:
            continue
        groups[c["verdict"]].append(ROW_NAMES.get(k, (k, ""))[0])
    return groups

DIAG_CHANNELS = """<figure class="diag"><svg viewBox="0 0 900 230" role="img" aria-labelledby="dch-t"><title id="dch-t">The three front-door channels</title>
<g class="step"><rect x="20" y="20" width="330" height="54" rx="8" class="box box-attack"/><text x="185" y="42" class="bt">external</text><text x="185" y="62" class="bs">attacker writes, honest provenance, attacker id</text></g>
<g class="step"><rect x="20" y="88" width="330" height="54" rx="8" class="box box-attack"/><text x="185" y="110" class="bt">laundered</text><text x="185" y="130" class="bs">attacker writes under the victim's id</text></g>
<g class="step"><rect x="20" y="156" width="330" height="54" rx="8" class="box box-attack"/><text x="185" y="178" class="bt">agent-laundered</text><text x="185" y="198" class="bs">the victim's own agent stores what the attacker said</text></g>
<path d="M352 47 C 376 47, 376 115, 392 115" class="flow" marker-end="url(#ah)"/>
<path d="M352 115 H392" class="flow" marker-end="url(#ah)"/>
<path d="M352 183 C 376 183, 376 115, 392 115" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="396" y="85" width="228" height="60" rx="8" class="box"/><text x="510" y="107" class="bt">mutations on every write</text><text x="510" y="127" class="bs">reworded, look-alike, split, diluted</text></g>
<path d="M626 115 H646" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="650" y="30" width="230" height="170" rx="12" class="box box-agent"/><text x="765" y="58" class="bt">The memory store</text>
<rect x="676" y="74" width="178" height="34" rx="6" class="box"/><text x="765" y="96" class="bs">write path</text>
<rect x="676" y="120" width="178" height="34" rx="6" class="box"/><text x="765" y="142" class="bs">read path, ranked</text>
<text x="765" y="184" class="bs">what comes back is the verdict</text></g>
</svg><figcaption>Three ways in through the front door. Provenance stops the first, an attested key stops the second, and no store can close the third, because the agent itself is the writer. Every write also runs as its content mutations.</figcaption></figure>"""

DIAG_HUNT = """<figure class="diag"><svg viewBox="0 0 900 300" role="img" aria-labelledby="dh-t"><title id="dh-t">The hunt loop</title>
<g class="step"><rect x="20" y="110" width="150" height="70" rx="10" class="box box-agent"/><text x="95" y="138" class="bt">authorise</text><text x="95" y="160" class="bs">fails closed</text></g>
<path d="M172 145 H208" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="212" y="90" width="190" height="110" rx="10" class="box"/><text x="307" y="118" class="bt">pick the next attempt</text><text x="307" y="142" class="bs">6 attacks</text><text x="307" y="160" class="bs">3 channels</text><text x="307" y="178" class="bs">base fixture, then mutations</text></g>
<path d="M404 145 H440" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="436" y="110" width="166" height="70" rx="10" class="box box-attack"/><text x="519" y="138" class="bt">write, then read</text><text x="519" y="160" class="bs">as the victim would</text></g>
<path d="M604 145 H622" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="626" y="110" width="176" height="70" rx="10" class="box"/><text x="714" y="138" class="bt">served as trusted?</text><text x="714" y="160" class="bs">positive control checked</text></g>
<path d="M714 108 C 714 40, 307 40, 307 88" class="flow" marker-end="url(#ah)"/><text x="509" y="34" class="bn">no: next attempt</text>
<path d="M714 182 V226" class="flow" marker-end="url(#ah)"/>
<g class="step"><rect x="580" y="230" width="268" height="60" rx="10" class="box box-verdict"/><text x="714" y="254" class="bt">finding</text><text x="714" y="276" class="bs">proof, served text, reproduction script</text></g>
<text x="20" y="220" class="bn" style="text-anchor:start">library target: allowed</text><text x="20" y="238" class="bn" style="text-anchor:start">localhost: allowed</text><text x="20" y="256" class="bn" style="text-anchor:start">other host: token named for it, or consent file</text><text x="20" y="274" class="bn" style="text-anchor:start">anything else: raises before the hunt starts</text>
</svg><figcaption>The agent searches attacks, channels and mutations for the first that lands, proves each landing against a positive control, and reports only what it proved. The gate runs before any target is touched.</figcaption></figure>"""

AGENT_RESULTS = [
    ("Mem0 local Qdrant store, all-MiniLM-L6-v2", "5", "5", "external", "none"),
    ("LangGraph SqliteStore, all-MiniLM-L6-v2", "5", "5", "external", "none"),
    ("inspeximus 3.0.0, default", "5", "5", "external", "none"),
    ("Letta archival memory, all-MiniLM-L6-v2", "4", "4 (no metadata filter, so that attack does not apply)", "external", "none"),
    ("reference-defended (model)", "131", "4", "agent-laundered only", "dilute, on the hijack"),
]

LEVELS = [
    ("L0", "Measured", "The store has a published row. Any verdicts.", []),
    ("L1", "Bytes bound", "Rejects on the read path every edit that changes or adds bytes: T1, T3, T5.", ["tamper", "delete_middle", "forge"]),
    ("L2", "Sequence bound", "Also rejects deletion, reordering and rollback: T2, T4, T7.", ["tamper", "delete_middle", "forge", "truncate", "reorder", "rollback_replay"]),
    ("L3", "Context bound", "Also rejects a record moved between owners and a metadata change: T6, T8.", ["tamper", "delete_middle", "forge", "truncate", "reorder", "rollback_replay", "cross_replay", "metadata_tamper"]),
]

def level_of(r):
    lvl = "L0"
    if r.get("checked_at") != "read":
        return lvl
    for code, _, _, need in LEVELS[1:]:
        if all(r["cells"].get(a, {}).get("verdict") == "rejected" for a in need):
            lvl = code
        else:
            break
    return lvl

# ---------------------------------------------------------------- helpers
def esc(s): return html.escape(str(s), quote=True)

def load():
    d = json.loads(RESULTS.read_text())
    rows = {r["label"]: r for r in d["rows"]}
    return d, rows

def verdict_class(v):
    return {"accepted": "v-acc", "rejected": "v-rej", "reported": "v-rep", "surfaced": "v-acc",
            "kept out": "v-rej", "n/a": "v-na"}.get(v, "v-na")

ATTACK_NAMES = {a: f"{t}, {n}" for a, t, n, _, _ in AT_REST}
ATTACK_NAMES.update({a: n for a, n, _, _ in FRONT_DOOR})


def cell(r, attack):
    c = r["cells"].get(attack)
    if not c:
        return '<td class="v-na"><span>n/a</span></td>'
    v = c["verdict"]
    det = c.get("detail") or ""
    return (f'<td class="{verdict_class(v)}"><button type="button" class="cellbtn" '
            f'data-row="{esc(r["label"])}" data-attack="{esc(attack)}" data-name="{esc(ATTACK_NAMES.get(attack, attack))}" data-verdict="{esc(v)}" '
            f'data-detail="{esc(det)}" data-point="{esc(r.get("checked_at") or "")}" '
            f'aria-label="{esc(ROW_NAMES.get(r["label"],(r["label"],""))[0])}, {esc(attack)}: {esc(v)}">{esc(v)}</button></td>')

def matrix(d, rows, keys, cols, kind):
    heads = "".join(f'<th scope="col"><abbr title="{esc(t)}">{esc(k)}</abbr></th>' for _, k, t in cols)
    body = ""
    for label in keys:
        r = rows[label]
        name, ver = ROW_NAMES.get(label, (label, ""))
        body += (f'<tr><th scope="row"><span class="rowname">{esc(name)}</span>'
                 f'<span class="rowver">{esc(ver)}</span></th>'
                 + "".join(cell(r, a) for a, _, _ in cols) + "</tr>")
    return (f'<div class="matrixwrap"><table class="matrix {kind}"><thead><tr>'
            f'<th scope="col" class="corner">Target</th>{heads}</tr></thead><tbody>{body}</tbody></table></div>')

def page(title, desc, path, body, nav_active):
    nav = [("index.html", "Overview"), ("scorecard.html", "Scorecard"), ("edits.html", "The edits"),
           ("architecture.html", "Architecture"), ("method.html", "Method"), ("agent.html", "Memory agent"), ("findings.html", "Findings"),
           ("ecosystem.html", "Ecosystem"), ("run.html", "Run it"), ("cite.html", "Cite"), ("about.html", "About")]
    links = "".join(f'<a href="{p}"{" aria-current=page" if p == nav_active else ""}>{t}</a>' for p, t in nav)
    canonical = SITE + "/" + ("" if path == "index.html" else path)
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<meta name="author" content="Yasha Khandelwal">
<meta name="robots" content="index,follow,max-snippet:-1">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{canonical}">
<meta property="og:type" content="website">
<link rel="icon" href="logo.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="site.css">
<script type="application/ld+json">{{"@context":"https://schema.org","@graph":[{{"@type":"SoftwareSourceCode","@id":"{SITE}/#software","name":"agmi: Agent Memory Integrity","codeRepository":"https://github.com/tech4biz-yasha/agmi","programmingLanguage":"Python","license":"https://opensource.org/licenses/MIT","version":"{VERSION}","identifier":"https://doi.org/10.5281/zenodo.22860886","author":{{"@id":"https://yashakhandelwal.com/#person"}},"url":"{SITE}/"}},{{"@type":"Person","@id":"https://yashakhandelwal.com/#person","name":"Yasha Khandelwal","url":"https://yashakhandelwal.com/","email":"yasha.khandelwal@tech4biz.io","sameAs":["https://orcid.org/0009-0005-2166-4951","https://github.com/tech4biz-yasha"]}},{{"@type":"Dataset","@id":"{SITE}/#scorecard","name":"Agent Memory Integrity scorecard","url":"{SITE}/scorecard.html","license":"https://opensource.org/licenses/MIT","creator":{{"@id":"https://yashakhandelwal.com/#person"}},"isBasedOn":"https://github.com/tech4biz-yasha/agmi","measurementTechnique":"Seed through the tool's own API, apply one edit to the store, restart, read through the tool's own read path, record the tool's own verdict"}}]}}</script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <a class="brand" href="index.html"><img src="logo.svg" alt="" width="28" height="28"><span>Agent Memory Integrity</span></a>
  <nav class="nav" aria-label="Site">{links}</nav>
  <a class="gh" href="https://github.com/tech4biz-yasha/agmi">GitHub</a>
</header>
<main id="main">
{body}
</main>
<footer class="foot">
  <p>agmi {VERSION}. Measured {esc(d_date)} on {esc(d_platform)}. Every cell on this site is read from the committed results file and reproduced in CI on every change.</p>
  <p>Built and maintained by <a href="https://yashakhandelwal.com/">Yasha Khandelwal</a> (<a href="mailto:yasha.khandelwal@tech4biz.io">yasha.khandelwal@tech4biz.io</a>, <a href="https://orcid.org/0009-0005-2166-4951">ORCID</a>). Hosted assessments and vendor badges through <a href="https://audittraxlabs.com/">AuditTrax Labs</a>. MIT licence. <a href="https://github.com/tech4biz-yasha/agmi">Source</a>, <a href="https://pypi.org/project/agent-memory-integrity/">PyPI</a>, <a href="https://doi.org/10.5281/zenodo.22860886">Zenodo</a>, <a href="about.html">About</a>.</p>
</footer>
<div id="drawer" class="drawer" hidden role="dialog" aria-modal="true" aria-labelledby="dtitle">
  <div class="drawer-card">
    <button type="button" class="drawer-close" aria-label="Close">×</button>
    <p class="drawer-kicker" id="dkick"></p>
    <h2 id="dtitle"></h2>
    <p id="dverdict" class="drawer-verdict"></p>
    <dl>
      <dt>What the tool said</dt><dd id="ddetail"></dd>
      <dt>Detection point</dt><dd id="dpoint"></dd>
      <dt>Reproduce</dt><dd><code id="drepro"></code></dd>
    </dl>
  </div>
</div>
<script src="site.js" defer></script>
</body>
</html>'''

# ---------------------------------------------------------------- pages
def build():
    global d_date, d_platform
    d, rows = load()
    d_date, d_platform = d["date"], d["platform"]
    at_rest_keys = [k for k in ["openfang(model,fixed)", "langgraph-sqlite", "openai-agents-sqlite-session", "llamaindex-memory-sqlite", "letta-block-history",
                                "mem0-qdrant-local", "inspeximus-default", "inspeximus-rcpt+dir",
                                "inspeximus-rcpt+dir+home"] if k in rows]
    fd_keys = [k for k in ["langgraph-sqlite-store", "letta-archival", "mem0-qdrant-local",
                           "inspeximus-default", "inspeximus-defended", "inspeximus-defended-key",
                           "naive-mem(scoped)", "naive-mem(unscoped)", "reference-defended(model)"] if k in rows]
    ar_cols = [(a, t, f"{t} {n}") for a, t, n, _, _ in AT_REST]
    fd_cols = [(a, n, n) for a, n, _, _ in FRONT_DOOR]

    # count the headline
    all8 = [k for k in ["langgraph-sqlite", "openai-agents-sqlite-session", "llamaindex-memory-sqlite", "letta-block-history", "mem0-qdrant-local", "inspeximus-default"]
            if k in rows and all(rows[k]["cells"][a]["verdict"] == "accepted" for a, *_ in AT_REST)]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "logo.svg").write_bytes((ROOT / "docs" / "logo.svg").read_bytes())

    # ---- index
    hero = f'''
<section class="hero">
  <div class="hero-text">
    <p class="lede">Edit an AI agent's memory behind its back. Restart the agent. Ask it what it remembers.</p>
    <h1>{len(all8)} of {len(all8)} memory stores serve the edit as genuine.</h1>
    <p class="sub">LangGraph, Letta, Mem0 and inspeximus, measured against eight storage-level edits and six front-door attacks. Real libraries, pinned versions, reproducible in under a minute, re-run in CI on every change.</p>
    <p class="cta"><a class="btn" href="scorecard.html">See the scorecard</a> <a class="btn-quiet" href="run.html">Run it on your store</a></p>
  </div>
  <figure class="hero-fig" aria-label="Animation: a genuine record from another user is copied over this user's newest record, and the read path returns it as genuine">
    <svg viewBox="0 0 560 300" role="img">
      <title>Cross-context replay, T6</title>
      <g class="lane lane-a">
        <text x="16" y="34" class="lbl">user A</text>
        <rect x="16" y="46" width="88" height="40" rx="6" class="rec"/><text x="60" y="71" class="rt">A0</text>
        <rect x="116" y="46" width="88" height="40" rx="6" class="rec"/><text x="160" y="71" class="rt">A1</text>
        <rect x="216" y="46" width="88" height="40" rx="6" class="rec rec-donor"/><text x="260" y="71" class="rt">A2</text>
      </g>
      <g class="lane lane-b">
        <text x="16" y="154" class="lbl">user B</text>
        <rect x="16" y="166" width="88" height="40" rx="6" class="rec"/><text x="60" y="191" class="rt">B0</text>
        <rect x="116" y="166" width="88" height="40" rx="6" class="rec"/><text x="160" y="191" class="rt">B1</text>
        <rect x="216" y="166" width="88" height="40" rx="6" class="rec rec-victim"/><text x="260" y="191" class="rt rt-victim">B2</text>
        <rect x="216" y="166" width="88" height="40" rx="6" class="rec rec-moved"/><text x="260" y="191" class="rt rt-moved">A2</text>
      </g>
      <path d="M260 92 C 260 130, 260 130, 260 160" class="arrow"/>
      <g class="read">
        <rect x="360" y="120" width="184" height="64" rx="8" class="readbox"/>
        <text x="376" y="146" class="lbl">B reads its memory</text>
        <text x="376" y="170" class="rt readval">A2</text>
        <text x="452" y="170" class="verdict">accepted</text>
      </g>
      <path d="M308 186 C 340 186, 340 152, 358 152" class="arrow arrow2"/>
    </svg>
    <figcaption>T6, cross-context replay. Genuine bytes from user A, copied over user B's newest record. B's store serves them as B's own. No forging, no key.</figcaption>
  </figure>
</section>
<section class="howto">
  <h2>How to read this site</h2>
  <div class="routes">
    <a href="scorecard.html"><strong>Five minutes.</strong> The two scorecards. Every cell is a measurement; click one to see what the tool actually said.</a>
    <a href="edits.html"><strong>Half an hour.</strong> The fourteen attacks, one figure and one paragraph each, and why each one matters.</a>
    <a href="run.html"><strong>Hands on.</strong> Run the eight edits against your own store in one CI step, or reproduce any cell on a laptop.</a>
  </div>
</section>
<section class="part">
  <h2>At rest: eight edits, {len(at_rest_keys)} stores</h2>
  <p>The attacker can write to the medium that holds the store (a database file, a table, a vector collection) but holds none of the tool's keys. Each edit is applied once, the tool is restarted, and its own read path is asked for the memory. <em>Accepted</em> means the tool served the edit as genuine. <em>Rejected</em> means it refused on read. <em>Reported</em> means its audit named the problem, after the agent had already resumed.</p>
  {matrix(d, rows, at_rest_keys, ar_cols, "atrest")}
  <p class="note">The edits, verdict words and control cases are the ones proposed as the test method for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7 (<a href="https://mailarchive.ietf.org/arch/browse/bmwg/">bmwg list, 24 September 2026</a>). T6 and T7 use only bytes the store itself wrote, in the wrong place; they are the edits that separate encryption from integrity. See <a href="method.html">Method</a>.</p>
</section>
<section class="part">
  <h2>Front door: six attacks through the tool's own write path</h2>
  <p>Here the attacker can only talk to the agent. Each attack runs on five different scenarios, on three channels (external, laundered with a forged label, and laundered with a valid signature), and a tool is <em>kept out</em> only if it keeps the attacker's memory out on all five. <em>Surfaced</em> means the planted memory came back as context for the agent.</p>
  {matrix(d, rows, fd_keys, fd_cols, "front")}
  <p class="note">The pattern is the same everywhere measured so far: only user isolation holds, and it holds for a tool-specific reason each time. The read path ranks by similarity and nothing else. Full detail per store on the <a href="scorecard.html">scorecard page</a>.</p>
</section>
<section class="part">
  <h2>How a cell is measured</h2>
  {DIAG_PIPELINE}
  <p>Every attack is written once against a small adapter interface and runs against every store; the whole scorecard is rendered from one committed results file, and CI fails if any published cell drifts from it. The full picture is on the <a href="architecture.html">Architecture</a> page.</p>
</section>
<section class="part">
  <h2>The memory agent</h2>
  <p>Beyond the fixed scorecard, agmi ships an agent that hunts: point it at one store and it searches six attacks, three channels and the content mutations for the first that gets a false memory served as trusted, proves the landing against a positive control, and hands back a reproduction script. Against every real store measured it walked in on the first attempt; only the defended reference store made it search. It runs behind an authorisation gate that fails closed. <a href="agent.html">How it works.</a></p>
  {DIAG_HUNT}
</section>
<section class="part">
  <h2>Where it sits</h2>
  {DIAG_ECO}
</section>
<section class="part latest">
  <h2>Latest findings</h2>
  <ul class="findlist">
    {"".join(f'<li><time>{esc(dt)}</time><a href="findings.html">{esc(t)}</a></li>' for t, dt, _, _ in FINDINGS[:3])}
  </ul>
</section>'''
    (OUT / "index.html").write_text(page("Agent Memory Integrity: do AI agent memory stores notice when they are tampered with?",
        "agmi measures whether AI agent memory and checkpoint stores notice tampering. Eight storage-level edits and six front-door attacks, measured on LangGraph, Letta, Mem0 and inspeximus.",
        "index.html", hero, "index.html"))

    # ---- scorecard
    def per_target(keys):
        out = ""
        for k in keys:
            r = rows[k]
            name, ver = ROW_NAMES.get(k, (k, ""))
            mo = r.get("measured_on") or ver
            out += f'<details class="target"><summary><span>{esc(name)}</span><span class="rowver">{esc(ver)}</span></summary><p class="mo">{esc(mo)}</p><ul>'
            for a, c in r["cells"].items():
                if c["verdict"] == "n/a":
                    continue
                out += f'<li><b>{esc(a)}</b>: {esc(c["verdict"])}. {esc(c.get("detail") or "")}</li>'
            out += "</ul></details>"
        return out
    sc = f'''
<section class="part">
  <h1>Scorecard</h1>
  <p>Two tables, one per attacker position. Click any cell for what the tool said, the detection point, and the command that reproduces it. Rows are pinned to the library version shown; a test fails the day that version changes its answer.</p>
  <h2>At rest</h2>
  {matrix(d, rows, at_rest_keys, ar_cols, "atrest")}
  <dl class="legend"><dt class="v-acc">accepted</dt><dd>the tool loaded the altered store, raised nothing, and served the altered memory as true</dd>
  <dt class="v-rej">rejected</dt><dd>the tool refused the edit at read time</dd>
  <dt class="v-rep">reported</dt><dd>a separate audit call named the problem; the read path had already served the store</dd>
  <dt class="v-na">n/a</dt><dd>not measurable on this store, or a control case failed, so no pass is recorded</dd></dl>
  <h2>Front door</h2>
  {matrix(d, rows, fd_keys, fd_cols, "front")}
  <dl class="legend"><dt class="v-acc">surfaced</dt><dd>the attacker's memory came back from the read path as context for the agent on at least one of five scenarios</dd>
  <dt class="v-rej">kept out</dt><dd>it did not, on all five</dd></dl>
  <h2>Per target, in full</h2>
  {per_target(at_rest_keys + [k for k in fd_keys if k not in at_rest_keys])}
</section>'''
    (OUT / "scorecard.html").write_text(page("Scorecard, Agent Memory Integrity", "Measured verdicts for LangGraph, Letta, Mem0 and inspeximus on eight at-rest edits and six front-door attacks.", "scorecard.html", sc, "scorecard.html"))

    # ---- edits
    ed = ('<section class="part"><h1>The edits and attacks</h1><p class="lede">Fourteen ways to change what an agent remembers. Eight need access to the store and are the at-rest edits, T1 to T8. Six only need to talk to the agent and are the front-door attacks. Each one below has a story, a picture of what changes, what the agent reads back, what stops it, and which stores stop it today.</p>'
          '<div class="legend"><span><i class="lg lg-n"></i>genuine record</span><span><i class="lg lg-x"></i>bytes changed</span><span><i class="lg lg-g"></i>removed</span><span><i class="lg lg-m"></i>genuine bytes moved</span><span><i class="lg lg-a"></i>attacker-authored</span></div>'
          + DIAG_TIMELINE + '<h2>At rest: the attacker can write to the store</h2>')
    for a, t, n, what, why in AT_REST:
        e = EXPLAIN[a]
        g = verdict_groups(rows, at_rest_keys, a)
        today = ""
        if g["rejected"]:
            today += f'<dt class="v-rej-t">rejected on read</dt><dd>{esc(", ".join(g["rejected"]))}</dd>'
        if g["reported"]:
            today += f'<dt class="v-rep-t">reported on audit</dt><dd>{esc(", ".join(g["reported"]))}</dd>'
        if g["accepted"]:
            today += f'<dt class="v-acc-t">accepted</dt><dd>{esc(", ".join(g["accepted"]))}</dd>'
        ed += (f'<article class="xedit" id="{t.lower()}"><h3><span class="tcode">{t}</span> {esc(n)}</h3>'
               f'<p class="story">{esc(e["story"])}</p>'
               f'<figure class="diag diag-x">{explainer(a)}</figure>'
               f'<div class="xcols"><div><h4>What stops it</h4><p>{esc(e["stops"])}</p></div><div><h4>What does not</h4><p>{esc(e["beats"])}</p></div>'
               f'<div><h4>Today, measured {esc(d_date)}</h4><dl class="today">{today}</dl></div></div>'
               f'<p class="repro"><code>agmi-check --adapter agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter   # runs T1 to T8; this is {t}</code></p></article>')
    ed += '<h2>Front door: the attacker can only talk to the agent</h2>' + DIAG_CHANNELS + '<div class="editgrid">'
    for a, n, what, why in FRONT_DOOR:
        g = verdict_groups(rows, fd_keys, a)
        today = ""
        if g["kept out"]:
            today += f'<dt class="v-rej-t">kept out</dt><dd>{esc(", ".join(g["kept out"]))}</dd>'
        if g["surfaced"]:
            today += f'<dt class="v-acc-t">surfaced</dt><dd>{esc(", ".join(g["surfaced"]))}</dd>'
        ed += f'<article class="edit"><h3>{esc(n)}</h3><p>{esc(what)}</p><p class="why">{esc(why)}</p><dl class="today">{today}</dl></article>'
    ed += '</div><p class="note">Every attack carries a version, printed by the runner and stored with each result, so cells from different reports are never compared as if the attack had stood still. Front-door attacks also run as content-evasion mutations: reworded, look-alike glyphs, split across records, diluted with filler. A positive control runs before every verdict: the victim reads back a genuine memory in the same store state, or the cell is not evaluable.</p></section>'
    (OUT / "edits.html").write_text(page("The edits and attacks, Agent Memory Integrity", "Eight storage-level edits and six front-door attacks against AI agent memory: the story, what changes, what the agent reads back, what stops it, and which stores stop it today.", "edits.html", ed, "edits.html"))

    # ---- method
    me = f'''<section class="part"><h1>Method</h1>
<p>The rule that makes every cell a measurement and not an opinion: the verdict is what the tool does, never what we infer. We seed through the tool's own API, apply one edit to the store, restart, and read through the tool's own read path. If it raises or refuses, that is rejected. If its documented audit names the problem, that is reported. If it serves the altered memory and says nothing, that is accepted. We never compare content and call a difference "detected", because the tool did not say anything.</p>
<h2>Two controls before any verdict</h2>
<p>A reload with no edit must still verify, or the cell is n/a; without this a store that cannot reopen its own files would score a perfect pass. And for the front-door attacks, the victim must be able to read back a genuine memory they wrote, in the same store state; without this an empty answer would satisfy "not surfaced".</p>
<h2>The threat models</h2>
{DIAG_THREAT}
<p><b>At rest.</b> The adversary has write access to the medium that holds the store but holds none of the tool's keys: a compromised host, a shared database credential, an injection flaw in a co-located application, a restored backup, a malicious operator. Because the adversary can write anything, an integrity value stored next to the data protects nothing unless it is bound to a secret the adversary does not hold. So the method measures the read path, not the presence of integrity fields.</p>
<p><b>Front door.</b> The adversary can only write through the agent, on one of three channels: external (no label), laundered (a forged first-party label, no key), and agent-laundered (a forged label carrying a valid signature). Provenance alone is never allowed to pass a content cell.</p>
<h2>The IETF mapping</h2>
<p>China Mobile's draft-han-bmwg-agent-security-benchmark-00 defines metric 5.4.7, "Protection of Memory Data Integrity", with no test method. On 24 September 2026 the eight edits T1 to T8, the verdict words, the two control cases and the scoring rule were sent to the BMWG list as proposed text for a new Section 6.6, with the measured verdicts above. agmi is the reference implementation of that text. <a href="https://mailarchive.ietf.org/arch/browse/bmwg/">Archive.</a></p>
<h2>Why T6 and T7 matter more than they look</h2>
<p>Encryption at rest keeps an attacker from reading a record. It does not stop them moving one. A genuine encrypted record copied to another user's slot decrypts and verifies, because as far as the cipher is concerned the bytes are authentic. Only a store that binds a record to its context and its position in the sequence rejects T6 and T7. That is the difference between confidentiality and integrity, and it is where every store measured so far scores zero.</p>
<h2>Self-validation</h2>
<p>A reference at-rest store ships with the suite: an HMAC over content, context, position, previous tag and metadata, plus a signed head pointer. It rejects all eight edits by construction. A test asserts that, so if an edit could not be caught even by a store built to catch it, the edit proves nothing and the suite fails.</p>
</section>'''
    (OUT / "method.html").write_text(page("Method, Agent Memory Integrity", "How each cell is measured: the tool's own verdict, two control cases, the two threat models, and the IETF 5.4.7 mapping.", "method.html", me, "method.html"))

    # ---- findings
    fi = '<section class="part"><h1>Findings</h1><p>What the measurements turned up, newest first. Each one is on the record with a date, and where a vendor thread exists it is linked.</p>'
    for t, dt, body, link in FINDINGS:
        vendor = f'<p><a href="{esc(link)}">Vendor thread</a></p>' if link else ""
        fi += f'<article class="finding"><time>{esc(dt)}</time><h2>{esc(t)}</h2><p>{esc(body)}</p>{vendor}</article>'
    fi += '</section>'
    (OUT / "findings.html").write_text(page("Findings, Agent Memory Integrity", "Dated findings from measuring agent memory stores: cross-context replay, rollback, receipts that do not bind the user, and a vendor fix caught by re-measurement.", "findings.html", fi, "findings.html"))

    # ---- run
    ru = f'''<section class="part"><h1>Run it</h1>
<h2>In your CI, one step</h2>
{DIAG_CI}
<p>The job fails the moment your store serves an edited record as genuine, and the row lands in the Actions summary.</p>
<pre><code>- uses: tech4biz-yasha/agmi@v{VERSION}
  with:
    adapter: agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter
    extras: langgraph</code></pre>
<p>For your own store, write an adapter against <code>agmi.adapters.base.MemoryAdapter</code> (seed, read raw, write raw, delete raw, reload, verify, plus the three optional replay and metadata hooks) and point the action at it with <code>install: "."</code>.</p>
<h2>On a laptop</h2>
<pre><code>pip install "agent-memory-integrity[langgraph]=={VERSION}"
agmi-check --adapter agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter</code></pre>
<p>Exit 1 means at least one edit was accepted, exit 2 means nothing could be evaluated, exit 0 means every edit was rejected or reported. The whole scorecard, all stores, is <code>python agmi/full_runner.py --json results/scorecard.json</code>; Letta needs a Postgres (an embedded one starts if none is set) and Mem0 a local Qdrant, both handled by the adapters.</p>
<h2>Submit a row</h2>
<p>Maintainers of a memory store can open a pull request with an adapter and their measured row. The defended inspeximus rows on the scorecard came in this way from the tool's own maintainer, with the two control cases as tests. Contributions follow <a href="https://github.com/tech4biz-yasha/agmi/blob/main/CONTRIBUTING.md">CONTRIBUTING.md</a>.</p>
</section>'''
    (OUT / "run.html").write_text(page("Run it, Agent Memory Integrity", "Run the eight at-rest edits against your memory store in one CI step, or on a laptop in under a minute.", "run.html", ru, "run.html"))

    # ---- cite
    ci = f'''<section class="part"><h1>Cite</h1>
<p>Cite the concept DOI for the software; it always resolves to the latest version. Cite a version DOI when a specific release matters.</p>
<dl class="cites">
<dt>Software, all versions</dt><dd><a href="https://doi.org/10.5281/zenodo.22860886">10.5281/zenodo.22860886</a></dd>
<dt>Software, v{VERSION}</dt><dd><a href="https://doi.org/10.5281/zenodo.22957647">10.5281/zenodo.22957647</a></dd>
<dt>Method paper (preprint)</dt><dd><a href="https://doi.org/10.5281/zenodo.22765627">10.5281/zenodo.22765627</a>, also SSRN 10.2139/ssrn.7461118</dd>
<dt>Standards</dt><dd>Proposed test method for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7, <a href="https://mailarchive.ietf.org/arch/browse/bmwg/">bmwg list, 24 September 2026</a></dd>
</dl>
<pre><code>Khandelwal, Y. (2026). agmi: Agent Memory Integrity test suite (v{VERSION}).
Zenodo. https://doi.org/10.5281/zenodo.22860886</code></pre>
<p>The repository ships a CITATION.cff, so GitHub's "Cite this repository" gives the same reference in BibTeX or APA.</p>
</section>'''
    (OUT / "cite.html").write_text(page("Cite, Agent Memory Integrity", "How to cite the agmi software, method paper and the IETF 5.4.7 method text.", "cite.html", ci, "cite.html"))


    # ---- architecture
    ar = f'''<section class="part"><h1>Architecture</h1>
<p>Four pictures that explain the suite. If you read nothing else, read the captions.</p>
<h2>How a cell is measured</h2>
{DIAG_PIPELINE}
<h2>Where the attacker stands</h2>
{DIAG_THREAT}
<h2>How the suite is put together</h2>
{DIAG_ARCH}
<h2>What runs in a vendor's CI</h2>
{DIAG_CI}
<h2>Design rules the code enforces</h2>
<ul class="rules">
<li><b>The tool speaks, we do not.</b> A cell is rejected or reported only if the tool raised, refused or named the problem itself. Comparing content and calling a difference "detected" is not allowed anywhere in the code.</li>
<li><b>No verdict without a control.</b> A reload with no edit must verify; a genuine memory must be readable in the same store state. Otherwise the cell is n/a, never a pass.</li>
<li><b>One results file.</b> The README, the scorecard document and this site are rendered from <code>results/scorecard.json</code>. Hand-edited tables cannot exist; CI checks all three against the file on every change.</li>
<li><b>Versions are part of the result.</b> Every row records the library version and every attack carries a version. A row is a statement about one release, and a test fails the day that release changes its answer.</li>
<li><b>Self-validating attacks.</b> A reference at-rest store that binds content, context, position and metadata must reject all eight edits, and a reference defended store must keep out what it is built to keep out. If an attack cannot be caught by a store built to catch it, the suite fails.</li>
<li><b>Fail closed on targets.</b> The memory agent refuses any target the operator does not demonstrably control: library targets only, network hosts only on a host-named token or a consent file.</li>
</ul>
</section>'''
    (OUT / "architecture.html").write_text(page("Architecture, Agent Memory Integrity", "How agmi measures a cell, where the attacker stands, how attacks, adapters, stores and the results file fit together, and what runs in a vendor's CI.", "architecture.html", ar, "architecture.html"))

    # ---- ecosystem
    roadmap = [
        ("0.1 to 0.5", "Attack catalogue, adapter interface, five at-rest edits on LangGraph, Letta and Mem0; inspeximus rows from its maintainer, reproduced independently; preprint, software DOI, PyPI", "done"),
        ("Phase 1", "Three attacker channels (external, laundered, agent-laundered), signed writes, attacker level on every cell", "done"),
        ("Phase 2", "Mutation engine on every attacker write; update poisoning and metadata poisoning; twelve-column front-door scorecard on four real stores", "done"),
        ("Memory agent v1", "Hunt loop over six attacks, three channels and mutations; proof and reproduction script per finding; authorisation gate that fails closed", "done"),
        ("0.6.0", "Eight at-rest edits T1 to T8 with control cases and read/audit detection points, matching the proposed IETF 5.4.7 method; agmi-check and the GitHub Action", "done"),
        ("Phase 3", "Live targets over HTTP (MCP memory servers, deployed LangGraph and Letta) behind the authorisation gate; obedience oracle that proves the agent acted on the poison; ingestion marking measured per framework", "next"),
        ("Phase 4", "Memory agent driving content-only attacks through a real model, same proof discipline", "planned"),
        ("0.9", "Deserialization safety, and a reference integrity layer (a hash chain over checkpoint ids) offered upstream as an optional mode", "planned"),
        ("1.0", "Stable adapter interface, published conformance levels, vendor badges, monthly report cadence; hosted runs through AuditTrax Labs, the open benchmark free", "planned"),
    ]
    by_level = {}
    for k in at_rest_keys:
        by_level.setdefault(level_of(rows[k]), []).append(ROW_NAMES.get(k, (k, ""))[0])
    lv = "".join(f'<tr><th scope="row">{code}</th><td>{esc(nm)}</td><td>{esc(req)}</td><td>{esc(", ".join(by_level.get(code, [])) or "none yet")}</td></tr>' for code, nm, req, _ in LEVELS)
    rm = "".join(f'<tr class="rm-{st}"><th scope="row">{esc(ph)}</th><td>{esc(sc)}</td><td>{esc(st)}</td></tr>' for ph, sc, st in roadmap)
    ec = f'''<section class="part"><h1>Ecosystem</h1>
<p>agmi is built to be the measurement other people's work points at: the standards text, the vendor threads, the maintainer-contributed rows and the assessments all hang off the same results file.</p>
{DIAG_ECO}
<h2>Standards</h2>
<dl class="eco">
<dt>IETF BMWG</dt><dd>China Mobile's draft-han-bmwg-agent-security-benchmark defines metric 5.4.7, Protection of Memory Data Integrity, with no test method. The eight edits, verdict words, control cases and scoring rule were sent to the working group list on 24 September 2026 as proposed text for a new Section 6.6, with measured verdicts. agmi is that method's reference implementation. <a href="https://mailarchive.ietf.org/arch/browse/bmwg/">Archive</a>.</dd>
<dt>OWASP</dt><dd>The front-door attacks map to the agentic security initiative's memory and context poisoning category (ASI06). agmi is offered there as the way to test it.</dd>
</dl>
<h2>Stores measured</h2>
<dl class="eco">
<dt>LangGraph</dt><dd>SqliteSaver and SqliteStore. Issue <a href="https://github.com/langchain-ai/langgraph/issues/9004">#9004</a> (encrypted checkpointer replay) was raised from these measurements; a community fix was verified with the suite and its remaining gap (deletion rollback) is on record.</dd>
<dt>Letta</dt><dd>Block checkpoint history and archival memory.</dd>
<dt>Mem0</dt><dd>Local Qdrant store, at rest and front door.</dd>
<dt>inspeximus</dt><dd>Five rows: default, receipts on (two attacker positions), and two defended trust-root configurations contributed by its maintainer with the control cases as tests. The receipts-on rows carry the T6 finding: a receipt binds text and key, not the owning user.</dd>
</dl>
<h2>Contributors</h2>
<p>Rows come from maintainers as well as from the suite's author. The inspeximus defended rows were submitted by the tool's maintainer, DanceNitra, with the two control cases from the issue thread written as tests, and reproduced independently before publication. That is the pattern for every future vendor row: an adapter, the measured cells, the controls as tests, an independent reproduction.</p>
<h2>Assessments</h2>
<p>The open benchmark is free and stays free. From 1.0, <a href="https://audittraxlabs.com/">AuditTrax Labs</a> offers hosted runs against a vendor's own deployment, conformance levels, and a badge that links back to the public row, so a claim of tamper evidence is a link to a measurement.</p>
<h2>Conformance levels, proposed for 1.0</h2>
<p>A level is a claim a vendor can make and a reader can check against the row it links to. Levels are earned on the read path: a store that only finds the edit on a separate audit call stays at L0 with its cells marked reported. This is the proposed ladder; it is published at 1.0 once two vendors have earned a level above L0.</p>
<div class="matrixwrap"><table class="roadmap levels"><thead><tr><th>Level</th><th>Name</th><th>What it requires</th><th>Rows there today</th></tr></thead><tbody>{lv}</tbody></table></div>
<h2>Roadmap</h2>
<div class="matrixwrap"><table class="roadmap"><thead><tr><th>Phase</th><th>Scope</th><th>Status</th></tr></thead><tbody>{rm}</tbody></table></div>
</section>'''
    (OUT / "ecosystem.html").write_text(page("Ecosystem, Agent Memory Integrity", "The standards text, vendor threads, maintainer-contributed rows, assessments and roadmap around the agmi measurement.", "ecosystem.html", ec, "ecosystem.html"))

    # ---- memory agent
    art = "".join(f'<tr><td>{esc(a)}</td><td>{esc(b)}</td><td>{esc(c)}</td><td>{esc(ch)}</td><td>{esc(m)}</td></tr>' for a, b, c, ch, m in AGENT_RESULTS)
    ag = f"""<section class="part"><h1>The memory agent</h1>
<p class="lede">The scorecard measures a store against fixed attacks. The agent does the opposite: point it at one target and it searches the attacks, channels and mutations for the first that gets a false memory served as trusted, proves each landing, and reports only what it proved, with the exact steps to reproduce.</p>
{DIAG_HUNT}
<h2>What a finding contains</h2>
<ul class="rules">
<li>The attack, the channel and the mutation that landed, with the attack's version.</li>
<li>The positive control: the genuine memory the victim could still read in the same store state. Without it there is no finding.</li>
<li>The text that was served back as trusted, exactly as the read path returned it.</li>
<li>A reproduction script: the writes, the query and the key, so anyone with the same target reaches the same cell.</li>
</ul>
<h2>Measured 24 September 2026, macOS arm64, Python 3.12</h2>
<div class="matrixwrap"><table class="roadmap"><thead><tr><th>Target</th><th>Attempts</th><th>Findings</th><th>Channel of every finding</th><th>Mutation needed</th></tr></thead><tbody>{art}</tbody></table></div>
<p>One attempt per attack means the first base fixture on the honest channel landed; nothing had to be disguised or laundered. The only target that made the agent search is the defended reference store, and the only channel it landed on there is the one no store can close, because the victim's own agent did the writing. Every proven landing is a new fixed row for the scorecard.</p>
<h2>A security tool, not an attack tool</h2>
<p>Two things keep it that way. The authorisation gate runs before any target is touched and fails closed: a library target the caller already holds is allowed, the caller's own loopback is allowed, a network host is allowed only on proven control (an environment token named for that host, or a consent file the operator writes), and anything else raises before the hunt starts. The run records which authorisation it used. And the agent reports only what it proved: no heuristics, no "likely vulnerable", a finding is a served text and a script.</p>
<h2>Run it</h2>
<pre><code>pip install agent-memory-integrity
python -m agmi.agent --target defended                 # a library target
python -m agmi.agent --target mem0 --embedder minilm --json</code></pre>
<p>Phase 3 puts live targets behind the same gate (MCP memory servers, deployed LangGraph and Letta) and adds an obedience oracle that proves the agent acted on the poison, not only that it was served.</p>
</section>"""
    (OUT / "agent.html").write_text(page("The memory agent, Agent Memory Integrity", "agmi's memory agent hunts attacks, channels and mutations for the first that lands, proves it against a positive control, and reports only what it proved, behind an authorisation gate that fails closed.", "agent.html", ag, "agent.html"))

    # ---- about
    ab = '''<section class="part"><h1>About</h1>
<p>agmi is built and maintained by <a href="https://yashakhandelwal.com/">Yasha Khandelwal</a>, a principal architect with twenty years in enterprise systems, previously at Cisco, Google and SpaceX, now co-founder and CEO of Tech4Biz Solutions in Bengaluru. Contact <a href="mailto:yasha.khandelwal@tech4biz.io">yasha.khandelwal@tech4biz.io</a>; <a href="https://orcid.org/0009-0005-2166-4951">ORCID 0009-0005-2166-4951</a>; <a href="https://github.com/tech4biz-yasha">GitHub</a>.</p>
<h2>Why this exists</h2>
<p>Agents are being given memory that outlives a session, and that memory is being trusted as if it were the agent's own experience. Nobody was measuring whether the stores holding it notice when it is changed. The first measurement, in September 2026, showed that none of the popular stores do. This site keeps that measurement current, in public, in a form a vendor can reproduce and a standards body can cite.</p>
<h2>How it is funded</h2>
<p>The suite, the scorecard and this site are open source under MIT and are not funded by any of the vendors measured. Hosted assessments and vendor badges are offered through <a href="https://audittraxlabs.com/">AuditTrax Labs</a>, a technical due-diligence firm, from version 1.0. Vendor rows on the public scorecard are never paid for and are reproduced independently before publication.</p>
<h2>Independence rules</h2>
<ul class="rules">
<li>A vendor cannot change a published cell. Only a re-measurement on a new version can, and the old row stays in the history.</li>
<li>Maintainer-contributed rows are labelled as such and reproduced by the suite's author before they appear.</li>
<li>Findings are raised with the vendor on their own tracker before they are written up here, and the thread is linked.</li>
</ul>
</section>'''
    (OUT / "about.html").write_text(page("About, Agent Memory Integrity", "Who builds agmi, why it exists, how it is funded, and the independence rules for published rows.", "about.html", ab, "about.html"))

    # ---- css, js, llms.txt, sitemap, robots
    (OUT / "site.css").write_text(CSS)
    (OUT / "site.js").write_text(JS)
    (OUT / "llms.txt").write_text(f"""# Agent Memory Integrity (agmi)
> A conformance test suite that measures whether AI agent memory and checkpoint stores notice when they are tampered with.

Version {VERSION}, measured {d_date}. Source: https://github.com/tech4biz-yasha/agmi
Method text proposed for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7.

## At rest (eight storage-level edits, attacker has store access, no keys)
""" + "\n".join(f"- {ROW_NAMES.get(k,(k,''))[0]} ({ROW_NAMES.get(k,(k,''))[1]}): " + ", ".join(f"{t} {rows[k]['cells'][a]['verdict']}" for a,t,*_ in AT_REST) for k in at_rest_keys) + """

## Front door (six attacks through the tool's own write path)
""" + "\n".join(f"- {ROW_NAMES.get(k,(k,''))[0]}: " + ", ".join(f"{n} {rows[k]['cells'][a]['verdict']}" for a,n,*_ in FRONT_DOOR) for k in fd_keys) + f"""

## Pages
- {SITE}/scorecard.html
- {SITE}/edits.html
- {SITE}/method.html
- {SITE}/findings.html
- {SITE}/run.html
- {SITE}/cite.html
- {SITE}/architecture.html
- {SITE}/agent.html
- {SITE}/ecosystem.html
- {SITE}/about.html

## Author
Yasha Khandelwal, https://yashakhandelwal.com/, yasha.khandelwal@tech4biz.io. Hosted assessments: https://audittraxlabs.com/
""")
    pages = ["", "scorecard.html", "edits.html", "architecture.html", "method.html", "agent.html", "findings.html", "ecosystem.html", "run.html", "cite.html", "about.html"]
    (OUT / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + "".join(f"<url><loc>{SITE}/{p}</loc><lastmod>{d_date}</lastmod></url>" for p in pages) + "</urlset>\n")
    (OUT / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE}/sitemap.xml\n")
    return OUT

CSS = r"""
:root{--paper:#F7F8F6;--ink:#14212B;--ink2:#3F4C57;--line:#D9DED9;--teal:#0F4C5C;--teal2:#0B3A47;
--acc:#B3261E;--accbg:#FBE9E7;--rej:#2E7D5B;--rejbg:#E6F2EC;--rep:#B26A00;--repbg:#FBF0DC;--na:#8A9199;--nabg:#EFF1F1;
--max:1120px;--sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"IBM Plex Mono",ui-monospace,Menlo,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--paper:#0F1518;--ink:#E8EDEA;--ink2:#A9B4B0;--line:#26302E;--teal:#5FB3C3;--teal2:#8BD0DB;--accbg:#3A1A17;--rejbg:#15302A;--repbg:#3A2A0F;--nabg:#1C2426}}
*{box-sizing:border-box}html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--paper);color:var(--ink);font:400 17px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--teal);text-decoration-thickness:1px;text-underline-offset:3px}a:hover{color:var(--teal2)}
.skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--ink);color:var(--paper);padding:8px 12px;z-index:9}
.top{display:flex;align-items:center;gap:24px;max-width:var(--max);margin:0 auto;padding:18px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:color-mix(in srgb,var(--paper) 92%,transparent);backdrop-filter:blur(8px);z-index:5}
.brand{display:flex;align-items:center;gap:10px;color:var(--ink);text-decoration:none;font-weight:600;white-space:nowrap}
.nav{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto}.nav a{color:var(--ink2);text-decoration:none;padding:6px 8px;border-radius:6px;font-size:15px}
.nav a:hover{background:var(--nabg);color:var(--ink)}.nav a[aria-current=page]{color:var(--ink);background:var(--nabg)}
.gh{color:var(--ink2);text-decoration:none;padding:6px 10px;border:1px solid var(--line);border-radius:6px;white-space:nowrap}
main{max-width:var(--max);margin:0 auto;padding:0 20px}
h1{font-size:clamp(30px,4.6vw,46px);line-height:1.12;letter-spacing:-.015em;font-weight:600;margin:.2em 0 .4em}
h2{font-size:clamp(22px,2.6vw,28px);line-height:1.2;font-weight:600;margin:1.8em 0 .5em;letter-spacing:-.01em}
h3{font-size:19px;margin:0 0 .4em;font-weight:600}
p{max-width:68ch}em{font-style:normal;font-weight:600}
.hero{display:grid;grid-template-columns:1.05fr 1fr;gap:48px;align-items:center;padding:56px 0 24px}
.lede{color:var(--ink2);font-size:19px;margin:0}.sub{color:var(--ink2);font-size:18px}
.cta{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn,.btn-quiet{display:inline-block;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:600}
.btn{background:var(--teal);color:#fff}.btn:hover{background:var(--teal2);color:#fff}.btn-quiet{border:1px solid var(--line);color:var(--ink)}
.hero-fig{margin:0}.hero-fig svg{width:100%;height:auto;display:block}.hero-fig figcaption{color:var(--ink2);font-size:15px;margin-top:10px;max-width:60ch}
.lbl{font:500 13px var(--sans);fill:var(--ink2)}.rt{font:500 15px var(--mono);fill:var(--ink);text-anchor:middle}
.rec{fill:none;stroke:var(--ink2);stroke-width:1.5}.rec-donor{stroke:var(--teal);stroke-width:2}
.rec-victim{stroke:var(--ink2);stroke-dasharray:4 3}.arrow{fill:none;stroke:var(--teal);stroke-width:2;stroke-dasharray:6 4;stroke-linecap:round}
.readbox{fill:none;stroke:var(--line);stroke-width:1.5}.verdict{font:600 15px var(--mono);fill:var(--acc)}.readval{text-anchor:start}
.rec-moved{fill:var(--paper);stroke:var(--teal);stroke-width:2;opacity:0;transform:translateY(-120px)}
.rt-moved{opacity:0;transform:translateY(-120px)}.rt-victim{opacity:1}.read{opacity:0}.arrow2{opacity:0}
@media (prefers-reduced-motion:no-preference){
.rec-moved,.rt-moved{animation:drop 1.1s cubic-bezier(.2,.8,.2,1) 1.2s forwards}
.rt-victim{animation:fadeout .4s 1.9s forwards}.read,.arrow2{animation:fadein .6s 2.6s forwards}
@keyframes drop{to{opacity:1;transform:translateY(0)}}@keyframes fadeout{to{opacity:0}}@keyframes fadein{to{opacity:1}}}
@media (prefers-reduced-motion:reduce){.rec-moved,.rt-moved,.read,.arrow2{opacity:1;transform:none}.rt-victim{opacity:0}}
.howto{padding:24px 0 8px;border-top:1px solid var(--line)}
.routes{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.routes a{display:block;padding:18px;border:1px solid var(--line);border-radius:10px;color:var(--ink);text-decoration:none;line-height:1.45}
.routes a:hover{border-color:var(--teal)}.routes strong{display:block;margin-bottom:6px;color:var(--teal)}
.part{padding:12px 0 24px}.note{color:var(--ink2);font-size:15.5px}
.matrixwrap{overflow-x:auto;margin:18px 0;border:1px solid var(--line);border-radius:10px}
.matrix{border-collapse:separate;border-spacing:0;width:100%;min-width:640px;font-size:14.5px}
.matrix th,.matrix td{padding:0;border-bottom:1px solid var(--line)}
.matrix thead th{background:var(--nabg);font-weight:500;text-align:center;padding:10px 6px;color:var(--ink2);position:sticky;top:0}
.matrix thead th.corner{text-align:left;padding-left:14px}.matrix abbr{text-decoration:none;border:0;cursor:help}
.matrix tbody th{text-align:left;padding:10px 14px;font-weight:500;max-width:320px;background:var(--paper);position:sticky;left:0}
.rowname{display:block}.rowver{display:block;color:var(--ink2);font-size:12.5px;font-family:var(--mono);margin-top:2px}
.matrix td{text-align:center}.cellbtn{all:unset;display:block;width:100%;padding:10px 6px;cursor:pointer;font:500 13.5px var(--mono);text-align:center}
.cellbtn:focus-visible{outline:2px solid var(--teal);outline-offset:-2px}
.v-acc .cellbtn{color:var(--acc);background:var(--accbg)}.v-rej .cellbtn{color:var(--rej);background:var(--rejbg)}
.v-rep .cellbtn{color:var(--rep);background:var(--repbg)}.v-na span{display:block;padding:10px 6px;color:var(--na);background:var(--nabg);font:400 13.5px var(--mono)}
.legend{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:15px;max-width:76ch}
.legend dt{font:500 13.5px var(--mono);padding:2px 8px;border-radius:4px;align-self:start}
.legend dt.v-acc{color:var(--acc);background:var(--accbg)}.legend dt.v-rej{color:var(--rej);background:var(--rejbg)}
.legend dt.v-rep{color:var(--rep);background:var(--repbg)}.legend dt.v-na{color:var(--na);background:var(--nabg)}.legend dd{margin:0}
.findlist{list-style:none;padding:0;margin:0}.findlist li{display:grid;grid-template-columns:110px 1fr;gap:16px;padding:10px 0;border-bottom:1px solid var(--line)}
time{color:var(--ink2);font-family:var(--mono);font-size:13.5px}
.target{border-bottom:1px solid var(--line);padding:10px 0}.target summary{cursor:pointer;display:flex;gap:16px;align-items:baseline;font-weight:500}
.target .mo{color:var(--ink2);font-size:14px}.target ul{font-size:15px}
.editgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;margin:12px 0}
.edit{border:1px solid var(--line);border-radius:10px;padding:18px}.edit p{font-size:15.5px}.why{color:var(--ink2)}
.pict{width:100%;height:auto;margin:6px 0 10px}.pb{fill:none;stroke:var(--ink2);stroke-width:1.5}
.pb-x{stroke:var(--acc);fill:var(--accbg)}.pb-gone{stroke:var(--acc);stroke-dasharray:3 3;fill:none;opacity:.55}.pb-swap{stroke:var(--teal);stroke-width:2}.pb-src{stroke:var(--teal);stroke-width:2;stroke-dasharray:3 3}.pb-moved{stroke:var(--teal);stroke-width:2;fill:var(--paper)}
.parrow{fill:none;stroke:var(--teal);stroke-width:1.5;stroke-dasharray:4 3}.ptiny{font:500 9px var(--sans);fill:var(--teal);text-anchor:middle}
.finding{padding:18px 0;border-bottom:1px solid var(--line)}.finding h2{margin:.2em 0 .4em}
pre{background:var(--nabg);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow-x:auto;font:400 14px/1.5 var(--mono)}
code{font-family:var(--mono);font-size:.93em}
.cites{display:grid;grid-template-columns:auto 1fr;gap:8px 18px}.cites dd{margin:0}
.diag{margin:18px 0 28px}.diag svg{width:100%;height:auto;display:block;background:var(--nabg);border:1px solid var(--line);border-radius:12px;padding:10px}
.diag figcaption{color:var(--ink2);font-size:15px;margin-top:10px;max-width:76ch}
.box{fill:var(--paper);stroke:var(--ink2);stroke-width:1.4}.box-agent{stroke:var(--teal);stroke-width:2}.box-attack{stroke:var(--acc);stroke-dasharray:5 4}
.box-store{fill:color-mix(in srgb,var(--teal) 8%,var(--paper))}.box-verdict{stroke:var(--teal);stroke-width:2}.box-rej{stroke:var(--rej)}.box-acc{stroke:var(--acc)}
.chip{fill:var(--paper);stroke:var(--line)}.chip-ref{stroke-dasharray:4 3}
.bt{font:600 14.5px var(--sans);fill:var(--ink);text-anchor:middle}.bs{font:400 12.5px var(--sans);fill:var(--ink2);text-anchor:middle}
.bn{font:400 12.5px var(--sans);fill:var(--ink2);text-anchor:middle}.bv{font:500 13.5px var(--mono);text-anchor:middle}
.v-rej-t{fill:var(--rej)}.v-rep-t{fill:var(--rep)}.v-acc-t{fill:var(--acc)}
.flow{fill:none;stroke:var(--ink2);stroke-width:1.5}.ahead{fill:var(--ink2)}
.rec-x{stroke:var(--acc);fill:var(--accbg)}.tag{font:500 12.5px var(--sans);text-anchor:middle}.tag-acc{fill:var(--acc)}.tag-teal{fill:var(--teal)}
.rules{padding-left:20px}.rules li{margin:8px 0;max-width:76ch}
.eco{display:grid;grid-template-columns:130px 1fr;gap:10px 18px}.eco dt{font-weight:600}.eco dd{margin:0;max-width:76ch}
.roadmap{width:100%;border-collapse:collapse;font-size:15px}.roadmap th,.roadmap td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.roadmap thead th{background:var(--nabg);color:var(--ink2);font-weight:500}.roadmap tbody th{font-weight:600;white-space:nowrap}
.rm-done td:last-child{color:var(--rej)}.rm-next td:last-child{color:var(--teal);font-weight:600}.rm-planned td:last-child{color:var(--ink2)}
@media (max-width:820px){.eco{grid-template-columns:1fr}}
.lede{font-size:19px;line-height:1.5;max-width:72ch;color:var(--ink)}
.legend{display:flex;flex-wrap:wrap;gap:8px 20px;font-size:14px;color:var(--ink2);margin:12px 0 4px}.legend span{display:inline-flex;align-items:center;gap:8px}
.lg{display:inline-block;width:22px;height:14px;border-radius:3px;border:1.5px solid var(--ink2);background:var(--paper)}
.lg-x{border-color:var(--acc);background:repeating-linear-gradient(45deg,var(--accbg) 0 3px,var(--paper) 3px 6px)}.lg-g{border-style:dashed;opacity:.45}.lg-m{border-color:var(--teal);background:color-mix(in srgb,var(--teal) 16%,var(--paper))}.lg-a{border-color:var(--acc);border-style:dashed;background:var(--accbg)}
.rec{fill:var(--paper);stroke:var(--ink2);stroke-width:1.4}.rec-x{stroke:var(--acc);fill:var(--accbg)}.rec-gone{stroke-dasharray:4 3;opacity:.4}.rec-moved{stroke:var(--teal);stroke-width:2;fill:color-mix(in srgb,var(--teal) 16%,var(--paper))}.rec-att{stroke:var(--acc);stroke-dasharray:4 3;fill:var(--accbg)}
.rt{font:500 12px var(--mono);fill:var(--ink);text-anchor:middle}
.pbox{fill:var(--paper);stroke:var(--line);stroke-width:1.2}.pbox-read{stroke:var(--teal);stroke-width:1.6}.pt{font:600 13.5px var(--sans);fill:var(--ink)}
.xedit{padding:26px 0;border-top:1px solid var(--line)}.xedit h3{font-size:24px;margin:0 0 8px}.tcode{font:600 15px var(--mono);color:var(--teal);margin-right:10px;vertical-align:middle}
.story{font-size:17px;max-width:76ch;margin:0 0 6px}.diag-x{margin:12px 0 16px}.diag-x svg{padding:6px}
.xcols{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px}.xcols h4{margin:0 0 6px;font-size:14px;color:var(--ink2);font-weight:500}.xcols p{margin:0;font-size:15px}
.today{margin:0;font-size:14.5px}.today dt{font:500 13px var(--mono);margin-top:4px}.today dd{margin:0 0 4px}
.repro{margin:14px 0 0}.repro code{font-size:13px}
.edit .today{margin-top:8px}
@media (max-width:820px){.xcols{grid-template-columns:1fr}}
/* motion: figures animate in reading order when scrolled into view */
.diag{position:relative}.diag .replay{position:absolute;top:10px;right:10px;font:500 12px var(--mono);color:var(--ink2);background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:3px 8px;cursor:pointer;opacity:0;transition:opacity .2s}.diag:hover .replay,.diag:focus-within .replay{opacity:1}
@media (prefers-reduced-motion:no-preference){
.diag.arm .step,.diag.arm .xp,.diag.arm .tag,.diag.arm .rec-x,.diag.arm .rec-att,.diag.arm .rec-moved,.diag.arm .rec-gone,.diag.arm .parrow{opacity:0}
.diag.arm .flow{stroke-dasharray:600;stroke-dashoffset:600}
.diag.play .step,.diag.play .xp{animation:rise .5s ease-out forwards}
.diag.play .flow{animation:draw .6s ease-out forwards}
.diag.play .tag,.diag.play .rec-x,.diag.play .rec-att,.diag.play .rec-moved,.diag.play .rec-gone,.diag.play .parrow{animation:rise .45s ease-out forwards}
.diag.play .step:nth-of-type(1),.diag.play .xp:nth-of-type(1){animation-delay:.05s}.diag.play .step:nth-of-type(2),.diag.play .xp:nth-of-type(2){animation-delay:.55s}.diag.play .step:nth-of-type(3),.diag.play .xp:nth-of-type(3){animation-delay:1.05s}.diag.play .step:nth-of-type(4){animation-delay:1.55s}.diag.play .step:nth-of-type(5){animation-delay:2.05s}.diag.play .step:nth-of-type(6){animation-delay:2.55s}
.diag.play .flow:nth-of-type(1){animation-delay:.35s}.diag.play .flow:nth-of-type(2){animation-delay:.85s}.diag.play .flow:nth-of-type(3){animation-delay:1.35s}.diag.play .flow:nth-of-type(4){animation-delay:1.85s}.diag.play .flow:nth-of-type(5){animation-delay:2.35s}.diag.play .flow:nth-of-type(6){animation-delay:2.85s}.diag.play .flow:nth-of-type(n+7){animation-delay:3.1s}
.diag.play .rec-x,.diag.play .rec-att,.diag.play .rec-moved,.diag.play .rec-gone{animation-delay:.9s}.diag.play .tag,.diag.play .parrow{animation-delay:1.1s}
.diag.play .tag:nth-of-type(n+3){animation-delay:1.8s}.diag.play .tag:nth-of-type(n+6){animation-delay:2.5s}
}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes draw{to{stroke-dashoffset:0}}
.foot{max-width:var(--max);margin:40px auto 0;padding:24px 20px 40px;border-top:1px solid var(--line);color:var(--ink2);font-size:14.5px}
.drawer[hidden]{display:none}.drawer{position:fixed;inset:0;background:rgba(10,20,25,.45);display:grid;place-items:end center;z-index:20;padding:0 0 env(safe-area-inset-bottom,0px)}
.drawer-card{background:var(--paper);color:var(--ink);width:min(720px,100%);border-radius:14px 14px 0 0;padding:22px 24px 28px;position:relative;box-shadow:0 -8px 40px rgba(0,0,0,.2)}
.drawer-close{position:absolute;right:14px;top:10px;font-size:26px;background:none;border:0;color:var(--ink2);cursor:pointer}
.drawer-kicker{color:var(--ink2);margin:0;font-size:14px}.drawer h2{margin:.2em 0 .4em;font-size:22px}
.drawer-verdict{font:600 15px var(--mono);margin:0 0 12px}.drawer-verdict.v-acc{color:var(--acc)}.drawer-verdict.v-rej{color:var(--rej)}.drawer-verdict.v-rep{color:var(--rep)}.drawer dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;font-size:15px}
.drawer dt{color:var(--ink2)}.drawer dd{margin:0}.drawer code{background:var(--nabg);padding:4px 8px;border-radius:6px;display:inline-block;word-break:break-all}
@media (max-width:820px){.hero{grid-template-columns:1fr;gap:28px;padding-top:32px}.routes,.editgrid{grid-template-columns:1fr}
.findlist li{grid-template-columns:1fr}.nav{order:3;width:100%;margin-left:0}.top{flex-wrap:wrap;gap:10px}}
"""

JS = r"""
(function(){
  if(!window.matchMedia||!window.matchMedia('(prefers-reduced-motion: no-preference)').matches)return;
  var figs=document.querySelectorAll('.diag');if(!figs.length||!('IntersectionObserver' in window))return;
  figs.forEach(function(f){f.classList.add('arm');var b=document.createElement('button');b.type='button';b.className='replay';b.textContent='replay';b.setAttribute('aria-label','replay the animation');
    b.addEventListener('click',function(){f.classList.remove('play');void f.offsetWidth;f.classList.add('play')});f.appendChild(b)});
  var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('play');io.unobserve(e.target)}})},{threshold:.35});
  figs.forEach(function(f){io.observe(f)});
})();
(function(){
  var drawer=document.getElementById('drawer');if(!drawer)return;
  var q=function(id){return document.getElementById(id)};
  var names={};document.querySelectorAll('.matrix tbody th').forEach(function(th){});
  function open(btn){
    var row=btn.dataset.row,att=btn.dataset.attack,v=btn.dataset.verdict;
    var th=btn.closest('tr').querySelector('th');
    q('dkick').textContent=th.querySelector('.rowver')?th.querySelector('.rowver').textContent:'';
    q('dtitle').textContent=(th.querySelector('.rowname')?th.querySelector('.rowname').textContent:row)+', '+(btn.dataset.name||att);
    q('dverdict').textContent=v;q('dverdict').className='drawer-verdict '+({accepted:'v-acc',surfaced:'v-acc',rejected:'v-rej','kept out':'v-rej',reported:'v-rep'}[v]||'v-na');
    q('ddetail').textContent=btn.dataset.detail||'(no detail recorded)';
    q('dpoint').textContent=btn.dataset.point?(btn.dataset.point==='audit'?'audit: a separate call the operator has to make':'read: the read path itself'):'front door, read path';
    q('drepro').textContent='python agmi/full_runner.py --json results/scorecard.json   # row '+row+', attack '+att;
    drawer.hidden=false;drawer.querySelector('.drawer-close').focus();
  }
  function close(){drawer.hidden=true}
  document.addEventListener('click',function(e){
    var b=e.target.closest('.cellbtn');if(b){open(b);return}
    if(e.target.closest('.drawer-close')||e.target===drawer)close();
  });
  document.addEventListener('keydown',function(e){if(e.key==='Escape')close()});
})();
"""

if __name__ == "__main__":
    check = "--check" in sys.argv
    if check:
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        old = OUT
        globals()["OUT"] = tmp
        build()
        diff = [f for f in os.listdir(tmp)
                if not (old / f).exists() or (old / f).read_bytes() != (tmp / f).read_bytes()]
        if diff:
            print("docs/site is stale:", ", ".join(sorted(diff)))
            sys.exit(1)
        print("docs/site matches results/scorecard.json")
        sys.exit(0)
    out = build()
    print("wrote", out, "(", len(list(out.iterdir())), "files )")
