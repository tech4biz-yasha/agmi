# Design guide for agentmemoryintegrity.org

The site has one job: make a reader who has never thought about agent memory
understand the problem, see the measurement, and trust the numbers, in one
sitting. It is the reference for the subject, not a project page.

## Reference sites studied

| Site | What it owns | What we take |
|---|---|---|
| slsa.dev | Supply-chain integrity levels | One threat diagram with lettered attack points, reused on every page; levels a vendor can claim; spec and "get started" kept apart |
| attack.mitre.org | Adversary technique catalogue | The matrix as the home of the subject; every technique has its own page with a fixed structure |
| securityscorecards.dev (OpenSSF) | Repo health checks | One check, one page: what it measures, why, how to pass, the exact command |
| ssllabs.com | TLS grades | A grade a vendor can put on a slide, with the row it links back to |
| sigstore.dev | Signing ecosystem | The ecosystem drawn as one picture, tools around a centre |

## Rules

1. Every explanation page follows one shape: a one-line answer, then the picture, then the walk-through, then what it means for the reader, then the command that reproduces it.
2. Diagrams are SVG built from data or hand-drawn in the generator, never bitmaps. They animate in sequence when they scroll into view, in the order a reader should look, and they stand still and complete when motion is off.
3. The same visual vocabulary everywhere: solid box for a genuine record, red cross-hatch for changed bytes, dashed and faded for removed, teal for genuine bytes moved, red dashed for attacker-authored. A reader learns it on the Edits page and reuses it on every other page.
4. Every explanation shows today's measured rows for the thing it explains, pulled from the results file, so the explanation is never stale and never marketing.
5. Plain spoken English. No symbol chips, no tinted alternating blocks, no headings shaped as "X, not Y".
6. Nothing is claimed that the results file does not show. Levels not yet published are marked proposed.
7. Colour: paper F7F8F6, ink 14212B, teal 0F4C5C; accepted red, rejected green, reported amber. Dark mode inverts paper and ink only.
8. Type: IBM Plex Sans for reading, IBM Plex Mono for verdicts, ids and commands.
