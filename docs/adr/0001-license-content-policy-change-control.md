# ADR-001 — License, content policy and change control

| Field | Value |
|---|---|
| Status | **Accepted** — 2026-09-20. Sign-off = the operator's merge of the PR that introduces this file. |
| Related | ADR-002 (packaging), ADR-003 (browser payload), ADR-004 (offline) |

> Not legal advice. This ADR records engineering decisions and the reasoning behind them.

---

## Context

- `matsurvey` turns a robot-competition mat PDF that the user supplies into mm-exact geometry.
  Mats, rules documents and their artwork belong to third parties. Their names, programmes,
  themes and sponsors are protected marks.
- The pipeline depends on PyMuPDF. `MEASURED(PyPI, 2026-09-19)`: `pymupdf==1.28.0` declares
  `License: Dual Licensed - GNU AFFERO GPL 3.0 or Artifex Commercial License`; its wheel's only
  license file is a one-line `COPYING` with no license text and no "only" / "or later" qualifier.
- Protected content can leak through channels other than `git add`: the Docker build context,
  wheels and sdists, CI logs, issue attachments, PR titles and bodies, README screenshots.

## Decision

### 1. License

| Item | Decision |
|---|---|
| Code | **AGPL-3.0-or-later**. Compatible with PyMuPDF as long as version 3 is permitted; lets future AGPL versions apply without relicensing. |
| `LICENSE` | unmodified text from gnu.org. Because the PyMuPDF wheel ships no license text, this file is also the copy of the AGPL that accompanies PyMuPDF inside the image. |
| `NOTICE` | generated from installed package metadata by `scripts/check_licenses.py`; never hand-edited |
| Source offer | the web UI will expose `/about` with version, commit and source URL (AGPLv3 §13) |

Why not a permissive license: permissive code can be combined into an AGPL work, but the
distributed image is governed by AGPL through PyMuPDF anyway, and a closed hosted fork of this
code would become permitted.

### 2. No third-party references

The repository — every file, path, commit message, branch and tag name, PR title and body,
issue template, release note, repository description and topic, and CI log — contains **no
reference** to any competition, its organiser, programmes, categories, seasons, themes or
sponsors, and no toy or hardware brand.

**Allowed:** names of open-source software this project uses or evaluates (libraries,
frameworks, tools), in code, dependency files, `NOTICE` and technical documents. Naming a
library is not a reference to protected content.

### 3. Content classes

| Class | Examples | In the repository |
|---|---|---|
| C0 Source documents | mat PDFs, rules documents, building instructions, Q&A pages | never |
| C1 Derived pixels | renders, tiles, crops, screenshots of the viewer showing a real mat | never — README and docs use synthetic mats only |
| C2 Derived data | geometry, coordinates, colours, palettes, sensor models, measured sizes, counts, byte lengths, output hashes of a real mat | never |
| C3 Rules text | verbatim or near-verbatim passages, scoring tables, area or object names taken from rules | never |
| C4 Output fingerprints | sha256 of pipeline outputs for a real source | **local only** — byte-identity is verified on the user's machine |
| C5 Area labels | `region_id → area_id` for a real mat | **user-local only**, exported and imported as files outside this repository |
| C6 Season facts | nominal mat size, placement rules, border policies | never — the nominal size is a **user-supplied profile**; the code has no default mat size |
| C7 Synthetic | generator code and ground-truth definitions | code only; PDFs are generated at test time |
| C8 Guard lists | salted hashes of protected terms, values, files and text shingles | yes — hashes only (§5) |

### 4. Area labels and region IDs

`region_id = hash(quantised colour, bbox rounded to 1 mm)` is an identifier, **not a secrecy
mechanism**. For a known palette colour, the bbox search space is C(W+1, 2) · C(H+1, 2) for a
W × H mm mat — about 10¹² for a 2000 × 1000 mm example — so a label file can be reversed to
bboxes and quantised colours. That is one more reason labels stay user-local.

### 5. Enforcement

| Layer | Where | Catches | Misses |
|---|---|---|---|
| `.gitignore` | client | accidental `git add .` of `data/` | explicit adds |
| `content-guard` via `pre-commit`, `commit-msg`, `pre-push` hooks | client | PDFs and known binary formats by magic bytes; non-UTF-8 content; blocked basenames; oversized files; embedded base64; protected terms (R7), values (R8), files (R9), copied text (R10); missing SPDX headers (R11) | `--no-verify`; clones without hooks installed |
| `guard` CI job, required by the ruleset | server | the same rules over the PR range, full tree and full history; PR title, body and branch name, re-checked on every edit. On PRs, the guard and lists are taken from the **base branch**. | a PR that edits the workflow file controls the job that judges it (§7) |
| `.dockerignore` allowlist | build | Docker's build context ignores `.gitignore`; `COPY . .` would otherwise ship local `data/` into a public image | files inside allowlisted directories |
| Image and wheel scans in release jobs | server | anything that reached a published artifact | — |
| Issue and PR templates | human | attachments and pasted rules text | — |

Guard lists hold **salted hashes**, so the repository never contains a protected term in
plaintext. Hashing is obfuscation, not secrecy: short terms can be recovered by brute force.
The goal is that nothing protected appears or reads in the repository, and that goal is met.
Plaintext sources for the lists live only on the operator's machine.

### 6. Third-party code intake

| License of the source | Rule |
|---|---|
| MIT / BSD / Apache-2.0 | code may be adapted with attribution; bundled assets (images, mats, fonts) never |
| GPL-3.0 | legally combinable with AGPL-3.0 (GPLv3 §13), but **policy: no copying** — clean-room only, to keep provenance simple. This is a policy choice, not a license incompatibility. |
| unknown / none | reference only |
| web pages, Q&A sites, documentation examples | never pasted; write the code |

### 7. Change control

| Rule | Mechanism |
|---|---|
| All changes reach `main` through a PR | ruleset: `pull_request`, `required_status_checks` (`guard`, `tests`, `licenses`, strict), `non_fast_forward`, `deletion`; no bypass actors |
| Squash merge with PR title, blank body | `squash_merge_commit_title = PR_TITLE`, `squash_merge_commit_message = BLANK` |
| Merge-dialog text is never edited | that text is not checked before it lands on `main`, and `main` cannot be rewritten — documented in `CONTRIBUTING.md` |
| Guard-critical PRs are verified outside CI | paths: `.github/workflows/`, `.githooks/`, `scripts/content_guard.py`, `scripts/build_denylist.py`, `guard/`. A green `guard` check is not evidence for such a PR; the maintainer runs the guard from `main` against the PR head locally. |
| Contributor terms: **DCO** | every PR commit carries `Signed-off-by:`. Squash merge keeps only the PR title on `main`; the sign-off record lives in the PR's commits, which GitHub retains. Enforcement check: follow-up change. |
| Two-person rule for agent work | the coding agent works under a **separate machine account** with Write (not Admin) role and its own token; the operator's token is removed from the agent's machine; the ruleset requires **1 approval**. The agent cannot approve its own PRs, so every agent change needs the operator. The rare operator-authored PR uses a ruleset bypass limited to the Admin role in pull-request mode. Required before any code is ported from the predecessor project. |
| History | the repository started from a fresh `git init`. Files from the predecessor project are copied, never its history — a filtered history is still derived from one that contained C1–C3. |

---

## Consequences

| + | − |
|---|---|
| The repository can be public with no exposure from third-party content | Users cannot discover the project by searching for the competition's name |
| One license story across code, image and wheel | AGPL deters some commercial integrators — intended |
| Leak channels are closed mechanically, not by reviewer memory | Labels and season facts cannot be shared through this repository |
| Mat size, placement and labels are user data, so the tool stays season-agnostic | First use needs a profile and labelling work from the user |
| The two-person rule is enforced by GitHub, not by instructions to the agent | The operator's approval is on the path of every agent PR |
