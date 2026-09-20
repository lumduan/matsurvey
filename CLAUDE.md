# Working rules for coding agents

These rules apply to every agent session in this repository. Task prompts may add rules; they
relax a rule only through a one-time grant (see the last section).

## Communication

- **English only** — in chat with the operator and on GitHub: commit messages, PR titles and
  bodies, review comments, issues, reports.
- Text in another language appears only when quoting a source exactly as it exists: a URL, a
  document title, a file name. Quote it verbatim; do not translate or transliterate it.

## Evidence

- Every claim in a report carries the command that was run and the tail of its raw output.
- Tag each fact: **VERIFIED** (run in this task) · **HISTORY** (earlier context only) ·
  **UNKNOWN** (no evidence). Never present HISTORY or UNKNOWN as fact.
- When a tool lacks a feature, write "not available in this version". Do not assert how other
  versions behave.

## Control

- A failed precondition or STOP condition ends the run. No substitute mechanism without the
  operator's explicit approval.
- End every task with a report and **HALT**.
- Never merge, approve, label, or change repository settings or rulesets, unless a one-time
  grant covers exactly that action.
- Never push to `main`; every change goes branch → PR.
- `gh api` with `-f` / `-F` sends a POST unless `-X GET` is given.

## Content policy — ADR-001

- Never commit, and never write inside this working tree: official source documents, anything
  derived from them, rules text, or any reference to a competition, its organiser, programmes,
  themes or sponsors, or to toy and hardware brands. Open-source software names are allowed.
- Plaintext guard sources and all scratch work live outside the repository (`$MATSURVEY_LOCAL`,
  `~/.config/matsurvey/`).
- Never put a protected term in a PR title, body or comment, not even to test the guard: GitHub
  keeps edit history public. Negative tests run locally.
- Never `--no-verify`, never change `core.hooksPath`, never edit hooks to get a commit through.
  If the guard blocks, stop and report — do not reword protected content to slip past it.
- Commits carry a DCO sign-off (`git commit -s`).

## Guard-critical paths

`.github/workflows/`, `.githooks/`, `scripts/content_guard.py`, `scripts/build_denylist.py`,
`guard/`. A PR touching any of them says so in its body and includes the command for verifying
it with the guard from `main`:

```bash
git fetch origin main pull/<N>/head:pr-<N>
rm -rf /tmp/guard-main && mkdir -p /tmp/guard-main
git archive origin/main scripts/content_guard.py guard | tar -x -C /tmp/guard-main
python3 /tmp/guard-main/scripts/content_guard.py --lists /tmp/guard-main/guard --range origin/main..pr-<N>
```

## One-time grants

The operator may relax a rule for a single task by stating a grant in the task prompt. A grant
names the rule, the one object it applies to (for example a single pull request, identified by
its branch), and the conditions that must all hold. It expires when that task ends and never
carries over to a later task. Anything a grant does not name stays forbidden.
