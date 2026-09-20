# Contributing

Thank you for helping. One rule matters more than the rest, so it comes first.

## What must never enter this repository

matsurvey is neutral tooling. It processes a document you already have; it never carries
one. Nothing in the list below may appear anywhere public — not in file contents, not in
file or directory names, not in commit messages, branch names, pull request titles or
bodies, issue text, or CI logs.

| Do not add | Examples |
|---|---|
| Third-party names and marks | competition, organiser, programme and category names; season themes; sponsor names; toy or hardware brands and product lines |
| Source documents | mat files, rules documents, building instructions, question-and-answer pages, in any format |
| Anything derived from them | renders, tiles, crops, screenshots; extracted geometry, coordinates, colours, palettes, sensor models; measured sizes, counts or hashes; extracted text; area or object names taken from rules |
| Other third-party assets | images, icons, fonts, colour profiles, audio, video, documentation text, or code copied from anywhere else |

Naming a software dependency is fine where it is technically or legally required:
`pyproject.toml`, `uv.lock`, import statements, `NOTICE`, and the license sentence in the
README. Nowhere else.

Write the code yourself. Do not paste code in from web pages, question-and-answer sites,
other repositories or documentation examples.

Use neutral vocabulary throughout: "mat", "mat PDF", "source document", "rules document",
"competition", "season", "category". Do not name which competition.

## Set up

```sh
uv sync
python scripts/install_hooks.py
```

`install_hooks.py` points `core.hooksPath` at the tracked `.githooks` directory. A clone
without that step is unprotected, so run it before your first commit.

## The content guard

`scripts/content_guard.py` reads the hash lists in `guard/` and refuses anything that
matches. It runs on every commit, on every push, and again in CI on every branch and every
pull request. The check is required and cannot be bypassed.

The lists hold salted hashes and nothing else, so they can be public without disclosing
what they protect. That also means the guard cannot tell you what it matched beyond the
text already in front of you: run it locally, without `--ci`, to see the offending text.

```sh
python scripts/content_guard.py --staged        # what you are about to commit
python scripts/content_guard.py --tree          # every tracked file
python scripts/content_guard.py --history       # every object and ref, ever
python scripts/content_guard.py --text -        # anything on stdin
```

Exit codes are `0` clean, `1` findings, `2` guard error. A guard error blocks, the same as
a finding: if the guard cannot do its job, nothing gets through.

If the guard blocks you, **do not** paraphrase the content to get past it, and do not
relax a rule. Both defeat the point. Remove the content, or open an issue describing the
problem in neutral terms.

If you believe a finding is a false positive, say so in an issue without quoting the text
that triggered it. Entries are never removed unilaterally.

## Tests

```sh
uv run pytest -m "not local and not golden" -q
```

Two markers select tests that need things this repository does not ship: `local` needs the
maintainer's own plaintext lists, and `golden` needs source documents you supply yourself.
CI runs neither.

## Pull requests

Keep the title and body neutral — both are scanned. Squash merge is the only merge method,
so the pull request title becomes the commit message on `main`.
