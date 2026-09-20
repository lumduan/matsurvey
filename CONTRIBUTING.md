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

A finding names how the text matched, and the kind is safe to print even in CI:

| Kind | Matched against |
|---|---|
| `phrase` | consecutive words, ignoring any digits between them; crosses punctuation and line breaks |
| `mixed` | consecutive tokens including digits, so an entry carrying a digit matches only where that digit is present |
| `compact` | tokens joined with nothing, inside a single whitespace-delimited word - this is what catches a run-together, camelCased, hyphenated or underscored spelling |

The list files carry a header declaring the format, the tokenizer and the salt they were
built with. If any of those does not match the guard reading them, the guard stops with an
error rather than quietly matching nothing, and a list left behind from an older format is
refused for the same reason. Rebuild the lists with `scripts/build_denylist.py`; it prints
counts, never content.

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

## Maintainers

Three rules that the guard cannot enforce for you.

**1. Merge with the default squash title and message.** Do not edit either in the merge
dialog. Text typed there is never checked, and it lands directly on the default branch,
which cannot be rewritten. To change what the commit will say, edit the pull request title
and let `guard` run again.

**2. A green `guard` check is not evidence for a pull request that changes the guard
itself.** On a pull request the job runs the workflow file from that pull request, so a
change to `.github/workflows/guard.yml` controls the job that judges it. The run writes a
notice to its step summary when a pull request touches `.github/workflows/`, `.githooks/`,
`scripts/content_guard.py`, `scripts/build_denylist.py` or `guard/`. That notice makes such
a pull request visible; it cannot make it safe. Before merging one, run the guard from the
default branch against the pull request head yourself:

```sh
git fetch origin main pull/<N>/head:pr-<N>
rm -rf /tmp/guard-main && mkdir -p /tmp/guard-main
git archive origin/main scripts/content_guard.py guard | tar -x -C /tmp/guard-main
python3 /tmp/guard-main/scripts/content_guard.py --lists /tmp/guard-main/guard \
  --range origin/main..pr-<N>
```

**3. Never write a third-party name into a pull request title, body or comment**, not even
to check that the guard catches it. Title changes and body edits stay visible in the
timeline afterwards, so there is nothing to undo. Test negative cases locally instead.
