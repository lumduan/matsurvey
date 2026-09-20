## What this changes

## Why

## Checklist

- [ ] I ran `python scripts/install_hooks.py` in this clone, so the content guard ran on every commit.
- [ ] This change adds no third-party content: no source documents, nothing derived from one, no third-party names, marks or assets. See [CONTRIBUTING.md](../blob/HEAD/CONTRIBUTING.md).
- [ ] The title and body of this pull request contain no third-party names. Both are scanned, and the title becomes the commit message on `main`.
- [ ] I wrote the code myself rather than pasting it from elsewhere.
- [ ] `uv run pytest -m "not local and not golden" -q` passes locally.
