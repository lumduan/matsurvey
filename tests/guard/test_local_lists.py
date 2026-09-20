# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Check the committed hash lists against the operator's local plaintext.

These tests need files that live outside the repository and are never
published, so they are marked ``local`` and excluded from CI.  They answer two
questions: does every protected value actually appear in the list that ships,
and did each line produce the kinds the format says it should?
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import build_denylist as bd
import content_guard as cg
from content_guard import SALT, SHINGLE_HASH_LEN, salted

pytestmark = pytest.mark.local

CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "matsurvey"
LOCAL = Path(os.environ.get("MATSURVEY_LOCAL", Path.home() / "matsurvey-local"))
GUARD = Path(__file__).resolve().parents[2] / "guard"


def entries() -> dict[str, frozenset[str]]:
    """The shipped denylist, keyed by kind."""
    return cg.load_denylist(GUARD / cg.DENYLIST_NAME)


def plain_lines(path: Path) -> list[str]:
    if not path.exists():
        pytest.skip(f"{path} is not present on this machine")
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        pytest.skip(f"{path} is empty")
    return lines


def test_the_shipped_lists_load():
    """Catches a leftover list from another format sitting in guard/."""
    lists, _config = cg.load_all(GUARD)
    assert lists.any_terms


def test_every_local_term_produces_the_kinds_the_format_requires():
    for line in plain_lines(CONFIG_HOME / "terms.txt"):
        produced, count = bd.term_entries(line, SALT)
        kinds = {entry.split(":", 1)[0] for entry in produced}
        has_digit = any(token.is_digit for token in cg.tokenize_text(line))
        assert "compact" in kinds, "every term line must have a compact entry"
        if count <= cg.MAX_NGRAM:
            expected = "mixed" if has_digit else "phrase"
            assert kinds == {"compact", expected}
        else:
            assert kinds == {"compact"}, "a long line is compact only"


def test_every_local_term_is_in_the_committed_list():
    buckets = entries()
    for line in plain_lines(CONFIG_HOME / "terms.txt"):
        produced, _count = bd.term_entries(line, SALT)
        for entry in produced:
            kind, _, digest = entry.partition(":")
            assert digest in buckets[kind], f"a {kind} entry is missing from the list"


def test_every_local_fingerprint_is_in_the_committed_list():
    buckets = entries()
    for line in plain_lines(CONFIG_HOME / "fingerprints.txt"):
        kind, _, value = line.partition(":")
        value = value.strip()
        tokens = cg.number_tokens(value) if kind == "num" else cg.hex_tokens(value)
        assert len(tokens) == 1, f"{kind} fingerprint does not tokenise cleanly"
        assert salted(kind, tokens[0].value, SALT) in buckets[kind]


def test_every_local_file_hash_is_in_the_committed_list():
    buckets = entries()
    for line in plain_lines(CONFIG_HOME / "files.txt"):
        digest = line.split()[0].lower()
        assert salted("file", digest, SALT) in buckets["file"]


def test_every_corpus_shingle_is_in_the_committed_list():
    corpus = LOCAL / "corpus"
    sources = sorted(corpus.glob("*.txt")) if corpus.is_dir() else []
    if not sources:
        pytest.skip("no local corpus is present on this machine")
    shipped = cg.load_shingles(GUARD / cg.SHINGLES_NAME)
    for source in sources:
        tokens = cg.tokenize_text(source.read_text(encoding="utf-8", errors="replace"))
        for value, _start, _end in cg.shingle_windows(tokens):
            assert salted("shingle", value, SALT)[:SHINGLE_HASH_LEN] in shipped
