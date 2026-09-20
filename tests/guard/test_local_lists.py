# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Check the committed hash lists against the operator's local plaintext.

These tests need files that live outside the repository and are never
published, so they are marked ``local`` and excluded from CI.  They answer one
question: does every protected value actually appear in the list that ships?
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import content_guard as cg
from content_guard import SALT, SHINGLE_HASH_LEN, salted, word_sequence

pytestmark = pytest.mark.local

CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "matsurvey"
LOCAL = Path(os.environ.get("MATSURVEY_LOCAL", Path.home() / "matsurvey-local"))
GUARD = Path(__file__).resolve().parents[2] / "guard"


def entries() -> tuple[frozenset[str], ...]:
    return cg.load_denylist(GUARD / "denylist.v1.txt")


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


def test_every_local_term_is_in_the_committed_list():
    terms, _, _, _ = entries()
    for line in plain_lines(CONFIG_HOME / "terms.txt"):
        digest = salted("term", " ".join(word_sequence(line)), SALT)
        assert digest in terms, "a local term is missing from denylist.v1.txt"


def test_every_local_fingerprint_is_in_the_committed_list():
    _, nums, hexes, _ = entries()
    for line in plain_lines(CONFIG_HOME / "fingerprints.txt"):
        kind, _, value = line.partition(":")
        value = value.strip()
        tokens = cg.number_tokens(value) if kind == "num" else cg.hex_tokens(value)
        assert len(tokens) == 1, f"{kind} fingerprint does not tokenise cleanly"
        pool = nums if kind == "num" else hexes
        assert salted(kind, tokens[0].value, SALT) in pool


def test_every_local_file_hash_is_in_the_committed_list():
    _, _, _, files = entries()
    for line in plain_lines(CONFIG_HOME / "files.txt"):
        digest = line.split()[0].lower()
        assert salted("file", digest, SALT) in files


def test_every_corpus_shingle_is_in_the_committed_list():
    corpus = LOCAL / "corpus"
    sources = sorted(corpus.glob("*.txt")) if corpus.is_dir() else []
    if not sources:
        pytest.skip("no local corpus is present on this machine")
    shipped = cg.load_shingles(GUARD / "shingles.v1.txt")
    for source in sources:
        words = word_sequence(source.read_text(encoding="utf-8", errors="replace"))
        for index in range(len(words) - cg.SHINGLE_WORDS + 1):
            window = " ".join(words[index : index + cg.SHINGLE_WORDS])
            assert salted("shingle", window, SALT)[:SHINGLE_HASH_LEN] in shipped
