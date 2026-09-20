# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Fixtures that build synthetic guard lists.

The vocabulary here is invented.  No term the guard actually protects appears
in this repository, and the in-process tests hash under a test-only salt so
that even the synthetic hashes differ from the shipped ones.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import content_guard as cg

TEST_SALT = "matsurvey-test-salt-not-for-use"

CONFIG = """\
[limits]
max_file_bytes = 524288
hard_max_file_bytes = 2097152
base64_run_min = 1024
data_uri_base64_min = 256

[allowlists]
binary = []
size = ["uv.lock", "guard/shingles.v1.txt"]
"""


def write_lists(
    directory: Path,
    *,
    salt: str,
    terms: tuple[str, ...] = (),
    nums: tuple[str, ...] = (),
    hexes: tuple[str, ...] = (),
    files: tuple[str, ...] = (),
    shingles: tuple[str, ...] = (),
    config: str = CONFIG,
) -> Path:
    """Write a complete lists directory from plain values."""
    directory.mkdir(parents=True, exist_ok=True)
    entries = []
    for term in terms:
        entries.append("term:" + cg.salted("term", " ".join(cg.word_sequence(term)), salt))
    for num in nums:
        entries.append("num:" + cg.salted("num", num, salt))
    for value in hexes:
        entries.append("hex:" + cg.salted("hex", value, salt))
    for digest in files:
        entries.append("file:" + cg.salted("file", digest, salt))
    (directory / "denylist.v1.txt").write_text(
        "# hashes only\n" + "".join(f"{e}\n" for e in sorted(set(entries))), encoding="utf-8"
    )
    shingle_hashes = {
        cg.salted("shingle", " ".join(cg.word_sequence(text)), salt)[: cg.SHINGLE_HASH_LEN]
        for text in shingles
    }
    (directory / "shingles.v1.txt").write_text(
        "# hashes only\n" + "".join(f"{h}\n" for h in sorted(shingle_hashes)), encoding="utf-8"
    )
    (directory / "config.toml").write_text(config, encoding="utf-8")
    return directory


def make_context(directory: Path, **kwargs) -> cg.Context:
    """A Context over freshly written lists, hashed with the test-only salt."""
    write_lists(directory, salt=TEST_SALT, **kwargs)
    lists, config = cg.load_all(directory)
    return cg.Context(lists, config, TEST_SALT)


@pytest.fixture
def ctx(tmp_path: Path) -> cg.Context:
    """The default context: one unigram, one bigram, one spaced-letter phrase."""
    return make_context(
        tmp_path / "lists",
        terms=("zorblax", "quux frobnitz", "q r s", "quuxfrobnitz"),
    )


@pytest.fixture
def git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty repository with the working directory moved into it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (
        ["init", "-b", "main", "-q"],
        ["config", "user.name", "test"],
        ["config", "user.email", "test@example.invalid"],
        ["config", "commit.gpgsign", "false"],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True)
    monkeypatch.chdir(repo)
    return repo


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout
