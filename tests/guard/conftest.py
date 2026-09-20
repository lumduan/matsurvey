# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Fixtures that build synthetic guard lists.

The vocabulary here is invented.  No term the guard actually protects appears
in this repository, and the in-process tests hash under a test-only salt so
that even the synthetic hashes differ from the shipped ones.

List files are built through the real builder's ``term_entries`` and the
guard's own ``shingle_windows``, so a fixture cannot select kinds or slide a
window differently from the code under test.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import build_denylist as bd
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
size = ["uv.lock", "guard/shingles.v2.txt"]
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
    extra: tuple[str, ...] = (),
    config: str = CONFIG,
) -> Path:
    """Write a complete v2 lists directory from plain values."""
    directory.mkdir(parents=True, exist_ok=True)
    entries: set[str] = set(extra)
    for term in terms:
        produced, _count = bd.term_entries(term, salt)
        entries |= produced
    for num in nums:
        entries.add("num:" + cg.salted("num", num, salt))
    for value in hexes:
        entries.add("hex:" + cg.salted("hex", value, salt))
    for digest in files:
        entries.add("file:" + cg.salted("file", digest, salt))

    shingle_hashes: set[str] = set()
    for text in shingles:
        for value, _start, _end in cg.shingle_windows(cg.tokenize_text(text)):
            shingle_hashes.add(cg.salted("shingle", value, salt)[: cg.SHINGLE_HASH_LEN])

    write_raw(directory / cg.DENYLIST_NAME, sorted(entries), salt)
    write_raw(directory / cg.SHINGLES_NAME, sorted(shingle_hashes), salt)
    (directory / "config.toml").write_text(config, encoding="utf-8")
    return directory


def write_raw(path: Path, lines: list[str], salt: str, *, header: list[str] | None = None) -> None:
    """Write a list file verbatim -- used by the format tests to break it."""
    head = header if header is not None else list(cg.list_header(salt))
    body = "".join(f"{line}\n" for line in lines)
    path.write_text("".join(f"{line}\n" for line in head) + body, encoding="utf-8")


def make_context(directory: Path, **kwargs) -> cg.Context:
    """A Context over freshly written lists, hashed with the test-only salt."""
    write_lists(directory, salt=TEST_SALT, **kwargs)
    lists, config = cg.load_all(directory, salt=TEST_SALT)
    return cg.Context(lists, config, TEST_SALT)


@pytest.fixture
def ctx(tmp_path: Path) -> cg.Context:
    """The default context: one term of each shape the builder can emit."""
    return make_context(
        tmp_path / "lists",
        terms=("zorblax", "quux frobnitz", "qx7", "gloopworks", "z q v"),
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
