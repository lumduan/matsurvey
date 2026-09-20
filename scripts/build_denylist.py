#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Build the guard's hash lists from plaintext sources kept outside the repository.

Plaintext never enters the repository.  This script reads the operator's local
term, fingerprint and file lists plus a local text corpus, and writes only
salted hashes into ``guard/``.  It refuses to read any source that lives inside
the repository, and it reports counts rather than content.

Each term line is tokenised with the guard's own tokenizer and emitted as one
or two entries, chosen so that a term is matched where it means something and
nowhere else:

* a line with **no digit** becomes a ``phrase`` entry -- matched against the
  letter-only token sequence, exactly as every term was matched before;
* a line **containing a digit** becomes a ``mixed`` entry instead, matched
  against the full token sequence.  A digit-bearing term therefore never
  degrades into its letters, which is what previously let a short alphanumeric
  term block an unrelated word;
* every line also becomes a ``compact`` entry -- the tokens joined with
  nothing -- which is what recovers the term when it is written run-together,
  camelCased, hyphenated or underscored inside a single word.

A line of five to eight tokens is too long for a phrase window and is emitted
as ``compact`` only; its line number is reported.  A line of more than eight
tokens could never match and is an error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from content_guard import (  # noqa: E402
    DENYLIST_NAME,
    MAX_COMPACT,
    MAX_NGRAM,
    SALT,
    SHINGLE_HASH_LEN,
    GuardError,
    alpha_tokens,
    hex_tokens,
    list_header,
    number_tokens,
    salted,
    shingle_windows,
    SHINGLES_NAME,
    tokenize_text,
)

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_TERM_KINDS = ("phrase", "mixed", "compact")


def read_lines(path: Path) -> list[tuple[int, str]]:
    if not path.exists():
        raise GuardError(f"missing input: {path}")
    out: list[tuple[int, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append((number, stripped))
    return out


def assert_outside(path: Path, repo_root: Path) -> None:
    resolved = path.resolve()
    if resolved == repo_root or repo_root in resolved.parents:
        raise GuardError(f"refusing to read plaintext from inside the repository: {resolved}")


def term_entries(line: str, salt: str) -> tuple[set[str], int]:
    """The entries one term line produces, and how many tokens it holds.

    Kept as its own function because the test fixtures build their lists with
    it too: a fixture that chose kinds differently from the real builder would
    test a guard nobody ships.
    """
    tokens = tokenize_text(line)
    if not tokens:
        raise GuardError("line has no tokens")
    if len(tokens) > MAX_COMPACT:
        raise GuardError(
            f"normalises to {len(tokens)} tokens; the guard matches windows of "
            f"at most {MAX_COMPACT}, so this line could never match"
        )
    values = [token.value for token in tokens]
    entries = {"compact:" + salted("compact", "".join(values), salt)}
    if len(tokens) <= MAX_NGRAM:
        kind = "mixed" if any(token.is_digit for token in tokens) else "phrase"
        entries.add(f"{kind}:" + salted(kind, " ".join(values), salt))
    return entries, len(tokens)


def build_terms(path: Path, salt: str) -> tuple[set[str], list[int]]:
    """Return the term entries and the line numbers emitted as compact only."""
    entries: set[str] = set()
    compact_only: list[int] = []
    for number, line in read_lines(path):
        try:
            produced, count = term_entries(line, salt)
        except GuardError as exc:
            raise GuardError(f"{path}:{number}: {exc}") from exc
        entries |= produced
        if count > MAX_NGRAM:
            compact_only.append(number)
    return entries, compact_only


def build_fingerprints(path: Path, salt: str) -> set[str]:
    entries: set[str] = set()
    for number, line in read_lines(path):
        kind, separator, value = line.partition(":")
        if not separator or kind not in {"num", "hex"}:
            raise GuardError(f"{path}:{number}: expected a 'num:' or 'hex:' prefix")
        value = value.strip()
        tokens = number_tokens(value) if kind == "num" else hex_tokens(value)
        if len(tokens) != 1 or tokens[0].length != len(value.lstrip("#")):
            raise GuardError(f"{path}:{number}: not a single well-formed {kind} token")
        entries.add(f"{kind}:" + salted(kind, tokens[0].value, salt))
    return entries


def build_files(path: Path, salt: str) -> set[str]:
    entries: set[str] = set()
    for number, line in read_lines(path):
        candidate = line.split()[0].lower()
        if not _SHA256_RE.match(candidate):
            raise GuardError(f"{path}:{number}: expected a sha256 hex digest")
        entries.add("file:" + salted("file", candidate, salt))
    return entries


def build_shingles(corpus: Path, salt: str) -> tuple[set[str], list[tuple[str, int]]]:
    digests: set[str] = set()
    per_source: list[tuple[str, int]] = []
    if not corpus.is_dir():
        return digests, per_source
    for source in sorted(corpus.glob("*.txt")):
        tokens = tokenize_text(source.read_text(encoding="utf-8", errors="replace"))
        per_source.append((source.name, len(alpha_tokens(tokens))))
        for value, _start, _end in shingle_windows(tokens):
            digests.add(salted("shingle", value, salt)[:SHINGLE_HASH_LEN])
    return digests, per_source


def write_list(path: Path, entries: set[str], salt: str) -> None:
    header = "".join(f"{line}\n" for line in list_header(salt))
    body = "".join(f"{entry}\n" for entry in sorted(entries))
    path.write_text(header + body, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    default_config = config_home / "matsurvey"
    default_local = Path(os.environ.get("MATSURVEY_LOCAL", Path.home() / "matsurvey-local"))
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--terms", type=Path, default=default_config / "terms.txt")
    parser.add_argument("--fingerprints", type=Path, default=default_config / "fingerprints.txt")
    parser.add_argument("--files", type=Path, default=default_config / "files.txt")
    parser.add_argument("--corpus", type=Path, default=default_local / "corpus")
    parser.add_argument("--out", type=Path, default=repo_root / "guard")
    parser.add_argument("--salt", default=SALT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        for source in (args.terms, args.fingerprints, args.files, args.corpus):
            assert_outside(source, repo_root)

        terms, compact_only = build_terms(args.terms, args.salt)
        fingerprints = build_fingerprints(args.fingerprints, args.salt)
        files = build_files(args.files, args.salt)
        shingles, per_source = build_shingles(args.corpus, args.salt)

        denylist = terms | fingerprints | files
        args.out.mkdir(parents=True, exist_ok=True)
        write_list(args.out / DENYLIST_NAME, denylist, args.salt)
        write_list(args.out / SHINGLES_NAME, shingles, args.salt)
    except GuardError as exc:
        print(f"build-denylist: error: {exc}", file=sys.stderr)
        return 2

    def count(prefix: str) -> int:
        return sum(1 for entry in denylist if entry.startswith(f"{prefix}:"))

    print("build-denylist: counts only, no content is reported")
    for kind in _TERM_KINDS:
        print(f"  {kind:<10} {count(kind)}")
    for kind in ("num", "hex", "file"):
        print(f"  {kind:<10} {count(kind)}")
    print(f"  {'shingle':<10} {len(shingles)}")
    if compact_only:
        joined = ", ".join(str(number) for number in compact_only)
        print(f"  compact-only lines (too long for a phrase window): {joined}")
    for name, words in per_source:
        print(f"  corpus {name}: {words} letter tokens")
    if not per_source:
        print("  corpus: no sources present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
