#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Content guard for the matsurvey repository.

The guard refuses content that must never reach a public surface: third-party
names and marks, source documents obtained from third parties, anything derived
from them, and other third-party assets.

It never stores what it blocks.  The lists shipped in ``guard/`` hold salted
hashes only, so the repository can be public without the lists disclosing the
terms they protect.  A list therefore cannot match itself.

Scanned surfaces are selected by mode: the index (``--staged``), a commit
message (``--commit-msg``), a push (``--push``), a revision range
(``--range``), the tracked tree (``--tree``), the whole object database
(``--history``) and arbitrary text (``--text -``).  Every mode scans file
*paths* as well as file contents, because names are a public surface too.

Exit codes
----------
0   clean
1   findings
2   guard error -- unreadable list, malformed list, bad config, unexpected
    exception.  Callers must treat any non-zero status as a block.

Known limitation
----------------
Matching is token equality over word n-grams, not substring matching.  An
inflected or misspelled form of a listed term is therefore not matched.  This
is deliberate: substring matching on short terms produces false positives, and
a guard that cries wolf teaches people to route around it.

A run that splits into several words is additionally checked in its re-joined
form, so an internal capital -- ``ZorBlax`` against an entry spelled
``zorblax`` -- does not slip past.  That is still whole-token equality, not
a substring search.

Offsets are reported against the NFKC-normalised text.  For ASCII content that
is identical to the bytes on disk; for content using compatibility forms the
column may shift by the width of the normalisation.  A finding reported at
line 0 refers to the path itself rather than to a line of the file.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import re
import subprocess
import sys
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

SALT = "matsurvey-guard-v1"
MAX_NGRAM = 4
SHINGLE_WORDS = 10
SHINGLE_HASH_LEN = 16
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZERO_SHA = "0" * 40

SPDX_DIRS = ("scripts/", "tests/", "tools/", "matsurvey/", ".githooks/")
SPDX_EXTS = (".py", ".sh", ".toml")
SPDX_MARKER = "SPDX-License-Identifier:"
SPDX_SCAN_LINES = 5

BLOCKED_BASENAMES = frozenset(
    {
        "drawings.json",
        "fills_by_colour.json",
        "semantic.json",
        "field_spec.json",
        "sensor_model.json",
        "manifest.json",
        "probe.json",
    }
)
BLOCKED_EXTENSIONS = frozenset({".ipynb", ".eps", ".ai", ".indd", ".idml"})

# Assembled from fragments on purpose.  The guard scans its own source, and it
# looks for these two markers anywhere in the head of a file rather than at a
# fixed offset.  Written out in one piece, either one would make this file
# block itself the moment it moved nearer the top.
PDF_MARKER = b"%P" + b"DF-"
SVG_MARKER = b"<s" + b"vg"


class GuardError(Exception):
    """Fail-closed error.  Always reported as exit code 2."""


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------


def salted(kind: str, value: str, salt: str = SALT) -> str:
    """Return the salted sha256 of ``value`` under ``kind``."""
    payload = f"{salt}\x1f{kind}\x1f{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# tokenizer -- the same code path builds the lists and scans content
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Token:
    """A token and where it starts in the normalised text."""

    value: str
    offset: int
    length: int


_RUN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_NUM_RE = re.compile(
    r"(?<![A-Za-z0-9.])(\d{1,3}(?:[,_]\d{3})+|\d+)(?:\.(\d+))?(?![A-Za-z0-9])"
)
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])#?([0-9A-Fa-f]{6,64})(?![0-9A-Za-z])")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]+")
_DATA_URI_RE = re.compile(r"data:[^\s;,]*;base64,([A-Za-z0-9+/=]+)")


def normalize(text: str) -> str:
    """Collapse full-width and other compatibility forms."""
    return unicodedata.normalize("NFKC", text)


def _split_run(run: str) -> list[tuple[str, int]]:
    """Split one alphanumeric run at lower->upper and letter<->digit boundaries."""
    parts: list[tuple[str, int]] = []
    start = 0
    for i in range(1, len(run)):
        prev, char = run[i - 1], run[i]
        if (prev.islower() and char.isupper()) or (prev.isalpha() != char.isalpha()):
            parts.append((run[start:i], start))
            start = i
    parts.append((run[start:], start))
    return parts


def word_tokens(text: str) -> list[Token]:
    """Return the word sequence of the whole text, in order.

    Digits are dropped; only alphabetic parts survive.  Building one sequence
    for the entire blob is what lets a phrase match across punctuation and
    line breaks.
    """
    tokens: list[Token] = []
    for match in _RUN_RE.finditer(text):
        run, base = match.group(0), match.start()
        for part, offset in _split_run(run):
            if part.isalpha():
                tokens.append(Token(part.casefold(), base + offset, len(part)))
    return tokens


def joined_run_tokens(text: str) -> list[Token]:
    """The re-joined form of each run that split into several words.

    ``ZorBlax`` splits at the camelCase boundary into two words, so a
    single-word entry spelled ``zorblax`` would not match it.  Re-joining
    the alphabetic parts of a run and checking that as one more unigram closes
    that gap without giving up token equality: the joined form is still
    matched whole, never as a substring.
    """
    tokens: list[Token] = []
    for match in _RUN_RE.finditer(text):
        run, base = match.group(0), match.start()
        parts = [part for part, _ in _split_run(run) if part.isalpha()]
        if len(parts) > 1:
            tokens.append(Token("".join(parts).casefold(), base, len(run)))
    return tokens


def _number_value(integer: str, fraction: str | None) -> str:
    base = integer.replace(",", "").replace("_", "")
    if fraction:
        trimmed = fraction.rstrip("0")
        if trimmed:
            return f"{base}.{trimmed}"
    return base


def number_tokens(text: str) -> list[Token]:
    """Return normalised number tokens (separators removed, trailing zeros trimmed)."""
    tokens: list[Token] = []
    for match in _NUM_RE.finditer(text):
        value = _number_value(match.group(1), match.group(2))
        tokens.append(Token(value, match.start(1), len(match.group(0))))
    return tokens


def hex_tokens(text: str) -> list[Token]:
    """Return lowercase hex runs that carry at least one digit and one a-f letter."""
    tokens: list[Token] = []
    for match in _HEX_RE.finditer(text):
        run = match.group(1)
        lowered = run.casefold()
        has_digit = any(char.isdigit() for char in lowered)
        has_letter = any(char in "abcdef" for char in lowered)
        if has_digit and has_letter:
            tokens.append(Token(lowered, match.start(1), len(run)))
    return tokens


def windows(tokens: Sequence[Token], size: int) -> Iterator[tuple[str, int, int]]:
    """Yield ``(joined value, start offset, end offset)`` for each window."""
    for index in range(len(tokens) - size + 1):
        window = tokens[index : index + size]
        value = " ".join(token.value for token in window)
        start = window[0].offset
        end = window[-1].offset + window[-1].length
        yield value, start, end


def word_sequence(text: str) -> list[str]:
    """The plain word sequence of ``text`` -- used when building lists."""
    return [token.value for token in word_tokens(normalize(text))]


# --------------------------------------------------------------------------
# lists and config
# --------------------------------------------------------------------------

_HASH64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_HASH_SHINGLE_RE = re.compile(r"\A[0-9a-f]{%d}\Z" % SHINGLE_HASH_LEN)
_LIST_KINDS = ("term", "num", "hex", "file")


@dataclass(frozen=True)
class Lists:
    terms: frozenset[str]
    nums: frozenset[str]
    hexes: frozenset[str]
    files: frozenset[str]
    shingles: frozenset[str]


@dataclass(frozen=True)
class Config:
    max_file_bytes: int
    hard_max_file_bytes: int
    base64_run_min: int
    data_uri_base64_min: int
    binary_allowlist: frozenset[str]
    size_allowlist: frozenset[str]


def _read_lines(path: Path) -> list[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise GuardError(f"{path} is not valid UTF-8: {exc}") from exc
    return raw.splitlines()


def load_denylist(path: Path) -> tuple[frozenset[str], ...]:
    buckets: dict[str, set[str]] = {kind: set() for kind in _LIST_KINDS}
    for number, line in enumerate(_read_lines(path), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kind, separator, digest = stripped.partition(":")
        if not separator or kind not in buckets or not _HASH64_RE.match(digest):
            raise GuardError(f"{path}:{number}: malformed denylist entry")
        buckets[kind].add(digest)
    return tuple(frozenset(buckets[kind]) for kind in _LIST_KINDS)


def load_shingles(path: Path) -> frozenset[str]:
    digests: set[str] = set()
    for number, line in enumerate(_read_lines(path), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not _HASH_SHINGLE_RE.match(stripped):
            raise GuardError(f"{path}:{number}: malformed shingle entry")
        digests.add(stripped)
    return frozenset(digests)


def _require_int(table: dict[str, object], key: str, where: str) -> int:
    value = table.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise GuardError(f"{where}: '{key}' must be a positive integer")
    return value


def _require_str_list(table: dict[str, object], key: str, where: str) -> frozenset[str]:
    value = table.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GuardError(f"{where}: '{key}' must be a list of strings")
    return frozenset(value)


def load_config(path: Path) -> Config:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise GuardError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise GuardError(f"{path}: invalid TOML: {exc}") from exc

    limits = data.get("limits")
    allowlists = data.get("allowlists")
    if not isinstance(limits, dict) or not isinstance(allowlists, dict):
        raise GuardError(f"{path}: [limits] and [allowlists] tables are required")

    config = Config(
        max_file_bytes=_require_int(limits, "max_file_bytes", str(path)),
        hard_max_file_bytes=_require_int(limits, "hard_max_file_bytes", str(path)),
        base64_run_min=_require_int(limits, "base64_run_min", str(path)),
        data_uri_base64_min=_require_int(limits, "data_uri_base64_min", str(path)),
        binary_allowlist=_require_str_list(allowlists, "binary", str(path)),
        size_allowlist=_require_str_list(allowlists, "size", str(path)),
    )
    if config.hard_max_file_bytes < config.max_file_bytes:
        raise GuardError(f"{path}: hard_max_file_bytes is below max_file_bytes")
    return config


def load_all(directory: Path) -> tuple[Lists, Config]:
    """Load lists and config from ``directory``, failing closed on any problem."""
    if not directory.is_dir():
        raise GuardError(f"lists directory not found: {directory}")
    terms, nums, hexes, files = load_denylist(directory / "denylist.v1.txt")
    shingles = load_shingles(directory / "shingles.v1.txt")
    config = load_config(directory / "config.toml")
    return Lists(terms, nums, hexes, files, shingles), config


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    col: int
    rule: str
    message: str
    detail: str | None = None


class LineIndex:
    """Map a character offset to a 1-based line and column."""

    def __init__(self, text: str) -> None:
        starts = [0]
        for index, char in enumerate(text):
            if char == "\n":
                starts.append(index + 1)
        self._starts = starts

    def locate(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset)
        line = max(line, 1)
        return line, offset - self._starts[line - 1] + 1


# --------------------------------------------------------------------------
# binary sniffing
# --------------------------------------------------------------------------

_SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "PNG"),
    (0, b"\xff\xd8\xff", "JPEG"),
    (0, b"GIF87a", "GIF"),
    (0, b"GIF89a", "GIF"),
    (0, b"II*\x00", "TIFF"),
    (0, b"MM\x00*", "TIFF"),
    (0, b"8BPS", "PSD"),
    (0, b"\x00\x01\x00\x00", "TTF"),
    (0, b"OTTO", "OTF"),
    (0, b"ttcf", "TTC"),
    (0, b"wOFF", "WOFF"),
    (0, b"wOF2", "WOFF2"),
    (0, b"PK\x03\x04", "ZIP/OOXML"),
    (0, b"PK\x05\x06", "ZIP"),
    (0, b"PK\x07\x08", "ZIP"),
    (0, b"\x1f\x8b", "GZIP"),
    (0, b"7z\xbc\xaf\x27\x1c", "7Z"),
    (0, b"Rar!\x1a\x07", "RAR"),
    (0, b"ID3", "MP3"),
    (0, b"\xff\xfb", "MP3"),
    (0, b"\xff\xf3", "MP3"),
    (0, b"\xff\xf2", "MP3"),
    (0, b"OggS", "OGG"),
    (0, b"SQLite format 3\x00", "SQLITE"),
    (4, b"ftyp", "MP4/MOV"),
    (36, b"acsp", "ICC"),
    (257, b"ustar", "TAR"),
)


def sniff_binary(data: bytes) -> str | None:
    """Return the name of a known binary format, or None."""
    head = data[:1024]
    if PDF_MARKER in head:
        return "PDF"
    if head[:4] == b"RIFF":
        container = head[8:12]
        if container == b"WEBP":
            return "WEBP"
        if container == b"WAVE":
            return "WAV"
        return "RIFF"
    if head[:2] == b"BM" and data[6:10] == b"\x00\x00\x00\x00" and len(data) >= 14:
        return "BMP"
    for offset, signature, name in _SIGNATURES:
        if data[offset : offset + len(signature)] == signature:
            return name
    return None


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Context:
    lists: Lists
    config: Config
    salt: str


def needs_spdx(path: str) -> bool:
    """True when ``path`` is a first-party source file that must carry a header."""
    if not path.startswith(SPDX_DIRS):
        return False
    name = path.rsplit("/", 1)[-1]
    if name.endswith(SPDX_EXTS):
        return True
    # Hooks are executable Python files and carry no extension.
    return path.startswith(".githooks/") and "." not in name


def scan_tokens(
    label: str,
    text: str,
    ctx: Context,
    *,
    index: LineIndex | None = None,
    line_override: int | None = None,
) -> list[Finding]:
    """Apply R7, R8 and R10 to already-normalised text."""
    findings: list[Finding] = []
    lists, salt = ctx.lists, ctx.salt

    def locate(offset: int) -> tuple[int, int]:
        if line_override is not None:
            return line_override, offset + 1
        assert index is not None
        return index.locate(offset)

    words = word_tokens(text)

    if lists.terms:
        for size in range(1, MAX_NGRAM + 1):
            for value, start, end in windows(words, size):
                if salted("term", value, salt) in lists.terms:
                    line, col = locate(start)
                    findings.append(
                        Finding(label, line, col, "R7", "blocked term", text[start:end])
                    )
        for token in joined_run_tokens(text):
            if salted("term", token.value, salt) in lists.terms:
                line, col = locate(token.offset)
                findings.append(
                    Finding(
                        label,
                        line,
                        col,
                        "R7",
                        "blocked term",
                        text[token.offset : token.offset + token.length],
                    )
                )

    if lists.nums:
        for token in number_tokens(text):
            if salted("num", token.value, salt) in lists.nums:
                line, col = locate(token.offset)
                findings.append(
                    Finding(label, line, col, "R8", "blocked number", token.value)
                )

    if lists.hexes:
        for token in hex_tokens(text):
            if salted("hex", token.value, salt) in lists.hexes:
                line, col = locate(token.offset)
                findings.append(
                    Finding(label, line, col, "R8", "blocked hex value", token.value)
                )

    if lists.shingles:
        for value, start, end in windows(words, SHINGLE_WORDS):
            if salted("shingle", value, salt)[:SHINGLE_HASH_LEN] in lists.shingles:
                line, col = locate(start)
                findings.append(
                    Finding(label, line, col, "R10", "copied text", text[start:end])
                )

    return findings


def scan_embedded(label: str, text: str, ctx: Context, index: LineIndex) -> list[Finding]:
    """R6 -- embedded payloads."""
    findings: list[Finding] = []
    for match in _DATA_URI_RE.finditer(text):
        if len(match.group(1)) > ctx.config.data_uri_base64_min:
            line, col = index.locate(match.start())
            findings.append(
                Finding(label, line, col, "R6", "embedded base64 data URI", None)
            )
    for match in _B64_RUN_RE.finditer(text):
        if len(match.group(0)) >= ctx.config.base64_run_min:
            line, col = index.locate(match.start())
            findings.append(
                Finding(label, line, col, "R6", "embedded base64 payload", None)
            )
    return findings


def scan_spdx(label: str, raw: str) -> list[Finding]:
    """R11 -- SPDX header in the first few lines."""
    head = raw.splitlines()[:SPDX_SCAN_LINES]
    if any(SPDX_MARKER in line for line in head):
        return []
    return [Finding(label, 1, 1, "R11", "missing SPDX-License-Identifier header", None)]


def scan_text(
    label: str, raw: str, ctx: Context, *, check_spdx: bool = False
) -> list[Finding]:
    """Apply every text rule to ``raw``."""
    text = normalize(raw)
    index = LineIndex(text)
    findings = scan_tokens(label, text, ctx, index=index)
    findings += scan_embedded(label, text, ctx, index)
    if check_spdx:
        findings += scan_spdx(label, raw)
    return findings


def scan_path(path: str, ctx: Context) -> list[Finding]:
    """Apply the term rules to the path itself (reported at line 0)."""
    return scan_tokens(path, normalize(path), ctx, line_override=0)


def scan_bytes(path: str, data: bytes, ctx: Context) -> tuple[list[Finding], str | None]:
    """Apply R1-R5 and R9.  Returns findings and the decoded text, if any."""
    findings: list[Finding] = []
    config = ctx.config
    name = path.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""

    cap = (
        config.hard_max_file_bytes
        if path in config.size_allowlist
        else config.max_file_bytes
    )
    if len(data) > cap:
        findings.append(
            Finding(path, 0, 1, "R5", "file exceeds the size cap", f"{len(data)} bytes")
        )

    if name in BLOCKED_BASENAMES:
        findings.append(Finding(path, 0, 1, "R4", "blocked file name", None))

    if ctx.lists.files:
        digest = hashlib.sha256(data).hexdigest()
        if salted("file", digest, ctx.salt) in ctx.lists.files:
            findings.append(Finding(path, 0, 1, "R9", "blocked file content", None))

    fmt = sniff_binary(data)
    if fmt is not None and path not in config.binary_allowlist:
        findings.append(
            Finding(path, 0, 1, "R2", f"blocked binary format ({fmt})", None)
        )

    if suffix in BLOCKED_EXTENSIONS:
        findings.append(
            Finding(path, 0, 1, "R3", f"blocked text format ({suffix})", None)
        )

    if SVG_MARKER in data[:4096].lower():
        findings.append(Finding(path, 0, 1, "R3", "blocked text format (SVG)", None))

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if path not in config.binary_allowlist:
            findings.append(
                Finding(path, 0, 1, "R1", "content is not valid UTF-8", f"byte {exc.start}")
            )
        return findings, None
    return findings, text


def scan_blob(
    path: str, data: bytes, ctx: Context, *, check_spdx: bool = True
) -> list[Finding]:
    """Apply every rule to one blob and its path."""
    findings = scan_path(path, ctx)
    byte_findings, text = scan_bytes(path, data, ctx)
    findings += byte_findings
    if text is not None:
        findings += scan_text(
            path, text, ctx, check_spdx=check_spdx and needs_spdx(path)
        )
    return findings


# --------------------------------------------------------------------------
# git plumbing
# --------------------------------------------------------------------------


def git(args: Sequence[str], *, allow_fail: bool = False) -> bytes:
    try:
        proc = subprocess.run(["git", *args], capture_output=True)
    except OSError as exc:
        raise GuardError(f"cannot run git: {exc}") from exc
    if proc.returncode != 0:
        if allow_fail:
            return b""
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise GuardError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def git_text(args: Sequence[str], *, allow_fail: bool = False) -> str:
    return git(args, allow_fail=allow_fail).decode("utf-8", "replace")


def _decode_path(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


def has_head() -> bool:
    return bool(git(["rev-parse", "--verify", "-q", "HEAD"], allow_fail=True))


def staged_paths() -> list[str]:
    args = ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    if not has_head():
        args.append(EMPTY_TREE)
    return [p for p in _decode_path(git(args)).split("\0") if p]


def tree_entries(rev: str = "HEAD") -> list[tuple[str, str]]:
    if not has_head():
        return []
    entries: list[tuple[str, str]] = []
    for record in git(["ls-tree", "-r", "-z", rev]).split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        fields = meta.split()
        if len(fields) >= 3 and fields[1] == b"blob":
            entries.append((fields[2].decode("ascii"), _decode_path(path)))
    return entries


def read_blobs(shas: Sequence[str]) -> dict[str, bytes]:
    """Read many blobs in as few git invocations as possible."""
    out: dict[str, bytes] = {}
    unique = sorted(set(shas))
    for start in range(0, len(unique), 256):
        chunk = unique[start : start + 256]
        payload = ("\n".join(chunk) + "\n").encode("ascii")
        proc = subprocess.run(
            ["git", "cat-file", "--batch"], input=payload, capture_output=True
        )
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GuardError(f"git cat-file --batch failed: {detail}")
        buffer, pos = proc.stdout, 0
        while pos < len(buffer):
            newline = buffer.find(b"\n", pos)
            if newline == -1:
                break
            header = buffer[pos:newline].decode("utf-8", "replace").split()
            pos = newline + 1
            if len(header) < 3:
                continue
            size = int(header[2])
            out[header[0]] = buffer[pos : pos + size]
            pos += size + 1
    return out


def rev_objects(rev_args: Sequence[str]) -> list[tuple[str, str]]:
    raw = _decode_path(git(["rev-list", "--objects", *rev_args], allow_fail=True))
    pairs: list[tuple[str, str]] = []
    for line in raw.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            pairs.append((sha, path))
    return pairs


def filter_blobs(pairs: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    if not pairs:
        return []
    kinds: dict[str, str] = {}
    unique = sorted({sha for sha, _ in pairs})
    for start in range(0, len(unique), 512):
        chunk = unique[start : start + 512]
        payload = ("\n".join(chunk) + "\n").encode("ascii")
        proc = subprocess.run(
            ["git", "cat-file", "--batch-check"], input=payload, capture_output=True
        )
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GuardError(f"git cat-file --batch-check failed: {detail}")
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split()
            if len(fields) >= 2:
                kinds[fields[0]] = fields[1]
    return [(sha, path) for sha, path in pairs if kinds.get(sha) == "blob"]


def commit_messages(rev_args: Sequence[str]) -> list[tuple[str, str]]:
    raw = git_text(["log", "--format=%H%x1f%B%x00", *rev_args], allow_fail=True)
    messages: list[tuple[str, str]] = []
    for record in raw.split("\0"):
        record = record.strip("\n")
        if not record:
            continue
        sha, _, body = record.partition("\x1f")
        messages.append((sha, body))
    return messages


# --------------------------------------------------------------------------
# modes
# --------------------------------------------------------------------------


def mode_staged(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for path in staged_paths():
        findings += scan_blob(path, git(["show", f":{path}"]), ctx)
    return findings


def mode_commit_msg(path: str, ctx: Context) -> list[Finding]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardError(f"cannot read commit message {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise GuardError(f"commit message is not valid UTF-8: {exc}") from exc
    return scan_text("<commit-msg>", raw, ctx)


def scan_range(
    rev_args: Sequence[str], ctx: Context, *, check_spdx: bool = True
) -> list[Finding]:
    findings: list[Finding] = []
    for sha, body in commit_messages(rev_args):
        findings += scan_text(f"<commit {sha[:12]}>", body, ctx)
    pairs = filter_blobs(rev_objects(rev_args))
    blobs = read_blobs([sha for sha, _ in pairs])
    for sha, path in pairs:
        findings += scan_blob(path, blobs.get(sha, b""), ctx, check_spdx=check_spdx)
    return findings


def mode_push(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for line in sys.stdin.read().splitlines():
        fields = line.split()
        if len(fields) != 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = fields
        if local_sha == ZERO_SHA:
            continue  # branch deletion pushes nothing to scan
        for ref in (local_ref, remote_ref):
            if ref and ref != "(delete)":
                findings += scan_text("<ref>", ref, ctx)
        if remote_sha == ZERO_SHA:
            rev_args = [local_sha, "--not", "--remotes"]
        else:
            rev_args = [f"{remote_sha}..{local_sha}"]
        findings += scan_range(rev_args, ctx)
    return findings


def mode_tree(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    entries = tree_entries("HEAD")
    blobs = read_blobs([sha for sha, _ in entries])
    for sha, path in entries:
        findings += scan_blob(path, blobs.get(sha, b""), ctx)
    return findings


def mode_history(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    pairs = filter_blobs(rev_objects(["--all"]))
    blobs = read_blobs([sha for sha, _ in pairs])
    for sha, path in pairs:
        findings += scan_blob(path, blobs.get(sha, b""), ctx, check_spdx=False)
    for sha, body in commit_messages(["--all"]):
        findings += scan_text(f"<commit {sha[:12]}>", body, ctx)
    for ref in git_text(
        ["for-each-ref", "--format=%(refname)"], allow_fail=True
    ).splitlines():
        findings += scan_text("<ref>", ref, ctx)
    return findings


def mode_text(value: str, ctx: Context) -> list[Finding]:
    raw = sys.stdin.read() if value == "-" else value
    return scan_text("<stdin>" if value == "-" else "<text>", raw, ctx)


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def redact_label(label: str, ctx: Context) -> str:
    """Mask a label that is itself denylisted, so CI logs never echo it."""
    if scan_tokens(label, normalize(label), ctx, line_override=0):
        return f"<redacted:{salted('path', label, ctx.salt)[:12]}>"
    return label


def report(findings: Sequence[Finding], ctx: Context, *, ci: bool) -> None:
    labels: dict[str, str] = {}
    for finding in findings:
        label = finding.path
        if ci:
            if label not in labels:
                labels[label] = redact_label(label, ctx)
            label = labels[label]
        if finding.detail is None:
            suffix = ""
        elif ci:
            suffix = " (masked)"
        else:
            suffix = ' "' + " ".join(finding.detail.split()) + '"'
        print(f"{label}:{finding.line}:{finding.col} {finding.rule} {finding.message}{suffix}")
    print(f"content-guard: {len(findings)} finding(s)", file=sys.stderr)


def default_lists_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "guard"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="content_guard.py",
        description="Refuse content that must never reach a public surface.",
    )
    parser.add_argument("--staged", action="store_true", help="scan the git index")
    parser.add_argument("--commit-msg", metavar="FILE", help="scan a commit message")
    parser.add_argument("--push", action="store_true", help="scan a push (refs on stdin)")
    parser.add_argument("--range", metavar="A..B", help="scan a revision range")
    parser.add_argument("--tree", action="store_true", help="scan every tracked file at HEAD")
    parser.add_argument("--history", action="store_true", help="scan every object and ref")
    parser.add_argument("--text", metavar="VALUE", help="scan text; '-' reads stdin")
    parser.add_argument("--lists", metavar="DIR", help="load lists and config from DIR")
    parser.add_argument("--ci", action="store_true", help="mask findings for public logs")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        directory = Path(args.lists) if args.lists else default_lists_dir()
        lists, config = load_all(directory)
        ctx = Context(lists, config, SALT)

        findings: list[Finding] = []
        selected = False
        if args.staged:
            findings += mode_staged(ctx)
            selected = True
        if args.commit_msg:
            findings += mode_commit_msg(args.commit_msg, ctx)
            selected = True
        if args.push:
            findings += mode_push(ctx)
            selected = True
        if args.range:
            findings += scan_range([args.range], ctx)
            selected = True
        if args.tree:
            findings += mode_tree(ctx)
            selected = True
        if args.history:
            findings += mode_history(ctx)
            selected = True
        if args.text is not None:
            findings += mode_text(args.text, ctx)
            selected = True
        if not selected:
            raise GuardError("no mode selected; pass at least one mode flag")
    except GuardError as exc:
        print(f"content-guard: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # fail closed on anything unexpected
        print(f"content-guard: unexpected error: {exc!r}", file=sys.stderr)
        return 2

    if findings:
        report(findings, ctx, ci=args.ci)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
