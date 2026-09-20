# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Tests for the content guard.

Every term used here is invented.  Nothing the guard actually protects appears
in this repository, in these tests, or in the fixtures they build.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

import content_guard as cg
import build_denylist as bd
from conftest import TEST_SALT, git, make_context, write_lists, write_raw

SHINGLE = "alpha bravo charlie delta echo foxtrot golf hotel india juliet"

# The guard scans this file too, and it finds these two markers anywhere in the
# head of a file.  Spelled out in one piece they would make the test suite block
# itself -- so the fixtures assemble them instead, and no path needs an exemption.
PDF_MAGIC = b"%P" + b"DF-1.7"
SVG_OPEN = b"<s" + b"vg"


def rules(findings) -> list[str]:
    return sorted({finding.rule for finding in findings})


def fired(findings, rule: str) -> bool:
    return any(finding.rule == rule for finding in findings)


# --------------------------------------------------------------------------
# R1-R3  format rules
# --------------------------------------------------------------------------

SIGNATURES = {
    "PDF": PDF_MAGIC + b"\n1 0 obj\n",
    "PNG": b"\x89PNG\r\n\x1a\n" + b"\x00" * 16,
    "JPEG": b"\xff\xd8\xff\xe0" + b"\x00" * 16,
    "GIF": b"GIF89a" + b"\x00" * 16,
    "TIFF": b"II*\x00" + b"\x00" * 16,
    "BMP": b"BM" + b"\x36\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00" * 16,
    "PSD": b"8BPS" + b"\x00" * 16,
    "TTF": b"\x00\x01\x00\x00" + b"\x00" * 16,
    "OTF": b"OTTO" + b"\x00" * 16,
    "WOFF": b"wOFF" + b"\x00" * 16,
    "WOFF2": b"wOF2" + b"\x00" * 16,
    "ZIP/OOXML": b"PK\x03\x04" + b"\x00" * 16,
    "GZIP": b"\x1f\x8b\x08" + b"\x00" * 16,
    "7Z": b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16,
    "RAR": b"Rar!\x1a\x07\x00" + b"\x00" * 16,
    "MP3": b"ID3\x03\x00" + b"\x00" * 16,
    "OGG": b"OggS" + b"\x00" * 16,
    "SQLITE": b"SQLite format 3\x00" + b"\x00" * 16,
    "WEBP": b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 8,
    "WAV": b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 8,
    "MP4/MOV": b"\x00\x00\x00\x18ftypisom" + b"\x00" * 8,
    "ICC": b"\x00" * 36 + b"acsp" + b"\x00" * 16,
    "TAR": b"\x00" * 257 + b"ustar" + b"\x00" * 16,
}


@pytest.mark.parametrize("fmt", sorted(SIGNATURES))
def test_r2_known_binary_blocked_even_when_renamed(ctx, fmt):
    findings = cg.scan_blob("docs/notes.txt", SIGNATURES[fmt], ctx)
    assert fired(findings, "R2"), f"{fmt} disguised as .txt was not blocked"


def test_r2_pdf_header_after_junk_bytes(ctx):
    """A PDF header does not have to be at offset zero to count."""
    data = bytes(range(200)) + PDF_MAGIC + b"\n"
    findings = cg.scan_blob("notes.txt", data, ctx)
    assert fired(findings, "R2")


def test_r1_unknown_binary_blocked(ctx):
    """Content that is not valid UTF-8 is refused even with no known signature."""
    findings = cg.scan_blob("notes.txt", b"\x80\x81\x82\x83" * 64, ctx)
    assert fired(findings, "R1")
    assert not fired(findings, "R2")


def test_r1_binary_allowlist_permits_non_utf8(tmp_path):
    ctx = make_context(
        tmp_path / "lists",
        config=(
            "[limits]\nmax_file_bytes = 524288\nhard_max_file_bytes = 2097152\n"
            "base64_run_min = 1024\ndata_uri_base64_min = 256\n\n"
            '[allowlists]\nbinary = ["assets/blob.bin"]\nsize = []\n'
        ),
    )
    findings = cg.scan_blob("assets/blob.bin", b"\x80\x81\x82\x83" * 64, ctx)
    assert not fired(findings, "R1")


def test_r3_svg_blocked_by_content(ctx):
    body = b'<?xml version="1.0"?>' + SVG_OPEN + b' xmlns="x"/>'
    findings = cg.scan_blob("diagram.txt", body, ctx)
    assert fired(findings, "R3")


@pytest.mark.parametrize("suffix", [".ipynb", ".eps", ".ai", ".indd", ".idml"])
def test_r3_blocked_extensions(ctx, suffix):
    findings = cg.scan_blob(f"notebook{suffix}", b"harmless text\n", ctx)
    assert fired(findings, "R3")


# --------------------------------------------------------------------------
# R4-R6  names, size, embedded payloads
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(cg.BLOCKED_BASENAMES))
def test_r4_blocked_basenames(ctx, name):
    findings = cg.scan_blob(f"data/{name}", b"{}\n", ctx)
    assert fired(findings, "R4")


def test_r4_similar_name_is_allowed(ctx):
    findings = cg.scan_blob("data/manifest.example.json", b"{}\n", ctx)
    assert not fired(findings, "R4")


def test_r5_oversized_file_blocked(ctx):
    findings = cg.scan_blob("big.txt", b"x" * (513 * 1024), ctx)
    assert fired(findings, "R5")


def test_r5_allowlisted_lockfile_passes(ctx):
    findings = cg.scan_blob("uv.lock", b"x" * (513 * 1024), ctx)
    assert not fired(findings, "R5")


def test_r5_allowlisted_path_still_has_a_hard_cap(ctx):
    findings = cg.scan_blob("uv.lock", b"x" * (2 * 1024 * 1024 + 1), ctx)
    assert fired(findings, "R5")


def test_r6_base64_run(ctx):
    findings = cg.scan_blob("payload.txt", b"PAYLOAD = " + b"A" * 1024 + b"\n", ctx)
    assert fired(findings, "R6")


def test_r6_short_base64_run_is_allowed(ctx):
    findings = cg.scan_blob("payload.txt", b"PAYLOAD = " + b"A" * 512 + b"\n", ctx)
    assert not fired(findings, "R6")


def test_r6_data_uri(ctx):
    data = b"background: url(data:image/png;base64," + b"A" * 300 + b")\n"
    findings = cg.scan_blob("style.txt", data, ctx)
    assert fired(findings, "R6")


# --------------------------------------------------------------------------
# R7  phrase -- the alpha sequence, where digits are invisible
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("as written", "the zorblax sits here"),
        ("uppercase", "THE ZORBLAX SITS HERE"),
        ("title case", "The Zorblax sits"),
        ("punctuation", "a (zorblax) here"),
        ("full-width", "\uff5a\uff4f\uff52\uff42\uff4c\uff41\uff58"),
    ],
)
def test_phrase_unigram_variants(ctx, label, text):
    assert fired(cg.scan_text("s.txt", text, ctx), "R7"), f"{label} was not matched"


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("as written", "the quux frobnitz unit"),
        ("uppercase", "THE QUUX FROBNITZ UNIT"),
        ("camelCase", "QuuxFrobnitz"),
        ("hyphenated", "the quux-frobnitz unit"),
        ("dotted", "quux.frobnitz."),
        ("snake_case", "quux_frobnitz"),
        ("across a newline", "quux\nfrobnitz"),
        ("a year between the words", "quux 2026 frobnitz"),
    ],
)
def test_phrase_variants_are_matched(ctx, label, text):
    assert fired(cg.scan_text("s.txt", text, ctx), "R7"), f"{label} was not matched"


@pytest.mark.parametrize(
    "text",
    ["quux big frobnitz", "quuxy frobnitz", "quux frobnitzes", "zorblaxian", "prezorblax", "zorbla"],
)
def test_phrase_near_misses_are_not_matched(ctx, text):
    """Matching is token equality, never substring."""
    assert not fired(cg.scan_text("s.txt", text, ctx), "R7")


def test_a_digit_is_invisible_to_a_phrase(ctx):
    """The alpha sequence skips digits, so a year between the words is ignored."""
    tokens = cg.tokenize_text("quux 2026 frobnitz")
    assert [token.value for token in cg.alpha_tokens(tokens)] == ["quux", "frobnitz"]


# --------------------------------------------------------------------------
# R7  mixed -- a term carrying a digit matches only where the digit is
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["qx7", "QX7", "qx-7", "qx 7", "QX7Mod", "the qx7 plate"])
def test_mixed_variants_are_matched(ctx, text):
    assert fired(cg.scan_text("s.txt", text, ctx), "R7")


@pytest.mark.parametrize("text", ["for qx in items", "qx8", "aqx7", "prqx 7", "qx"])
def test_mixed_does_not_degrade_to_its_letters(ctx, text):
    """The regression this format exists to prevent.

    Dropping the digit would leave a bare two-letter entry, and every ordinary
    use of that name as an identifier would be refused.
    """
    assert not fired(cg.scan_text("s.txt", text, ctx), "R7")


def test_a_digit_term_never_reports_a_phrase_kind(ctx):
    findings = [f for f in cg.scan_text("s.txt", "qx7", ctx) if f.rule == "R7"]
    assert findings
    assert all("phrase" not in finding.kinds for finding in findings)


# --------------------------------------------------------------------------
# R7  compact -- inside one chunk, and never across whitespace
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["GloopWorks", "gloop-works", "gloop_works", "gloop.works", "gloopworks", "x_gloopworks_y"],
)
def test_compact_variants_are_matched(ctx, text):
    assert fired(cg.scan_text("s.txt", text, ctx), "R7")


@pytest.mark.parametrize("text", ["the gloop works well", "gloop, works", "gloop\nworks"])
def test_compact_never_crosses_whitespace(ctx, text):
    """A compound of common words must not fire on prose that merely contains them."""
    assert not fired(cg.scan_text("s.txt", text, ctx), "R7")


def test_compact_supersedes_the_v1_joined_run_check(ctx):
    """An internal capital needed a dedicated re-joining pass before; compact covers it."""
    assert fired(cg.scan_text("s.txt", "the ZorBlax plate", ctx), "R7")
    assert [token.value for token in cg.tokenize_text("ZorBlax")] == ["zor", "blax"]


def test_compact_matches_the_concatenated_spelling_of_a_spaced_term(ctx):
    """Deliberately not matched before this format; compact matches it now."""
    findings = [f for f in cg.scan_text("s.txt", "quuxfrobnitz", ctx) if f.rule == "R7"]
    assert findings
    assert findings[0].kinds == ("compact",)


# --------------------------------------------------------------------------
# R7  spaced single letters, reported position, and the kinds themselves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["z q v", "z. q. v.", "Z.Q.V.", "zqv", "marked z q v here"])
def test_spaced_letter_term_variants(ctx, text):
    assert fired(cg.scan_text("s.txt", text, ctx), "R7")


@pytest.mark.parametrize("text", ["z q x v", "z v q"])
def test_spaced_letter_near_misses(ctx, text):
    assert not fired(cg.scan_text("s.txt", text, ctx), "R7")


def test_finding_names_every_kind_that_fired(ctx):
    """One span, one finding, naming each kind -- not one finding per kind."""
    findings = [f for f in cg.scan_text("s.txt", "QuuxFrobnitz", ctx) if f.rule == "R7"]
    assert len(findings) == 1
    assert findings[0].kinds == ("phrase", "compact")


def test_r7_reports_position_of_the_first_token(ctx):
    findings = [
        f for f in cg.scan_text("s.txt", "one\ntwo quux frobnitz\n", ctx) if f.rule == "R7"
    ]
    assert findings
    assert (findings[0].line, findings[0].col) == (2, 5)


def test_r7_matches_the_path_itself(ctx):
    findings = cg.scan_path("docs/zorblax/readme.md", ctx)
    assert fired(findings, "R7")
    assert findings[0].line == 0


# --------------------------------------------------------------------------
# R8  numbers and hex values
# --------------------------------------------------------------------------


@pytest.fixture
def number_ctx(tmp_path):
    return make_context(tmp_path / "lists", nums=("1143", "2361.999"), hexes=("8d8f91",))


@pytest.mark.parametrize("text", ["1,143.000", "1143", "1_143", "1,143", "1143.0"])
def test_r8_number_forms_normalise_to_the_same_fingerprint(number_ctx, text):
    assert fired(cg.scan_text("s.txt", f"value {text} mm", number_ctx), "R8")


@pytest.mark.parametrize("text", ["11430", "114.3", "1143.5", "21143"])
def test_r8_different_numbers_do_not_match(number_ctx, text):
    assert not fired(cg.scan_text("s.txt", f"value {text} mm", number_ctx), "R8")


def test_r8_fraction_is_significant(number_ctx):
    assert fired(cg.scan_text("s.txt", "2361.999", number_ctx), "R8")
    assert not fired(cg.scan_text("s.txt", "2361.998", number_ctx), "R8")


@pytest.mark.parametrize("text", ["#8D8F91", "8d8f91", "#8d8f91"])
def test_r8_hex_forms_match(number_ctx, text):
    assert fired(cg.scan_text("s.txt", f"fill {text};", number_ctx), "R8")


def test_r8_sha256_does_not_match_a_short_hex_fingerprint(number_ctx):
    digest = hashlib.sha256(b"unrelated").hexdigest()
    assert not fired(cg.scan_text("s.txt", digest, number_ctx), "R8")


def test_r8_greyscale_style_hex_without_letters_is_not_a_token(number_ctx):
    assert not fired(cg.scan_text("s.txt", "888888", number_ctx), "R8")


# --------------------------------------------------------------------------
# R9, R10, R11
# --------------------------------------------------------------------------


def test_r9_blocked_file_content(tmp_path):
    payload = b"the exact bytes of a protected file\n"
    ctx = make_context(
        tmp_path / "lists", files=(hashlib.sha256(payload).hexdigest(),)
    )
    assert fired(cg.scan_blob("renamed.txt", payload, ctx), "R9")
    assert not fired(cg.scan_blob("other.txt", payload + b"x", ctx), "R9")


@pytest.fixture
def shingle_ctx(tmp_path):
    return make_context(tmp_path / "lists", shingles=(SHINGLE,))


def test_r10_ten_word_copy_detected(shingle_ctx):
    assert fired(cg.scan_text("s.txt", f"intro {SHINGLE} outro", shingle_ctx), "R10")


def test_r10_nine_word_copy_not_detected(shingle_ctx):
    nine = " ".join(SHINGLE.split()[:9])
    assert not fired(cg.scan_text("s.txt", nine, shingle_ctx), "R10")


def test_r10_copy_spanning_two_lines_detected(shingle_ctx):
    words = SHINGLE.split()
    broken = " ".join(words[:5]) + "\n" + " ".join(words[5:])
    assert fired(cg.scan_text("s.txt", broken, shingle_ctx), "R10")


def test_r10_digits_between_words_do_not_break_a_shingle(shingle_ctx):
    """Shingles run over the alpha sequence, so interleaved numbers are ignored."""
    numbered = " ".join(
        f"{word} {index}" for index, word in enumerate(SHINGLE.split())
    )
    assert fired(cg.scan_text("s.txt", numbered, shingle_ctx), "R10")


@pytest.mark.parametrize(
    "path",
    ["scripts/thing.py", "tests/thing.py", "tools/thing.py", "matsurvey/thing.py", ".githooks/pre-commit"],
)
def test_r11_missing_spdx_header(ctx, path):
    assert fired(cg.scan_blob(path, b"print('hi')\n", ctx), "R11")


def test_r11_present_spdx_header(ctx):
    body = b"#!/usr/bin/env python3\n# SPDX-License-Identifier: AGPL-3.0-or-later\n"
    assert not fired(cg.scan_blob("scripts/thing.py", body, ctx), "R11")


def test_r11_not_required_outside_first_party_directories(ctx):
    assert not fired(cg.scan_blob("docs/notes.md", b"text\n", ctx), "R11")
    assert not fired(cg.scan_blob("guard/config.toml", b"x = 1\n", ctx), "R11")


# --------------------------------------------------------------------------
# modes
# --------------------------------------------------------------------------


@pytest.fixture
def cli_lists(tmp_path: Path) -> Path:
    """Lists hashed with the shipped salt, so the CLI can load them.

    The terms are still invented; only the salt is real.
    """
    return write_lists(
        tmp_path / "cli-lists",
        salt=cg.SALT,
        terms=("zorblax", "quux frobnitz"),
    )


def test_staged_reads_the_index_not_the_working_tree(git_repo, cli_lists):
    """A clean index stays clean however dirty the working tree is."""
    (git_repo / "notes.txt").write_text("clean content\n", encoding="utf-8")
    git(git_repo, "add", "notes.txt")
    (git_repo / "notes.txt").write_text("zorblax in the working tree\n", encoding="utf-8")
    assert cg.main(["--staged", "--lists", str(cli_lists)]) == 0


def test_staged_finds_content_the_working_tree_no_longer_has(git_repo, cli_lists):
    """The reverse direction: a dirty index is caught after the file is cleaned."""
    (git_repo / "notes.txt").write_text("zorblax staged\n", encoding="utf-8")
    git(git_repo, "add", "notes.txt")
    (git_repo / "notes.txt").write_text("clean again\n", encoding="utf-8")
    assert cg.main(["--staged", "--lists", str(cli_lists)]) == 1


def test_staged_is_clean_for_acceptable_content(git_repo, cli_lists):
    (git_repo / "notes.txt").write_text("a perfectly ordinary note\n", encoding="utf-8")
    git(git_repo, "add", "notes.txt")
    assert cg.main(["--staged", "--lists", str(cli_lists)]) == 0


def test_staged_blocks_a_disguised_binary(git_repo, cli_lists):
    (git_repo / "notes.txt").write_bytes(bytes(range(200)) + PDF_MAGIC + b"\n")
    git(git_repo, "add", "notes.txt")
    assert cg.main(["--staged", "--lists", str(cli_lists)]) == 1


def test_commit_msg_mode(tmp_path, cli_lists):
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text("Add zorblax support\n", encoding="utf-8")
    assert cg.main(["--commit-msg", str(message), "--lists", str(cli_lists)]) == 1
    message.write_text("Add content guard\n", encoding="utf-8")
    assert cg.main(["--commit-msg", str(message), "--lists", str(cli_lists)]) == 0


def test_text_mode_reads_stdin(monkeypatch, cli_lists):
    monkeypatch.setattr("sys.stdin", io.StringIO("a zorblax appears"))
    assert cg.main(["--text", "-", "--lists", str(cli_lists)]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("nothing to see"))
    assert cg.main(["--text", "-", "--lists", str(cli_lists)]) == 0


def test_range_mode_scans_messages_and_blobs(git_repo, cli_lists):
    (git_repo / "a.txt").write_text("first\n", encoding="utf-8")
    git(git_repo, "add", "a.txt")
    git(git_repo, "commit", "-q", "-m", "Add first file")
    base = git(git_repo, "rev-parse", "HEAD").strip()

    (git_repo / "b.txt").write_text("zorblax landed here\n", encoding="utf-8")
    git(git_repo, "add", "b.txt")
    git(git_repo, "commit", "-q", "-m", "Add second file")

    assert cg.main(["--range", f"{base}..HEAD", "--lists", str(cli_lists)]) == 1
    assert cg.main(["--range", f"{base}..{base}", "--lists", str(cli_lists)]) == 0


def test_range_mode_catches_a_commit_message(git_repo, cli_lists):
    (git_repo / "a.txt").write_text("first\n", encoding="utf-8")
    git(git_repo, "add", "a.txt")
    git(git_repo, "commit", "-q", "-m", "Add first file")
    base = git(git_repo, "rev-parse", "HEAD").strip()

    (git_repo / "b.txt").write_text("ordinary\n", encoding="utf-8")
    git(git_repo, "add", "b.txt")
    git(git_repo, "commit", "-q", "-m", "Add quux frobnitz handling")

    assert cg.main(["--range", f"{base}..HEAD", "--lists", str(cli_lists)]) == 1


def test_tree_and_history_modes(git_repo, cli_lists):
    (git_repo / "a.txt").write_text("zorblax\n", encoding="utf-8")
    git(git_repo, "add", "a.txt")
    git(git_repo, "commit", "-q", "-m", "Add a file")
    assert cg.main(["--tree", "--lists", str(cli_lists)]) == 1
    assert cg.main(["--history", "--lists", str(cli_lists)]) == 1

    git(git_repo, "rm", "-q", "a.txt")
    git(git_repo, "commit", "-q", "-m", "Remove the file")
    assert cg.main(["--tree", "--lists", str(cli_lists)]) == 0
    assert cg.main(["--history", "--lists", str(cli_lists)]) == 1, (
        "history must still see the blob the tree no longer references"
    )


def test_push_mode_reads_refs_from_stdin(git_repo, cli_lists, monkeypatch):
    (git_repo / "a.txt").write_text("ordinary\n", encoding="utf-8")
    git(git_repo, "add", "a.txt")
    git(git_repo, "commit", "-q", "-m", "Add a file")
    head = git(git_repo, "rev-parse", "HEAD").strip()

    clean = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(clean))
    assert cg.main(["--push", "--lists", str(cli_lists)]) == 0

    dirty = f"refs/heads/zorblax {head} refs/heads/zorblax {'0' * 40}\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(dirty))
    assert cg.main(["--push", "--lists", str(cli_lists)]) == 1


def test_ci_masks_findings(capsys, cli_lists, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("a zorblax appears"))
    assert cg.main(["--text", "-", "--lists", str(cli_lists), "--ci"]) == 1
    captured = capsys.readouterr()
    assert "(masked)" in captured.out
    assert "zorblax" not in captured.out
    assert "zorblax" not in captured.err


def test_local_output_shows_the_offending_text(capsys, cli_lists, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("a zorblax appears"))
    assert cg.main(["--text", "-", "--lists", str(cli_lists)]) == 1
    assert "zorblax" in capsys.readouterr().out


def test_ci_redacts_a_denylisted_path(capsys, git_repo, cli_lists):
    (git_repo / "zorblax.txt").write_text("ordinary content\n", encoding="utf-8")
    git(git_repo, "add", "zorblax.txt")
    assert cg.main(["--staged", "--lists", str(cli_lists), "--ci"]) == 1
    captured = capsys.readouterr()
    assert "zorblax" not in captured.out, "a denylisted path leaked into masked output"
    assert "<redacted:" in captured.out


# --------------------------------------------------------------------------
# fail closed
# --------------------------------------------------------------------------


def test_corrupt_denylist_exits_two(cli_lists):
    write_raw(cli_lists / cg.DENYLIST_NAME, ["phrase:not-a-hash"], cg.SALT)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_corrupt_shingle_list_exits_two(cli_lists):
    write_raw(cli_lists / cg.SHINGLES_NAME, ["zzzz"], cg.SALT)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_missing_config_exits_two(cli_lists):
    (cli_lists / "config.toml").unlink()
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_missing_lists_directory_exits_two(tmp_path):
    assert cg.main(["--text", "hello", "--lists", str(tmp_path / "absent")]) == 2


def test_incomplete_config_exits_two(cli_lists):
    (cli_lists / "config.toml").write_text("[limits]\n[allowlists]\n", encoding="utf-8")
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_no_mode_selected_exits_two(cli_lists):
    assert cg.main(["--lists", str(cli_lists)]) == 2


def test_unreadable_denylist_exits_two(cli_lists):
    (cli_lists / cg.DENYLIST_NAME).unlink()
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


# --------------------------------------------------------------------------
# list format -- a list the guard cannot vouch for must never read as clean
# --------------------------------------------------------------------------


def test_missing_header_exits_two(cli_lists):
    write_raw(cli_lists / cg.DENYLIST_NAME, ["phrase:" + "0" * 64], cg.SALT, header=[])
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_wrong_tokenizer_version_exits_two(cli_lists):
    header = list(cg.list_header(cg.SALT))
    header[2] = "# tokenizer: 1"
    write_raw(cli_lists / cg.DENYLIST_NAME, [], cg.SALT, header=header)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_wrong_format_version_exits_two(cli_lists):
    header = list(cg.list_header(cg.SALT))
    header[1] = "# format: 1"
    write_raw(cli_lists / cg.DENYLIST_NAME, [], cg.SALT, header=header)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_wrong_salt_exits_two(cli_lists):
    write_raw(cli_lists / cg.DENYLIST_NAME, [], "some-other-salt")
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_unknown_kind_exits_two(cli_lists):
    write_raw(cli_lists / cg.DENYLIST_NAME, ["sideways:" + "0" * 64], cg.SALT)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_unsorted_entries_exit_two(cli_lists):
    write_raw(
        cli_lists / cg.DENYLIST_NAME,
        ["phrase:" + "b" * 64, "phrase:" + "a" * 64],
        cg.SALT,
    )
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_duplicate_entry_exits_two(cli_lists):
    entry = "phrase:" + "a" * 64
    write_raw(cli_lists / cg.DENYLIST_NAME, [entry, entry], cg.SALT)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_comment_after_the_header_exits_two(cli_lists):
    write_raw(cli_lists / cg.DENYLIST_NAME, ["# a note", "phrase:" + "a" * 64], cg.SALT)
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


@pytest.mark.parametrize("stale", ["denylist.v1.txt", "shingles.v1.txt", "denylist.v9.txt"])
def test_a_list_from_another_format_exits_two(cli_lists, stale):
    """A leftover list is refused rather than quietly ignored."""
    (cli_lists / stale).write_text("# leftover\n", encoding="utf-8")
    assert cg.main(["--text", "hello", "--lists", str(cli_lists)]) == 2


def test_a_list_built_under_a_different_salt_matches_nothing_and_is_refused(tmp_path):
    """The failure this format exists to prevent: skew that reads as clean."""
    lists = write_lists(tmp_path / "skewed", salt="another-salt", terms=("zorblax",))
    assert cg.main(["--text", "zorblax", "--lists", str(lists)]) == 2


# --------------------------------------------------------------------------
# tokenizer contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("RoboBot", ["robo", "bot"]),
        ("ABCDef", ["abc", "def"]),
        ("HTTPServer", ["http", "server"]),
        ("qx7", ["qx", "7"]),
        ("QX7Mod", ["qx", "7", "mod"]),
        ("v2Parser", ["v", "2", "parser"]),
        ("zor_blax-9.q", ["zor", "blax", "9", "q"]),
        ("ABC", ["abc"]),
        ("A-B-C", ["a", "b", "c"]),
        ("abc_def", ["abc", "def"]),
        ("\uff21\uff22", ["ab"]),
    ],
)
def test_tokenizer_contract(text, expected):
    assert [token.value for token in cg.tokenize_text(text)] == expected


def test_one_chunk_keeps_one_index():
    """Punctuation and underscores divide runs without ending the chunk."""
    assert {token.chunk for token in cg.tokenize_text("zor_blax-9.q")} == {0}


def test_whitespace_starts_a_new_chunk():
    assert [token.chunk for token in cg.tokenize_text("zor blax")] == [0, 1]


def test_digit_tokens_are_flagged():
    assert [token.is_digit for token in cg.tokenize_text("qx7")] == [False, True]


def test_token_offsets_locate_the_first_token():
    tokens = cg.tokenize_text("one\ntwo QuuxFrobnitz")
    index = cg.LineIndex("one\ntwo QuuxFrobnitz")
    quux = next(token for token in tokens if token.value == "quux")
    assert index.locate(quux.offset) == (2, 5)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1,143.000", ["1143"]),
        ("2361.999", ["2361.999"]),
        ("1_143", ["1143"]),
        ("11430", ["11430"]),
        ("0.50", ["0.5"]),
    ],
)
def test_number_token_contract(text, expected):
    assert [t.value for t in cg.number_tokens(cg.normalize(text))] == expected


def test_salt_is_not_read_from_the_environment(monkeypatch):
    """The shipped salt is a constant; no environment variable can weaken it."""
    monkeypatch.setenv("MATSURVEY_GUARD_SALT", "attacker-supplied")
    assert cg.salted("phrase", "zorblax") == cg.salted("phrase", "zorblax", cg.SALT)
    assert cg.salted("phrase", "zorblax", TEST_SALT) != cg.salted("phrase", "zorblax")


# --------------------------------------------------------------------------
# builder -- which kinds a term line produces
# --------------------------------------------------------------------------


def kinds_for(line: str) -> set[str]:
    entries, _count = bd.term_entries(line, TEST_SALT)
    return {entry.split(":", 1)[0] for entry in entries}


def test_builder_emits_phrase_and_compact_for_an_alpha_term():
    assert kinds_for("gloop works") == {"phrase", "compact"}


def test_builder_emits_mixed_instead_of_phrase_for_a_digit_term():
    """The heart of the fix: a digit-bearing term gets no alpha-only entry."""
    assert kinds_for("qx7") == {"mixed", "compact"}


def test_builder_emits_compact_only_for_a_long_term():
    entries, count = bd.term_entries("alpha bravo charlie delta echo", TEST_SALT)
    assert count == 5
    assert {entry.split(":", 1)[0] for entry in entries} == {"compact"}


def test_builder_refuses_a_term_longer_than_the_compact_window():
    with pytest.raises(cg.GuardError):
        bd.term_entries("a b c d e f g h i", TEST_SALT)


def test_builder_refuses_a_line_with_no_tokens():
    with pytest.raises(cg.GuardError):
        bd.term_entries("---", TEST_SALT)


def test_builder_output_reports_counts_without_plaintext(tmp_path, capsys):
    config = tmp_path / "config"
    config.mkdir()
    (config / "terms.txt").write_text("gloopworks\nqx7\n", encoding="utf-8")
    (config / "fingerprints.txt").write_text("", encoding="utf-8")
    (config / "files.txt").write_text("", encoding="utf-8")
    out_dir = tmp_path / "out"
    assert (
        bd.main(
            [
                "--terms", str(config / "terms.txt"),
                "--fingerprints", str(config / "fingerprints.txt"),
                "--files", str(config / "files.txt"),
                "--corpus", str(tmp_path / "absent-corpus"),
                "--out", str(out_dir),
                "--salt", TEST_SALT,
            ]
        )
        == 0
    )
    printed = capsys.readouterr().out
    assert "gloopworks" not in printed
    assert "qx7" not in printed
    assert "phrase" in printed and "mixed" in printed and "compact" in printed


def test_builder_output_is_loadable_by_the_guard(tmp_path):
    """Round trip: what the builder writes is what the guard accepts."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "terms.txt").write_text("gloopworks\n", encoding="utf-8")
    (config / "fingerprints.txt").write_text("", encoding="utf-8")
    (config / "files.txt").write_text("", encoding="utf-8")
    out_dir = tmp_path / "out"
    assert bd.main([
        "--terms", str(config / "terms.txt"),
        "--fingerprints", str(config / "fingerprints.txt"),
        "--files", str(config / "files.txt"),
        "--corpus", str(tmp_path / "absent-corpus"),
        "--out", str(out_dir),
        "--salt", TEST_SALT,
    ]) == 0
    (out_dir / "config.toml").write_text(
        (Path(__file__).resolve().parents[2] / "guard" / "config.toml").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    lists, _config = cg.load_all(out_dir, salt=TEST_SALT)
    assert lists.compacts and not lists.mixed
