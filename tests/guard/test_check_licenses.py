# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Tests for the dependency license check."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

import check_licenses as cl

POLICY = """\
allowed = ["MIT", "BSD-3-Clause"]

[packages.alpha]
spdx = "MIT"
evidence = "License-Expression: MIT"
"""


class FakeMetadata(dict):
    def __init__(self, mapping: dict[str, str], classifiers: tuple[str, ...] = ()) -> None:
        super().__init__(mapping)
        self._classifiers = list(classifiers)

    def get_all(self, key: str):
        return self._classifiers if key == "Classifier" else None


@dataclass
class FakeDist:
    metadata: FakeMetadata
    version: str


def dist(name: str, version: str = "1.0", **fields) -> FakeDist:
    classifiers = fields.pop("classifiers", ())
    return FakeDist(FakeMetadata({"Name": name, **fields}, classifiers), version)


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "licenses.toml"
    path.write_text(POLICY, encoding="utf-8")
    return path


def install(monkeypatch, *dists: FakeDist) -> None:
    monkeypatch.setattr(
        cl, "installed", lambda: {d.metadata["Name"]: d for d in dists}
    )


def test_matching_environment_passes(policy, monkeypatch):
    install(monkeypatch, dist("alpha", **{"License-Expression": "MIT"}))
    problems, rows = cl.check(policy)
    assert problems == []
    assert rows == [("alpha", "1.0", "MIT")]


def test_unknown_package_fails(policy, monkeypatch):
    install(
        monkeypatch,
        dist("alpha", **{"License-Expression": "MIT"}),
        dist("beta", **{"License-Expression": "MIT"}),
    )
    problems, _ = cl.check(policy)
    assert any("beta" in problem and "not listed" in problem for problem in problems)


def test_listed_but_uninstalled_fails(policy, monkeypatch):
    install(monkeypatch)
    problems, _ = cl.check(policy)
    assert any("alpha" in problem and "not installed" in problem for problem in problems)


def test_changed_metadata_fails(policy, monkeypatch):
    install(monkeypatch, dist("alpha", **{"License-Expression": "BSD-3-Clause"}))
    problems, _ = cl.check(policy)
    assert any("metadata changed" in problem for problem in problems)


def test_expression_outside_the_allowed_set_fails(tmp_path, monkeypatch):
    path = tmp_path / "licenses.toml"
    path.write_text(
        'allowed = ["MIT"]\n\n[packages.alpha]\nspdx = "GPL-3.0-only"\n'
        'evidence = "License-Expression: GPL-3.0-only"\n',
        encoding="utf-8",
    )
    install(monkeypatch, dist("alpha", **{"License-Expression": "GPL-3.0-only"}))
    problems, _ = cl.check(path)
    assert any("not in the allowed set" in problem for problem in problems)


def test_ambiguous_classifier_must_be_marked_interpreted(tmp_path, monkeypatch):
    classifier = "License :: OSI Approved :: BSD License"
    path = tmp_path / "licenses.toml"
    path.write_text(
        f'allowed = ["BSD-3-Clause"]\n\n[packages.alpha]\nspdx = "BSD-3-Clause"\n'
        f'evidence = "Classifier: {classifier}"\n',
        encoding="utf-8",
    )
    install(monkeypatch, dist("alpha", classifiers=(classifier,)))
    problems, _ = cl.check(path)
    assert any("interpreted = true" in problem for problem in problems)

    path.write_text(
        f'allowed = ["BSD-3-Clause"]\n\n[packages.alpha]\nspdx = "BSD-3-Clause"\n'
        f'evidence = "Classifier: {classifier}"\ninterpreted = true\n'
        'note = "upstream ships the 3-clause text"\n',
        encoding="utf-8",
    )
    problems, rows = cl.check(path)
    assert problems == []
    assert rows == [("alpha", "1.0", "BSD-3-Clause")]


def test_unambiguous_classifier_that_disagrees_fails(tmp_path, monkeypatch):
    classifier = "License :: OSI Approved :: MIT License"
    path = tmp_path / "licenses.toml"
    path.write_text(
        f'allowed = ["BSD-3-Clause"]\n\n[packages.alpha]\nspdx = "BSD-3-Clause"\n'
        f'evidence = "Classifier: {classifier}"\n',
        encoding="utf-8",
    )
    install(monkeypatch, dist("alpha", classifiers=(classifier,)))
    problems, _ = cl.check(path)
    assert any("metadata states MIT" in problem for problem in problems)


def test_notice_drift_fails(policy, tmp_path, monkeypatch):
    install(monkeypatch, dist("alpha", **{"License-Expression": "MIT"}))
    notice = tmp_path / "NOTICE"
    argv = ["--licenses", str(policy), "--notice", str(notice)]

    assert cl.main(argv + ["--write-notice"]) == 0
    assert cl.main(argv + ["--check-notice"]) == 0

    notice.write_text(notice.read_text(encoding="utf-8") + "extra\n", encoding="utf-8")
    assert cl.main(argv + ["--check-notice"]) == 1


def test_missing_notice_fails_the_check(policy, tmp_path, monkeypatch):
    install(monkeypatch, dist("alpha", **{"License-Expression": "MIT"}))
    argv = ["--licenses", str(policy), "--notice", str(tmp_path / "absent")]
    assert cl.main(argv + ["--check-notice"]) == 1
