#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Verify every installed distribution against guard/licenses.toml.

Package metadata states a license in three different ways depending on how old
the packaging is: a PEP 639 ``License-Expression``, a trove classifier, or a
free-text ``License`` field.  Only the first is unambiguous.  For the other two
the mapping to an SPDX expression is a judgement, so this script records the
exact metadata string it based the decision on and fails if that string ever
changes.  Entries whose SPDX expression had to be interpreted are marked in the
file and reported here, because a human has to stand behind them.

A distribution that is installed but unlisted, listed but not installed, or
whose metadata has changed is a failure.  So is an SPDX expression outside the
allowed set.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from importlib import metadata
from pathlib import Path

NOTICE_INTRO = """\
matsurvey
Copyright 2026 lumduan and matsurvey contributors

Licensed under AGPL-3.0-or-later. See LICENSE for the full text.

matsurvey depends on the third-party components listed below. They are not
distributed with this repository; the versions shown are the ones resolved in
uv.lock. Each remains under its own license, held by its own authors.
"""

# Classifiers with exactly one SPDX meaning. Anything else is an interpretation:
# "BSD License" does not say whether it is 2- or 3-clause, and "Apache Software
# License" does not say which version.
UNAMBIGUOUS_CLASSIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Apache Software License": None,
    "License :: OSI Approved :: BSD License": None,
}


def evidence_for(dist: metadata.Distribution) -> tuple[str | None, str]:
    """Return ``(unambiguous SPDX or None, the exact metadata string used)``."""
    message = dist.metadata
    expression = message.get("License-Expression")
    if expression and expression.strip():
        value = expression.strip()
        return value, f"License-Expression: {value}"

    classifiers = [
        item
        for item in (message.get_all("Classifier") or [])
        if item.startswith("License ::")
    ]
    if classifiers:
        first = sorted(classifiers)[0]
        return UNAMBIGUOUS_CLASSIFIERS.get(first), f"Classifier: {first}"

    free_text = (message.get("License") or "").strip()
    if free_text:
        collapsed = " ".join(free_text.split())
        if len(collapsed) > 120:
            collapsed = collapsed[:120] + "..."
        return None, f"License: {collapsed}"

    return None, "License: (absent)"


def installed() -> dict[str, metadata.Distribution]:
    found: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            found[name] = dist
    return found


def load_policy(path: Path) -> tuple[set[str], dict[str, dict[str, object]]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    allowed = data.get("allowed")
    packages = data.get("packages")
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise SystemExit(f"{path}: 'allowed' must be a list of SPDX expressions")
    if not isinstance(packages, dict):
        raise SystemExit(f"{path}: '[packages]' table is required")
    return set(allowed), packages


def check(path: Path) -> tuple[list[str], list[tuple[str, str, str]]]:
    """Return (problems, rows). Rows are (name, version, spdx)."""
    allowed, packages = load_policy(path)
    dists = installed()
    problems: list[str] = []
    rows: list[tuple[str, str, str]] = []

    for name in sorted(set(packages) - set(dists)):
        problems.append(f"{name}: listed in {path.name} but not installed")

    for name in sorted(dists):
        dist = dists[name]
        declared = packages.get(name)
        if declared is None:
            problems.append(f"{name}: installed but not listed in {path.name}")
            continue
        spdx = declared.get("spdx")
        stored = declared.get("evidence")
        unambiguous, actual = evidence_for(dist)
        if not isinstance(spdx, str) or not isinstance(stored, str):
            problems.append(f"{name}: entry needs both 'spdx' and 'evidence'")
            continue
        if actual != stored:
            problems.append(
                f"{name}: license metadata changed\n"
                f"    recorded: {stored}\n"
                f"    found:    {actual}"
            )
            continue
        if unambiguous is not None and unambiguous != spdx:
            problems.append(
                f"{name}: metadata states {unambiguous}, {path.name} says {spdx}"
            )
            continue
        if unambiguous is None and not declared.get("interpreted"):
            problems.append(
                f"{name}: metadata is ambiguous, so the entry must set interpreted = true"
            )
            continue
        if spdx not in allowed:
            problems.append(f"{name}: {spdx} is not in the allowed set")
            continue
        rows.append((name, dist.version, spdx))

    return problems, rows


def render_notice(rows: list[tuple[str, str, str]]) -> str:
    width = max((len(name) for name, _, _ in rows), default=0)
    lines = [NOTICE_INTRO]
    for name, version, spdx in rows:
        lines.append(f"  {name.ljust(width)}  {version:<10}  {spdx}")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--licenses", type=Path, default=root / "guard" / "licenses.toml")
    parser.add_argument("--notice", type=Path, default=root / "NOTICE")
    parser.add_argument("--write-notice", action="store_true", help="regenerate NOTICE")
    parser.add_argument("--check-notice", action="store_true", help="fail if NOTICE has drifted")
    args = parser.parse_args(argv)

    problems, rows = check(args.licenses)
    if problems:
        print("check-licenses: failed", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    _, policy = load_policy(args.licenses)
    interpreted = [name for name, _, _ in rows if policy[name].get("interpreted")]

    if args.write_notice:
        args.notice.write_text(render_notice(rows), encoding="utf-8")
        print(f"check-licenses: wrote {args.notice.name} with {len(rows)} component(s)")
        return 0

    if args.check_notice:
        expected = render_notice(rows)
        current = args.notice.read_text(encoding="utf-8") if args.notice.exists() else ""
        if current != expected:
            print(
                f"check-licenses: {args.notice.name} has drifted; "
                "run check_licenses.py --write-notice",
                file=sys.stderr,
            )
            return 1
        print(f"check-licenses: {args.notice.name} is current")
        return 0

    print(f"check-licenses: {len(rows)} component(s) verified against {args.licenses.name}")
    if interpreted:
        print(f"check-licenses: {len(interpreted)} entry(ies) interpreted by hand: "
              f"{', '.join(interpreted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
