#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lumduan and matsurvey contributors
"""Point this clone's git hooks at the tracked hooks directory.

Run once after cloning.  The content guard runs from these hooks on every
commit and every push; a clone without them is not protected.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

HOOKS_DIR = ".githooks"
HOOKS = ("pre-commit", "commit-msg", "pre-push")


def main() -> int:
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if root.returncode != 0:
        print("install-hooks: not inside a git repository", file=sys.stderr)
        return 1
    repo = Path(root.stdout.strip())

    missing = [name for name in HOOKS if not (repo / HOOKS_DIR / name).is_file()]
    if missing:
        print(f"install-hooks: missing hooks: {', '.join(missing)}", file=sys.stderr)
        return 1

    for name in HOOKS:
        path = repo / HOOKS_DIR / name
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    subprocess.run(["git", "config", "core.hooksPath", HOOKS_DIR], cwd=repo, check=True)

    configured = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"],
        cwd=repo,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if configured != HOOKS_DIR:
        print(
            f"install-hooks: core.hooksPath is {configured!r}, expected {HOOKS_DIR!r}",
            file=sys.stderr,
        )
        return 1

    for name in HOOKS:
        path = repo / HOOKS_DIR / name
        if not os.access(path, os.X_OK):
            print(f"install-hooks: {name} is not executable", file=sys.stderr)
            return 1

    print(f"install-hooks: core.hooksPath = {configured}")
    print(f"install-hooks: {', '.join(HOOKS)} installed and executable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
