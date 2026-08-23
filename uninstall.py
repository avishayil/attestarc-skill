#!/usr/bin/env python3
"""Uninstall the AttestArc skill from Claude Code and/or Cursor.

Removes only the ``attestarc`` skill directory, and only after confirming it is
an AttestArc skill. Never touches unrelated host configuration.

Examples::

    python uninstall.py --platform claude --scope project
    python uninstall.py --platform both   --scope user
    python uninstall.py --platform cursor --scope project --target /path/to/repo
"""

from __future__ import annotations

import argparse
import shutil
import sys

# Reuse resolution/validation from install.py so both stay consistent.
from install import (  # noqa: E402
    InstallError,
    _is_our_skill,
    dest_dir,
    read_version,
)


def uninstall_one(platform: str, scope: str, target, dry_run: bool) -> dict:
    dest = dest_dir(platform, scope, target)
    import os
    if not os.path.isdir(dest):
        return {"platform": platform, "dest": dest, "action": "absent"}
    if not _is_our_skill(dest):
        raise InstallError(
            f"{dest} is not an AttestArc skill; refusing to remove it."
        )
    version = read_version(dest)
    if not dry_run:
        shutil.rmtree(dest)
    return {"platform": platform, "dest": dest,
            "action": "would-remove" if dry_run else "removed",
            "version": version}


def _platforms(arg: str):
    return ["claude", "cursor"] if arg == "both" else [arg]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Uninstall the AttestArc skill")
    p.add_argument("--platform", choices=["claude", "cursor", "both"],
                   default="claude")
    p.add_argument("--scope", choices=["project", "user"], default="project")
    p.add_argument("--target", default=None)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    try:
        for platform in _platforms(args.platform):
            result = uninstall_one(platform, args.scope, args.target,
                                   args.dry_run)
            verb = result["action"].replace("-", " ")
            v = f" v{result['version']}" if result.get("version") else ""
            print(f"{platform}: {verb}{v} -> {result['dest']}")
    except InstallError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
