#!/usr/bin/env python3
"""Filesystem-path containment shared by AttestArc's helpers.

The repository under assessment is untrusted input. A symlink, an absolute path,
or a ``..`` traversal in the subject must never let a helper *read* or *write*
outside the assessed repository root. ``state.py`` already guards its writes with
this logic; the read helpers (``inspect_workflows.py``, ``inspect_git_diff.py``)
share it here so there is a single, tested containment rule.

Stdlib-only; no verdicts — this module only computes whether a path stays inside
a root. Callers decide how to react (refuse a write, skip a read, degrade to
``parse_partial``).
"""

from __future__ import annotations

import os


def resolve_within_root(path: str, root: str) -> tuple[str, str, bool]:
    """Resolve ``path`` and report whether it stays inside ``root``.

    Returns ``(resolved, root_real, within)`` where ``resolved`` is the fully
    resolved absolute path and ``root_real`` the resolved root.

    :func:`os.path.realpath` resolves every symlink along ``path`` — including a
    symlinked parent, an escaping *final-component* symlink, and even a broken
    one whose target does not exist — while leaving a not-yet-created trailing
    component appended to the resolved existing prefix. That catches both a
    not-yet-created ``.attestarc/findings.json`` under a symlinked parent (write
    side) and a symlinked ``.github/workflows/evil.yml`` pointing off-root (read
    side), whether or not the escape target exists.
    """
    root_real = os.path.normpath(os.path.realpath(root))
    resolved = os.path.normpath(os.path.realpath(os.path.abspath(path)))
    within = resolved == root_real or resolved.startswith(root_real + os.sep)
    return resolved, root_real, within


def is_within_root(path: str, root: str) -> bool:
    """True if ``path`` resolves to inside ``root`` (see :func:`resolve_within_root`)."""
    return resolve_within_root(path, root)[2]


class PathEscapeError(Exception):
    """Raised when a caller-supplied path resolves outside the assessed root.

    Carries the resolved path and root so callers can build a precise message.
    """

    def __init__(self, path: str, resolved: str, root_real: str):
        self.path = path
        self.resolved = resolved
        self.root_real = root_real
        super().__init__(
            f"{path} resolves to {resolved}, which is not under {root_real}"
        )


def safe_read_text(path: str, root: str, encoding: str = "utf-8") -> str:
    """Read ``path`` as text only if it resolves to inside ``root``.

    The repository under assessment is untrusted input: a symlinked, absolute, or
    ``..``-traversing path in the subject must never let a helper read outside the
    assessed root. Containment is computed by :func:`resolve_within_root` (the
    same rule the write side uses), so a symlinked ``findings.json`` or upsert
    ``source`` pointing at ``~/.ssh`` is refused *before* it is opened.

    Raises :class:`PathEscapeError` on a containment violation; otherwise returns
    the file contents.
    """
    resolved, root_real, within = resolve_within_root(path, root)
    if not within:
        raise PathEscapeError(path, resolved, root_real)
    with open(path, "r", encoding=encoding) as fh:
        return fh.read()
