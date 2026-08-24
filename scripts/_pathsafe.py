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
import shutil
import tarfile


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


# Resource limits for untrusted-archive extraction (defense-in-depth against a
# decompression bomb: a small .tar.gz can declare enormous or innumerable members).
# These bound what an OFFLINE extract-before-attest can cost before the attestation
# gate would reject the bytes anyway. Generous relative to a real knowledge bundle
# (a handful of small JSONL packs + a manifest), tight relative to an abuse case.
_MAX_TAR_MEMBERS = 10_000
_MAX_TAR_FILE_BYTES = 50 * 1024 * 1024        # 50 MiB per member
_MAX_TAR_TOTAL_BYTES = 200 * 1024 * 1024      # 200 MiB uncompressed total


def safe_extract_tar(tar_path: str, dest_dir: str,
                     max_members: int = _MAX_TAR_MEMBERS,
                     max_file_bytes: int = _MAX_TAR_FILE_BYTES,
                     max_total_bytes: int = _MAX_TAR_TOTAL_BYTES) -> list[str]:
    """Extract a tar archive into ``dest_dir``, refusing every unsafe member.

    A downloaded knowledge bundle is untrusted supply-chain input. Each member
    MUST be a regular file or directory whose resolved path stays strictly within
    ``dest_dir``. Absolute paths, ``..`` traversal, and every non-regular member
    (symlink, hardlink, device, fifo) are refused *before anything is written* —
    so a malicious archive can neither escape the staging dir nor plant a link a
    later member follows out of it. Extraction is done member-by-member with our
    own IO (never :meth:`tarfile.extractall`), so tarfile's own path handling is
    not on the trust path.

    Resource limits bound a decompression bomb: the member count, each member's
    declared uncompressed size, and the total uncompressed size are all checked in
    the first (validate-only) pass, so an oversized or over-populated archive is
    refused *before anything is written*. The declared sizes are the tar headers;
    the second pass copies with our own IO and never trusts a header past this gate.

    Raises :class:`PathEscapeError` (containment) or :class:`ValueError` (unsafe
    member kind / unreadable / exceeds a resource limit) on any violation;
    otherwise returns the list of extracted file paths relative to ``dest_dir``.
    """
    dest_real = os.path.normpath(os.path.realpath(dest_dir))
    os.makedirs(dest_real, exist_ok=True)
    written: list[str] = []
    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > max_members:
            raise ValueError(
                f"tar has {len(members)} members, exceeding the {max_members} cap")
        # First pass: validate every member. Nothing is written until all pass.
        total_bytes = 0
        for m in members:
            name = m.name
            if os.path.isabs(name) or name.startswith(("/", "\\")):
                raise ValueError(f"absolute path in tar member: {name!r}")
            if not (m.isfile() or m.isdir()):
                raise ValueError(
                    f"unsafe tar member (not a regular file or directory): {name!r}")
            if m.isfile():
                if m.size > max_file_bytes:
                    raise ValueError(
                        f"tar member {name!r} is {m.size} bytes, exceeding the "
                        f"{max_file_bytes}-byte per-file cap")
                total_bytes += m.size
                if total_bytes > max_total_bytes:
                    raise ValueError(
                        f"tar uncompressed size exceeds the {max_total_bytes}-byte "
                        "total cap")
            resolved, root_real, within = resolve_within_root(
                os.path.join(dest_real, name), dest_real)
            if not within:
                raise PathEscapeError(name, resolved, root_real)
        # Second pass: extract with our own IO now that all members are safe. We
        # still enforce the total cap against the ACTUAL bytes read, not the tar
        # header, so a member whose header under-declares its size (streaming more
        # than advertised) cannot slip past the first-pass gate.
        extracted_total = 0
        for m in members:
            resolved, _, _ = resolve_within_root(
                os.path.join(dest_real, m.name), dest_real)
            if m.isdir():
                os.makedirs(resolved, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                raise ValueError(f"unreadable tar member: {m.name!r}")
            written_bytes = 0
            with src, open(resolved, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written_bytes += len(chunk)
                    extracted_total += len(chunk)
                    if written_bytes > max_file_bytes or extracted_total > max_total_bytes:
                        out.close()
                        os.remove(resolved)
                        raise ValueError(
                            f"tar member {m.name!r} streamed more than its declared "
                            "size, exceeding a resource cap")
                    out.write(chunk)
            written.append(os.path.relpath(resolved, dest_real))
    return written
