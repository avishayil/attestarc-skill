"""Unit tests for scripts/_pathsafe.py — filesystem containment + safe tar extract.

A downloaded knowledge bundle is untrusted supply-chain input. ``safe_extract_tar``
must refuse every member that could escape the staging directory (absolute path,
``..`` traversal) or plant a link a later member follows out of it (symlink,
hardlink, device, fifo) — and it must refuse *before* writing anything.
"""

import os
import tarfile

import pytest

from _pathsafe import (
    PathEscapeError,
    is_within_root,
    safe_extract_tar,
)


def _add_bytes(tf, name, data=b"x"):
    import io
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def _add_symlink(tf, name, target):
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    tf.addfile(info)


def test_containment_basic(tmp_path):
    root = str(tmp_path / "root")
    os.makedirs(root)
    assert is_within_root(os.path.join(root, "a", "b"), root) is True
    assert is_within_root(os.path.join(root, "..", "escape"), root) is False


def test_extract_regular_files(tmp_path):
    archive = str(tmp_path / "ok.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "bundle/manifest.json", b"{}")
        _add_bytes(tf, "bundle/bootstrap/a.jsonl", b'{"id":"KE-a"}\n')
    dest = str(tmp_path / "out")
    written = safe_extract_tar(archive, dest)
    assert set(written) == {"bundle/manifest.json", "bundle/bootstrap/a.jsonl"}
    assert os.path.isfile(os.path.join(dest, "bundle", "manifest.json"))


def test_extract_rejects_absolute_member(tmp_path):
    archive = str(tmp_path / "abs.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "/etc/evil", b"x")
    dest = str(tmp_path / "out")
    with pytest.raises(ValueError, match="absolute"):
        safe_extract_tar(archive, dest)
    assert not os.path.exists(dest) or not os.listdir(dest)


def test_extract_rejects_parent_traversal(tmp_path):
    archive = str(tmp_path / "dotdot.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "../escape.txt", b"x")
    dest = str(tmp_path / "out")
    with pytest.raises(PathEscapeError):
        safe_extract_tar(archive, dest)
    assert not os.path.exists(os.path.join(tmp_path, "escape.txt"))


def test_extract_rejects_symlink_member(tmp_path):
    archive = str(tmp_path / "link.tar")
    with tarfile.open(archive, "w") as tf:
        _add_symlink(tf, "bundle/link", "/etc/passwd")
    dest = str(tmp_path / "out")
    with pytest.raises(ValueError, match="unsafe tar member"):
        safe_extract_tar(archive, dest)


def test_extract_writes_nothing_when_any_member_unsafe(tmp_path):
    """First member is fine; a later ``..`` member must abort the whole extract."""
    archive = str(tmp_path / "mixed.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "bundle/good.txt", b"x")
        _add_bytes(tf, "../evil.txt", b"x")
    dest = str(tmp_path / "out")
    with pytest.raises(PathEscapeError):
        safe_extract_tar(archive, dest)
    # two-pass: nothing from the good member is left behind
    assert not os.path.exists(os.path.join(dest, "bundle", "good.txt"))


# H6: resource limits (decompression-bomb defense-in-depth for the offline
# extract-before-attest path). A small archive can declare enormous or
# innumerable members; the caps bound the cost before the attestation gate runs.


def test_extract_rejects_too_many_members(tmp_path):
    archive = str(tmp_path / "many.tar")
    with tarfile.open(archive, "w") as tf:
        for i in range(6):
            _add_bytes(tf, f"bundle/f{i}.txt", b"x")
    dest = str(tmp_path / "out")
    with pytest.raises(ValueError, match="members, exceeding"):
        safe_extract_tar(archive, dest, max_members=5)
    assert not os.path.exists(dest) or not os.listdir(dest)


def test_extract_rejects_oversized_member_by_declared_size(tmp_path):
    """A member whose header declares more than the per-file cap is refused in the
    first (validate-only) pass, before any bytes are written."""
    archive = str(tmp_path / "big.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "bundle/big.txt", b"x" * 2048)
    dest = str(tmp_path / "out")
    with pytest.raises(ValueError, match="per-file cap"):
        safe_extract_tar(archive, dest, max_file_bytes=1024)
    assert not os.path.exists(os.path.join(dest, "bundle", "big.txt"))


def test_extract_rejects_oversized_total_by_declared_size(tmp_path):
    archive = str(tmp_path / "tot.tar")
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "bundle/a.txt", b"x" * 800)
        _add_bytes(tf, "bundle/b.txt", b"x" * 800)
    dest = str(tmp_path / "out")
    with pytest.raises(ValueError, match="total cap"):
        safe_extract_tar(archive, dest, max_total_bytes=1000)
    assert not os.path.exists(os.path.join(dest, "bundle", "a.txt"))
