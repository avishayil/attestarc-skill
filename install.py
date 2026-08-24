#!/usr/bin/env python3
"""Install the AttestArc skill into Claude Code and/or Cursor.

The repository root *is* the skill package. Installation copies the skill
payload (SKILL.md, core/, references/, knowledge/, scripts/, schemas/, and
LICENSE/README) into the host's skills location; development-only files (tests/,
evals/, evolution/, the installer, pyproject) are not shipped. It never modifies
unrelated host config.

The default destination, ``.claude/skills/attestarc/``, is where Claude Code
natively discovers Agent Skills. Cursor also natively supports Agent Skills: it
auto-discovers ``.cursor/skills/`` (and ``.agents/skills/``) and, for
compatibility, also loads ``.claude/skills/`` and ``.codex/skills/``. Use
``--platform cursor`` to place the skill under ``.cursor/skills/attestarc/``;
Cursor then exposes it via ``/attestarc`` in Agent chat with no extra
configuration. See the README's Cursor section.

Examples::

    python install.py                                  # claude + project
    python install.py --platform claude --scope user
    python install.py --platform cursor --scope project
    python install.py --platform both   --scope user
    python install.py --scope project --target /path/to/repo
    python install.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SKILL_NAME = "attestarc"

# External root of trust for the DISTRIBUTED PACKAGE. It lives next to this
# installer (repo root), OUTSIDE the tarball it verifies, and is NOT part of
# SKILL_PAYLOAD — a bundle can never declare its own trust. `--from-tarball`
# verifies a release tarball's Sigstore build provenance against this anchor
# before extracting anything. See bootstrap-anchor.json and THREAT_MODEL.md §6.
BOOTSTRAP_ANCHOR = "bootstrap-anchor.json"

# Only these top-level entries are shipped into an installed skill. Everything
# else in the repo (tests/, evals/, evolution/, installer, pyproject, CLAUDE.md,
# THREAT_MODEL.md, SPECIFICATION.md, ...) is development scaffolding and stays out
# of the host's skills directory.
SKILL_PAYLOAD = ("SKILL.md", "core", "references", "knowledge", "scripts",
                 "schemas", "LICENSE", "README.md")

_PLATFORM_DIR = {
    "claude": ".claude",
    "cursor": ".cursor",
}


def source_skill_dir() -> str:
    """The repo root, which is the skill package (SKILL.md lives here)."""
    return os.path.dirname(os.path.abspath(__file__))


class InstallError(Exception):
    pass


def _frontmatter_block(skill_md: str) -> str | None:
    """Return the raw YAML frontmatter block of SKILL.md, or None."""
    if not os.path.exists(skill_md):
        return None
    with open(skill_md, "r", encoding="utf-8") as fh:
        text = fh.read()
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    return text[3:end] if end != -1 else text


def _frontmatter_scalar(block: str, key: str) -> str | None:
    """Find the first ``key:`` line in the block and return its scalar value.

    Works for top-level keys and for nested keys (e.g. ``version:`` under
    ``metadata:``) since it matches the key regardless of indentation. Quotes
    around the value are stripped.
    """
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}:"):
            value = stripped.split(":", 1)[1].strip()
            return value.strip('"').strip("'") or None
    return None


def read_version(skill_dir: str) -> str | None:
    """Read the skill version from SKILL.md frontmatter ``metadata.version``."""
    block = _frontmatter_block(os.path.join(skill_dir, "SKILL.md"))
    if block is None:
        return None
    return _frontmatter_scalar(block, "version")


def _frontmatter_name(skill_md: str) -> str | None:
    """Extract the 'name:' value from SKILL.md YAML frontmatter."""
    block = _frontmatter_block(skill_md)
    if block is None:
        return None
    return _frontmatter_scalar(block, "name")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_bundled_knowledge(source: str) -> None:
    """Verify the bundled knowledge snapshot's integrity before shipping it.

    The in-package snapshot is bootstrap-trusted because it rides in on the
    SSH-signed skill release; there is no attestation to check at install time
    (that is the Updater's job for downloaded bundles). But we DO confirm the
    bundled manifest.json pins each pack by a matching sha256+size and that the
    external trust-anchor.json is present — so a locally-corrupted or tampered
    snapshot fails the install rather than being copied out as "trusted".
    """
    kroot = os.path.join(source, "knowledge")
    if not os.path.isdir(kroot):
        return  # a source without a knowledge plane is a no-op here
    anchor = os.path.join(kroot, "trust-anchor.json")
    if not os.path.exists(anchor):
        raise InstallError("knowledge/trust-anchor.json is missing; refusing to "
                           "install a knowledge plane with no root of trust")
    mpath = os.path.join(kroot, "manifest.json")
    if not os.path.exists(mpath):
        raise InstallError("knowledge/manifest.json is missing; cannot verify "
                           "the bundled snapshot's integrity")
    try:
        with open(mpath, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallError(f"knowledge/manifest.json is unparseable: {exc}")
    for pack in manifest.get("packs", []):
        name = pack.get("name", "")
        ppath = os.path.join(kroot, name)
        if not os.path.exists(ppath):
            raise InstallError(f"bundled pack missing: {name}")
        if os.path.getsize(ppath) != pack.get("size") \
                or _sha256_file(ppath) != pack.get("sha256"):
            raise InstallError(
                f"bundled pack {name} does not match manifest sha256/size; "
                f"refusing to install a tampered knowledge snapshot")

    # Beyond byte integrity, confirm the snapshot obeys its own trust contract:
    # every entry schema-valid, each source's provenance matching the registry's
    # reclassification of its URL, no secret-looking values, and the set coherent.
    # A pack can hash-match the manifest yet still violate policy (an entry
    # claiming a higher authority tier than the registry assigns its URL); we
    # refuse to ship such a snapshot rather than copy it out as "trusted".
    _validate_bundled_snapshot(source, kroot)


def _validate_bundled_snapshot(source: str, kroot: str) -> None:
    """Run the deterministic snapshot-validation gate (scripts/knowledge.py) over
    the source's own packs, using the source's own registry as the classification
    root of trust. Import the helpers from the source being installed."""
    scripts_dir = os.path.join(source, "scripts")
    inserted = scripts_dir not in sys.path
    if inserted:
        sys.path.insert(0, scripts_dir)
    try:
        import knowledge
        import knowledge_compile
        entries, _ = knowledge.load_packs(kroot)
        registry = knowledge_compile.load_registry(kroot)
        result = knowledge.validate_snapshot(entries, registry)
        consistency = knowledge.check_consistency(entries)
    except InstallError:
        raise
    except Exception as exc:  # noqa: BLE001 — an unvalidatable snapshot is not trusted
        raise InstallError(
            f"cannot validate the bundled knowledge snapshot: {exc}")
    finally:
        if inserted and scripts_dir in sys.path:
            sys.path.remove(scripts_dir)
    if not result.get("valid"):
        raise InstallError(
            "bundled knowledge snapshot violates its own trust contract "
            f"(schema/provenance/secret): {result['violations']}")
    if not consistency.get("consistent"):
        raise InstallError(
            "bundled knowledge snapshot is internally inconsistent: "
            f"{consistency['conflicts']}")


def validate_source(source: str) -> str:
    """Ensure the source skill is well-formed; return its version string."""
    if not os.path.isdir(source):
        raise InstallError(f"source skill directory not found: {source}")
    skill_md = os.path.join(source, "SKILL.md")
    name = _frontmatter_name(skill_md)
    if name != SKILL_NAME:
        raise InstallError(
            f"{skill_md} is missing or its frontmatter name is not "
            f"'{SKILL_NAME}' (got {name!r})"
        )
    verify_bundled_knowledge(source)
    return read_version(source) or "unknown"


def dest_dir(platform: str, scope: str, target: str | None) -> str:
    if platform not in _PLATFORM_DIR:
        raise InstallError(f"unknown platform: {platform}")
    if scope == "user":
        base = os.path.expanduser("~")
    elif scope == "project":
        base = os.path.abspath(target) if target else os.getcwd()
    else:
        raise InstallError(f"unknown scope: {scope}")
    return os.path.join(base, _PLATFORM_DIR[platform], "skills", SKILL_NAME)


def _is_our_skill(path: str) -> bool:
    return _frontmatter_name(os.path.join(path, "SKILL.md")) == SKILL_NAME


def _atomic_copy_tree(source: str, dest: str) -> None:
    """Copy source -> dest, replacing an existing dest as atomically as we can."""
    parent = os.path.dirname(os.path.abspath(dest))
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".attestarc-staging-", dir=parent)
    staged_skill = os.path.join(staging, SKILL_NAME)
    try:
        os.makedirs(staged_skill)
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
        for entry in SKILL_PAYLOAD:
            src = os.path.join(source, entry)
            if not os.path.exists(src):
                continue  # optional payload entry (e.g. LICENSE/README)
            dst = os.path.join(staged_skill, entry)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=ignore)
            else:
                shutil.copy2(src, dst)
        if os.path.exists(dest):
            if not _is_our_skill(dest):
                raise InstallError(
                    f"refusing to overwrite {dest}: it does not look like an "
                    f"AttestArc skill (no matching SKILL.md)."
                )
            backup = dest + ".old"
            if os.path.exists(backup):
                shutil.rmtree(backup)
            os.replace(dest, backup)
            try:
                os.replace(staged_skill, dest)
            except OSError:
                os.replace(backup, dest)  # roll back
                raise
            shutil.rmtree(backup, ignore_errors=True)
        else:
            os.replace(staged_skill, dest)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def load_bootstrap_anchor(anchor_dir: str | None = None) -> dict:
    """Load and sanity-check bootstrap-anchor.json (the package root of trust).

    Looked up next to this installer by default. It pins the Sigstore
    build-provenance identity an official skill-release tarball must carry:
    ``repo``, ``issuer``, and ``cert_identity_regexp``. A missing anchor is a
    hard error — we never fall back to installing an unverified tarball.
    """
    base = anchor_dir or source_skill_dir()
    path = os.path.join(base, BOOTSTRAP_ANCHOR)
    if not os.path.exists(path):
        raise InstallError(
            f"{BOOTSTRAP_ANCHOR} not found next to the installer; cannot verify a "
            f"release tarball without the package root of trust")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            anchor = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallError(f"{BOOTSTRAP_ANCHOR} is unparseable: {exc}")
    for key in ("repo", "issuer", "cert_identity_regexp"):
        if not anchor.get(key):
            raise InstallError(
                f"{BOOTSTRAP_ANCHOR} is missing required field {key!r}")
    try:
        re.compile(anchor["cert_identity_regexp"])
    except re.error as exc:
        raise InstallError(
            f"{BOOTSTRAP_ANCHOR} cert_identity_regexp is not a valid regexp: {exc}")
    return anchor


def verify_release_tarball(tarball_path: str, anchor: dict) -> None:
    """Cryptographically verify a release tarball before it is extracted.

    Shells out to the system ``gh attestation verify`` (no Python crypto
    dependency — the same tool the Updater and the release workflows use) to
    confirm the tarball carries a Sigstore build-provenance attestation whose
    certificate identity matches the bootstrap anchor's repo, OIDC issuer, and
    ``cert_identity_regexp`` (which pins ``release-skill.yml@refs/tags/v<semver>``).

    Fail-secure: a missing ``gh``, a non-zero exit, or any error means the
    tarball is NOT trusted and MUST NOT be extracted. A plain ``git clone`` of a
    signed tag does not verify the tag signature; THIS is the install-time crypto
    check. Raises :class:`InstallError` on any failure.
    """
    if not os.path.exists(tarball_path):
        raise InstallError(f"release tarball not found: {tarball_path}")
    if shutil.which("gh") is None:
        raise InstallError(
            "gh CLI not found; cannot verify the release tarball's attestation. "
            "Install GitHub CLI (with the attestation extension) or install from a "
            "source checkout you trust.")
    cmd = [
        "gh", "attestation", "verify", tarball_path,
        "--repo", anchor["repo"],
        "--cert-identity-regexp", anchor["cert_identity_regexp"],
        "--cert-oidc-issuer", anchor["issuer"],
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise InstallError(f"failed to run gh attestation verify: {exc}")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise InstallError(
            "release tarball failed attestation verification against "
            f"{BOOTSTRAP_ANCHOR} (repo={anchor['repo']}); refusing to install an "
            f"unverified package.\n{detail}")


def install_from_tarball(tarball_path: str, platforms, scope: str,
                         target: str | None, force: bool, dry_run: bool,
                         anchor_dir: str | None = None) -> list[dict]:
    """Verify an attested release tarball, then install from its contents.

    Order matters: the tarball is attestation-verified against the bootstrap
    anchor FIRST, then safe-extracted (member-by-member, refusing traversal /
    non-regular members via :func:`scripts._pathsafe.safe_extract_tar`) into a
    temp dir, and only that extracted, verified tree is used as the install
    source. Never fetch-then-trust: nothing is extracted before verification.
    """
    anchor = load_bootstrap_anchor(anchor_dir)
    verify_release_tarball(tarball_path, anchor)

    # safe_extract_tar ships with the installer, in scripts/. Import it the same
    # way _validate_bundled_snapshot imports the knowledge helpers.
    scripts_dir = os.path.join(source_skill_dir(), "scripts")
    inserted = scripts_dir not in sys.path
    if inserted:
        sys.path.insert(0, scripts_dir)
    try:
        import _pathsafe
        safe_extract_tar = _pathsafe.safe_extract_tar
    finally:
        if inserted and scripts_dir in sys.path:
            sys.path.remove(scripts_dir)

    workdir = tempfile.mkdtemp(prefix=".attestarc-tarball-")
    try:
        extract_root = os.path.join(workdir, "extracted")
        safe_extract_tar(tarball_path, extract_root)
        # The workflow tars the payload entries at the archive root, so the
        # extracted tree is itself the skill source.
        results = []
        for platform in platforms:
            results.append(install_one(platform, scope, target, force, dry_run,
                                       source=extract_root))
        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def install_one(platform: str, scope: str, target: str | None,
                force: bool, dry_run: bool, source: str | None = None) -> dict:
    if source is None:
        source = source_skill_dir()
    version = validate_source(source)
    dest = dest_dir(platform, scope, target)

    existing_version = None
    existing = os.path.isdir(dest)
    if existing:
        if not _is_our_skill(dest):
            raise InstallError(
                f"{dest} exists but is not an AttestArc skill; not touching it."
            )
        existing_version = read_version(dest)
        if existing_version == version and not force:
            return {"platform": platform, "scope": scope, "dest": dest,
                    "action": "up-to-date", "version": version,
                    "installed_version": existing_version}

    action = "would-install" if dry_run else (
        "upgraded" if existing else "installed")
    if not dry_run:
        _atomic_copy_tree(source, dest)

    return {"platform": platform, "scope": scope, "dest": dest,
            "action": action, "version": version,
            "installed_version": existing_version}


def _platforms(arg: str):
    return ["claude", "cursor"] if arg == "both" else [arg]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Install the AttestArc skill")
    p.add_argument("--platform", choices=["claude", "cursor", "both"],
                   default="claude",
                   help="default 'claude' (.claude/skills is natively "
                        "discovered by Claude Code; 'cursor' installs into "
                        ".cursor/skills, which Cursor discovers natively)")
    p.add_argument("--scope", choices=["project", "user"], default="project")
    p.add_argument("--target", default=None,
                   help="destination repository (project scope only)")
    p.add_argument("--force", action="store_true",
                   help="reinstall even if the same version is present")
    p.add_argument("--dry-run", action="store_true",
                   help="report what would happen without copying")
    p.add_argument("--from-tarball", default=None, metavar="PATH",
                   help="install from an attested release tarball: verify its "
                        "Sigstore provenance against bootstrap-anchor.json with "
                        "'gh attestation verify' BEFORE extracting, then install "
                        "from the verified contents (a git clone of a signed tag "
                        "does not verify the tag signature; this does)")
    args = p.parse_args(argv)

    if args.target and args.scope != "project":
        sys.stderr.write("warning: --target is ignored for --scope user\n")

    def _report(result):
        verb = result["action"].replace("-", " ")
        extra = ""
        if result["installed_version"]:
            extra = f" (was {result['installed_version']})"
        print(f"{result['platform']}: {verb} v{result['version']}{extra} -> "
              f"{result['dest']}")
        if result["platform"] == "cursor":
            print("       (Cursor natively discovers .cursor/skills/; "
                  "invoke it with /attestarc in Agent chat — see README)")

    try:
        if args.from_tarball:
            results = install_from_tarball(
                args.from_tarball, _platforms(args.platform), args.scope,
                args.target, args.force, args.dry_run)
            for result in results:
                _report(result)
        else:
            for platform in _platforms(args.platform):
                _report(install_one(platform, args.scope, args.target,
                                    args.force, args.dry_run))
    except InstallError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
