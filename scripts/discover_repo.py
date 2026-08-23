#!/usr/bin/env python3
"""Repository discovery: emit structured *facts* about the repository.

No findings. No security verdicts. The host agent decides what these facts
mean. Output is a single JSON object on stdout, e.g.::

    {
      "git": {"repository": true, "remote": "https://github.com/acme/svc.git"},
      "detected": {
        "scm": "github",
        "ci": ["github-actions"],
        "languages": ["python"],
        "package_managers": ["pip"],
        "containers": true,
        "terraform": false,
        ...
      }
    }

The scan is read-only and never executes repository code.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# Directories that never contain security-relevant configuration and would only
# slow the walk down (and could be enormous).
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", "dist", "build", ".next", ".idea", ".gradle",
    "target", "vendor", ".terraform",
}

# Marker file/dir -> (fact category, value). Presence-based; content untouched.
_CI_MARKERS = {
    ".github/workflows": "github-actions",
    ".gitlab-ci.yml": "gitlab-ci",
    ".circleci": "circleci",
    "Jenkinsfile": "jenkins",
    ".travis.yml": "travis",
    "azure-pipelines.yml": "azure-pipelines",
    ".azure-pipelines.yml": "azure-pipelines",
    "bitbucket-pipelines.yml": "bitbucket-pipelines",
}

# manifest filename -> (language, package_manager)
_MANIFESTS = {
    "requirements.txt": ("python", "pip"),
    "pyproject.toml": ("python", "pip"),
    "setup.py": ("python", "pip"),
    "setup.cfg": ("python", "pip"),
    "Pipfile": ("python", "pipenv"),
    "poetry.lock": ("python", "poetry"),
    "package.json": ("javascript", "npm"),
    "yarn.lock": ("javascript", "yarn"),
    "pnpm-lock.yaml": ("javascript", "pnpm"),
    "go.mod": ("go", "go-modules"),
    "Cargo.toml": ("rust", "cargo"),
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "build.gradle.kts": ("kotlin", "gradle"),
    "Gemfile": ("ruby", "bundler"),
    "composer.json": ("php", "composer"),
    "*.csproj": ("csharp", "nuget"),
    "mix.exs": ("elixir", "hex"),
}

_SECURITY_FILES = {
    "CODEOWNERS": "codeowners",
    "SECURITY.md": "security-policy",
    ".github/dependabot.yml": "dependabot",
    ".github/dependabot.yaml": "dependabot",
    "renovate.json": "renovate",
    ".renovaterc": "renovate",
    ".renovaterc.json": "renovate",
}


def _run_git(args, cwd):
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def _scm_from_remote(remote: str | None) -> str | None:
    if not remote:
        return None
    r = remote.lower()
    if "github.com" in r:
        return "github"
    if "gitlab" in r:
        return "gitlab"
    if "bitbucket" in r:
        return "bitbucket"
    if "dev.azure.com" in r or "visualstudio.com" in r:
        return "azure-devops"
    return None


def _normalize_remote(remote: str | None) -> str | None:
    """Return owner/repo when derivable from a GitHub-style remote, else raw."""
    if not remote:
        return None
    m = re.search(r"github\.com[:/]+([^/]+/[^/]+?)(?:\.git)?/?$", remote)
    if m:
        return m.group(1)
    return remote


def _exists(root: str, rel: str) -> bool:
    return os.path.exists(os.path.join(root, rel))


def discover(root: str) -> dict:
    root = os.path.abspath(root)

    is_git = os.path.isdir(os.path.join(root, ".git")) or (
        _run_git(["rev-parse", "--is-inside-work-tree"], root) == "true"
    )
    remote_raw = _run_git(["remote", "get-url", "origin"], root) if is_git else None
    default_branch = None
    if is_git:
        head = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], root)
        default_branch = head or None

    ci: set[str] = set()
    for marker, value in _CI_MARKERS.items():
        if _exists(root, marker):
            ci.add(value)

    languages: set[str] = set()
    package_managers: set[str] = set()
    security_files: set[str] = set()
    containers = False
    terraform = False
    kubernetes = False
    helm = False

    # Top-level manifests / security files (most live at the root).
    for name, (lang, pm) in _MANIFESTS.items():
        if name.startswith("*."):
            ext = name[1:]
            if any(fn.endswith(ext) for fn in os.listdir(root)
                   if os.path.isfile(os.path.join(root, fn))):
                languages.add(lang)
                package_managers.add(pm)
        elif _exists(root, name):
            languages.add(lang)
            package_managers.add(pm)

    for rel, value in _SECURITY_FILES.items():
        if _exists(root, rel):
            security_files.add(value)
    # CODEOWNERS can live at repo root, .github/, or docs/
    for loc in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        if _exists(root, loc):
            security_files.add("codeowners")

    # Shallow-ish walk for container / IaC signals.
    workflow_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        depth = os.path.relpath(dirpath, root).count(os.sep)
        for fn in filenames:
            low = fn.lower()
            if low == "dockerfile" or low.startswith("dockerfile."):
                containers = True
            if low in ("docker-compose.yml", "docker-compose.yaml",
                       "compose.yml", "compose.yaml"):
                containers = True
            if fn.endswith(".tf") or fn.endswith(".tf.json"):
                terraform = True
            if fn == "Chart.yaml" or fn == "Chart.yml":
                helm = True
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if rel_dir.endswith(".github/workflows"):
            for fn in filenames:
                if fn.endswith((".yml", ".yaml")):
                    workflow_files.append(f"{rel_dir}/{fn}")
        # Heuristic: kubernetes manifests dir
        if os.path.basename(dirpath) in ("k8s", "kubernetes", "manifests"):
            kubernetes = True
        # Keep the walk bounded in pathological trees.
        if depth > 6:
            dirnames[:] = []

    scm = _scm_from_remote(remote_raw)
    if scm is None and "github-actions" in ci:
        scm = "github"  # strong local signal, but note: not remote-verified

    iac = []
    if terraform:
        iac.append("terraform")
    if kubernetes:
        iac.append("kubernetes")
    if helm:
        iac.append("helm")

    result = {
        "git": {
            "repository": bool(is_git),
            "remote": remote_raw,
            "default_branch": default_branch,
        },
        "detected": {
            "scm": scm,
            "scm_verified_remotely": False,
            "remote_slug": _normalize_remote(remote_raw),
            "ci": sorted(ci),
            "languages": sorted(languages),
            "package_managers": sorted(package_managers),
            "containers": containers,
            "terraform": terraform,
            "iac": sorted(iac),
            "security_files": sorted(security_files),
            "workflow_files": sorted(workflow_files),
        },
        "notes": [],
    }

    # Honest notes about the limits of local-only discovery.
    unsupported = [c for c in result["detected"]["ci"]
                   if c not in ("github-actions",)]
    if unsupported:
        result["notes"].append(
            "Detected CI systems not deeply supported in V1 "
            f"({', '.join(unsupported)}); generic methodology applies."
        )
    if scm == "github":
        result["notes"].append(
            "SCM inferred locally. Remote settings (branch protection, rulesets, "
            "environments) are not verified here."
        )
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AttestArc repository discovery")
    p.add_argument("--root", default=".", help="repository root (default: .)")
    args = p.parse_args(argv)
    if not os.path.isdir(args.root):
        sys.stderr.write(f"error: {args.root} is not a directory\n")
        return 2
    print(json.dumps(discover(args.root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
