"""Shared test configuration.

Puts the skill's ``scripts/`` directory on sys.path so the deterministic helper
modules can be imported directly, and exposes fixture paths.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
_SCRIPTS = os.path.join(_REPO_ROOT, "scripts")
_ASSETS = os.path.join(_REPO_ROOT, "assets")
_FIXTURES = os.path.join(_HERE, "fixtures")

if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)  # so install.py / uninstall.py import

import pytest  # noqa: E402


@pytest.fixture
def repo_root():
    return _REPO_ROOT


@pytest.fixture
def assets_dir():
    return _ASSETS


@pytest.fixture
def fixtures_dir():
    return _FIXTURES
