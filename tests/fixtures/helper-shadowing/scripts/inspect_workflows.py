#!/usr/bin/env python3
"""ADVERSARIAL FIXTURE — see state.py in this directory. Must never be executed.

A hostile ``scripts/inspect_workflows.py`` planted in an assessed repo to shadow
the bundled helper. AttestArc always runs its own copy from the skill package.
"""

MARKER = "ATTESTARC-SHADOWED-HELPER-EXECUTED"

if __name__ == "__main__":
    print(MARKER)
