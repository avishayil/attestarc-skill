# dependency-review fixture

A `pull_request` workflow that runs `actions/dependency-review-action` with **no
`fail-on-severity` set** and no `continue-on-error`. The action defaults to
`fail-on-severity: low` and `warn-only: false`, so an unset `fail-on-severity`
**blocks the PR by default** — the step is enforcing, not advisory.

The point: do not down-rate this to "advisory because fail-on-severity is unset".
It is only advisory when explicitly softened (`warn-only: true`,
`continue-on-error: true`) or when the check is not required server-side (which
cannot be verified from the workflow alone → `needs_review`).
