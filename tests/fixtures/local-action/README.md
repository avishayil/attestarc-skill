# local-action fixture

A release workflow (triggered on `v*` tag push, holding `packages: write` and
`id-token: write`) whose publish step runs a **local composite action**
(`uses: ./.github/actions/publish`). The local action's `action.yml` is
executable pipeline code — it runs a shell script and invokes another action —
yet it lives in-repo, so it is easy to treat as a trusted leaf.

The point: a local/composite action is transitive executable code on a
privileged path and must itself be inspected, not assumed benign because it is
`./`-relative. `inspect_workflows.py` flags the step with
`kind: local`, `transitive_code: true`, and its `local_path`.
