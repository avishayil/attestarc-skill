# Threat model: CI/CD pipelines

The portable attack classes for build/test/release pipelines, framed as
capability chains. Pair this with `references/github-actions.md` for GitHub
observation, the parser facts, and remediation. The recurring shape is the
grammar from `core/methodology.md`:

```
ACTOR → ENTRY POINT → CONTROLLED INPUT → TRUST TRANSITION
      → CAPABILITY → TARGET ASSET → IMPACT
```

A pipeline is dangerous when a low-trust actor reaches a step that holds a
high-trust capability (secrets, a writable token, a workload identity, a publish
right). Walk the reachability ladder — `present → reachable → exploitable →
impactful` — before you rate anything.

## Poisoned Pipeline Execution (PPE)

An untrusted actor gets their code or input to run inside a privileged pipeline.

- **Direct PPE.** The controlled input *is* code the pipeline runs. Classic:
  external contributor → `pull_request_target` (or `workflow_run`) → checkout of
  the PR head → a build/test/`run:` step executes it → `EXECUTE_UNTRUSTED_CODE`
  with base-repo secrets and a writable token → whatever that token/identity
  reaches. Reachability is usually `direct` (any fork).
- **Indirect PPE.** The attacker cannot edit the workflow but controls a file the
  privileged pipeline *interprets*: a Makefile, `package.json` script, test
  config, or a `${{ }}` expression interpolated into a shell. Same capability,
  one hop removed. Reachability often `conditional` on the poisoned file being
  read.

Ask: which event carries secrets/a writable token? Does the controlled input
actually execute? A fork `pull_request` (read-only token, no secrets) running
untrusted code is normally expected and safe — that chain does not close.

## workflow_run privilege bridging

`workflow_run` runs trusted workflow code, but is *triggered by* another workflow
that a fork may have influenced — and it holds secrets and a writable token the
triggering run did not. The bridge is the data crossing between them:

```
untrusted/first workflow → {artifact, cache, metadata, outputs, PR number}
                         → privileged workflow_run consumes it
                         → EXECUTE_UNTRUSTED_CODE / WRITE_REPOSITORY / PUBLISH_ARTIFACT
```

Investigate: identify the triggering workflow and whether untrusted contributors
can influence it; enumerate every artifact/output/cache/label the privileged
`workflow_run` consumes; treat those values as attacker-controlled unless the
privileged workflow independently validates them; then determine the capability
available after consumption. The modern "unprivileged build produces a poisoned
artifact → privileged release trusts it" chain lives here. A `workflow_run` that
consumes only its own trusted outputs, or validates inputs, does not close.

## Cache poisoning

Actions caches are **not signed or verified**. That makes them a trust boundary
of their own (`cache-trust-boundary`):

```
low-trust writer (a run an untrusted actor can influence)
        → cache key in a scope the privileged run reads
        → privileged job restores it
        → executable / tool / build-script / dependency runs
        → EXECUTE_UNTRUSTED_CODE in the privileged context
```

The load-bearing question is **scope**: caches are keyed *and scoped*, and a
privileged run only restores from scopes it is allowed to read. Ask: can low-trust
code **write** a cache **in a scope the privileged job restores from** (not merely
write *some* cache)? Can that privileged workflow later restore it? Does the
restored content include executables, compiled tools, build scripts, or dependency
directories that then run? A cache written only by trusted refs, or in a scope the
privileged run never reads, does not close the chain — an isolated fork-PR scope
is the common example. **Which actors/triggers can actually write a given scope is
platform-specific** — on GitHub the write-capable set is narrow and several
low-trust triggers get read-only cache access, so verify the writer against
`references/github-actions.md` (cache write-scope decision tree) before assuming a
low-trust run can poison anything. `inspect_workflows.py` surfaces `uses_cache`
per job as a starting fact.

## Reusable-workflow transitive trust

Callers reach across a chain `A → B → C`. Permissions can only stay equal or
decrease down the chain, so the sharper risks are **secret propagation** and
**trusted-code identity**:

- `secrets: inherit` hands the callee *every* caller secret — a broad
  `READ_SECRET` capability transfer. Treat it as a wide blast radius and ask what
  the callee does with those secrets and whether its code is trusted.
- An **external or mutable reusable-workflow ref** (`owner/repo/.github/
  workflows/x.yml@main`) means the trusted-looking call can change underneath
  you — same class as an unpinned Action.
- A called workflow that runs on **self-hosted** runners, or is itself reachable
  by untrusted triggers, extends the boundary transitively.

The parser reports per-job `secrets` (`"inherit"` or a name map) and `uses_pinned`
for job-level reusable-workflow calls.

## Self-hosted runner abuse

`self_hosted: true` is the *observation that prompts questions*, not a verdict —
it does not by itself mean "persistent" or "privileged network". Blast radius is
set by separable properties the label alone rarely answers: **lifecycle**
(ephemeral, fresh per job, vs a long-lived host that reuses filesystem and
credentials), **tenancy/scope** (a runner group scoped to one trusted repo vs an
org-wide group a fork PR can land on), and **network segmentation** (what the
runner can reach — production, cloud metadata, internal services). The serious
pattern is running **untrusted contributions** on a **persistent,
broadly-scoped, poorly-segmented** runner, or sharing one between PR and
release/deploy workloads: an attacker who achieves `EXECUTE_UNTRUSTED_CODE` there
gains persistence, lateral movement, and secret theft against everything the
runner reaches. Correlate `self_hosted: true` with the trigger's reachability and
any deployment/identity capability on the same runner, and record the unknown
properties as `evidence_gaps`. See `references/github-actions.md` (Runners) for
the observation model on GitHub.

## Download-and-execute

A workflow that fetches code from the network and runs it is a supply-chain
dependency even with no `uses:` — `curl … | sh`, `wget … && chmod +x`,
`iwr … | iex`, `npm i -g`, `pip install git+…`, `go install …@latest`,
`cargo install`. The parser flags these per run step as `fetch_execute` with a
`fetch_execute_excerpt`. Do not treat the pattern as an automatic finding; ask:

- Is the fetched content **immutable** (a content digest or full commit SHA — a
  tag is *movable*, not immutable) or a moving `latest`/branch?
- Is its **integrity verified** (checksum, signature) before use?
- Is it actually **executed**?
- What **privilege** does the job hold? A release/publish job doing this
  (`PUBLISH_ARTIFACT`, `ASSUME_EXTERNAL_IDENTITY`) is far more interesting than a
  developer-only lint job.

Immutable, verified, and low-privilege → the chain does not close.
