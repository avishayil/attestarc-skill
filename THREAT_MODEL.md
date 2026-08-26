# AttestArc Threat Model

- **Status:** Draft — normative for the self-evolving architecture (0.5.x).
- **Scope:** The security of **AttestArc itself** as a software supply chain — its
  kernel, its knowledge plane, and its evolution pipeline. This is distinct from
  the security *of the assessed repository*, which is the product's subject and is
  covered by `SPECIFICATION.md`.
- **Audience:** Contributors. Keep in sync with `SPECIFICATION.md` and `CLAUDE.md`.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as in RFC 2119.

**How to read this, and where else the model is documented.** This document is the
**normative** source for AttestArc's own security. Two other surfaces summarize it
for different audiences and MUST stay consistent with it (see the doc-sync rule in
`CLAUDE.md`):

- [`SECURITY.md`](SECURITY.md) — the public summary and vulnerability-reporting
  policy; it feeds the GitHub Security tab.
- The [security page](https://avishay.co.il/attestarc-skill/security.html) on the
  project site — a visual overview with the same trust zones, principals, and
  verify-chain.

Where they overlap, this document is authoritative and the others mirror it; the
trust-zone description (§2) and the verify-chain diagram (§4) are the canonical text.
A glossary of the coined terms is in §9.

## 1. Why AttestArc needs its own threat model

Once AttestArc can dynamically learn facts that alter security verdicts,
**poisoning its knowledge becomes equivalent to compromising scanner logic.** An
attacker who can teach AttestArc that `pull_request_target` is safe can suppress a
Critical finding without ever touching the target repository. Therefore AttestArc's
knowledge plane is **security-critical code**, and the pipeline that produces it is
a software supply chain that MUST be defended as one.

The primary rule:

> **Nothing learned at runtime may directly modify the trusted security brain.**
> AI may discover knowledge, propose knowledge, and propose changes to itself, but
> a *deterministic* trust policy decides what becomes trusted, and the running
> assessor can never grant itself more trust.

## 2. Trust zones

AttestArc is partitioned into three zones. The kernel/knowledge boundary is
enforced in **code** (the assessor reads knowledge only through a verify-gate, its
helpers contain no network code, and the kernel is not writable at assessment time)
and in **process** (all changes land through reviewed pull requests gated by the
eval corpus, third-party Actions pinned to a full commit SHA, and — for root-of-trust
files — two-party review; see §6 for what two-party review means and how it is
enforced given the repository's reviewer staffing). The
separation of the *principals* (§3) is **structural and documented**, not an
in-session sandbox: a host that pre-approves a tool (Claude Code `allowed-tools`,
Cursor) does not remove it, so AttestArc cannot claim to strip the network from a
running session. Instead the assessor path simply contains no fetch step, and
ingestion lives upstream (§3, §4).

### 2.1 KERNEL — highly trusted

`SKILL.md`, `core/` (methodology, capabilities, severity, evidence, agent-safety,
remediation, promotion-policy), the verification helpers (`scripts/knowledge_verify.py`,
`scripts/state.py`, `scripts/_pathsafe.py`), the schemas, and the eval corpus.

- Changes rarely.
- Changes ONLY through reviewed pull requests, gated by the eval corpus and (for
  root-of-trust files, §6) two-party review.
- MUST NOT be writable by the running skill during an assessment.

### 2.2 VERIFIED KNOWLEDGE — trusted for reasoning

Attested, versioned, temporal, provenance-backed knowledge packs (`knowledge/`).

- MAY be refreshed by the Updater principal (§3), never by the Assessor.
- Trusted for reasoning ONLY after passing the verification chain (§4): the
  in-package snapshot is bootstrap-trusted (it rode in with the skill package,
  whose own authenticity is established at install time by §4a, not by this
  anchor); a refreshed snapshot is trusted only if persistent client state records
  that its exact version + manifest digest was attestation-verified.
- Every entry MUST carry provenance (a registry-derived source, bound to a fetched
  object), and the pack set is only trusted after `check_consistency` **and**
  `validate_snapshot` pass. A matching attested pack hash proves *these are the
  released bytes*; it does NOT prove the bytes obey the trust contract. Byte
  integrity is therefore necessary but not sufficient: `validate_snapshot`
  additionally requires every entry to be schema-valid, every source's declared
  `publisher`/`type`/`authority` to match the source registry's reclassification of
  its URL (never the value written in the pack), every source URL to be
  registry-allowed, and no entry to carry a secret-looking value. This gate runs at
  install time (`install.py`) and again on the Assessor read path (`open_verified`);
  a violation withholds trust (route to `needs_review`). A pack that only partially
  parses (`parse_partial`) is a partially-consumed verified set and likewise fails
  closed — the snapshot is untrusted rather than reasoned over line-by-line.

### 2.3 CANDIDATE KNOWLEDGE — untrusted

LLM extractions, web discoveries, changelog deltas, researcher claims, user
feedback, and conflicting evidence.

- MAY influence which *investigation questions* AttestArc asks.
- MUST NOT change a security conclusion.
- Becomes verified only by passing deterministic promotion policy (§6).

## 3. Principals

Three principals with disjoint capabilities. They are **skill modes plus a
development workflow**, not a hosted multi-agent runtime; the host coding agent
provides all orchestration.

| Principal | May | MUST NOT |
|-----------|-----|----------|
| **Assessor** (`/attestarc`) | Read repo; read *verified* knowledge; write `findings.json` | Reach the network; write kernel or knowledge; grant itself trust |
| **Updater** (`/attestarc knowledge refresh`) | Read allow-listed sources over the network; write *candidate* knowledge; promote per policy | Access the target repository; write the kernel; sign/publish releases |
| **Evolver** (dev-time) | Read candidates/evals; propose branch changes + evals | Write the production skill; release; modify or delete trusted evals in the same trust step |

The Assessor and the Updater are separated precisely so that a malicious repository
cannot turn the security-assessment path into a network egress or data-exfiltration
channel.

## 4. Update security (attestation-based)

The root of trust for *knowledge bundles* is an **external anchor** that ships
inside the skill package — `knowledge/trust-anchor.json` — and lives OUTSIDE any
downloaded bundle. (The *package itself* has a separate root of trust,
`bootstrap-anchor.json`; how the distributed package is authenticated at install
time is covered in §4a.)
It pins the Sigstore build-provenance identity (repo + signer workflow + the
reviewed git **ref** + OIDC issuer) that an official knowledge bundle must have been
produced under. The identity is enforced by an **artifact-specific** SAN regexp,
which binds the certificate SAN's trailing `@<ref>` — not merely the workflow path —
to a *single* reviewed ref per artifact kind: a knowledge **bundle** (manifest/archive)
must match `cert_identity_regexp_bundle` (`…release-knowledge.yml@refs/tags/knowledge-v<N>`
only), and a **revocation** must match `cert_identity_regexp_revocation`
(`…@refs/heads/main` only). Splitting these prevents a bundle from being signed off
`main` and prevents a revocation identity from standing in for a bundle; an attestation
minted from an unreviewed branch, or from the wrong ref for its kind, does not satisfy
the anchor even though the workflow file is identical. A bundle can therefore never
declare its own trust; the homemade root/timestamp/snapshot/targets role-file protocol
is gone. (A legacy combined `cert_identity_regexp` is honored only as a fallback when
the per-artifact keys are absent.)

Two verification entry points in `knowledge_verify.py`:

```
verify_download  (Updater; network/gh)          verify_installed (Assessor; no network/gh)
  gh attestation verify <archive>+<manifest>      is the root the in-package snapshot?
    --repo / --cert-identity-regex / --issuer       → yes: bootstrap-trusted (integrity only)
    (SAN binds workflow path AND the bundle ref)  → no:  trusted ONLY if client state records
  → manifest pack hashes + no undeclared pack             this version+digest was attested
  → fresh (short TTL; freeze protection)          → pack hashes + no undeclared pack
  → version > client_state.highest_version        → not revoked
  → prev_digest REQUIRED once installed, and       → else untrusted
    chains to the high-water manifest head
  → not revoked
  ANY failure → DISCARD the download (keep LKG)
```

This defends against: knowledge tampering, rollback to vulnerable knowledge, freeze
on a stale version, a forged bundle (no valid attestation), mix-and-match of files
(the attestation covers the manifest, which pins **every file** in the OKF bundle by
`{sha256,size}` — concept `.md` files and the reserved `index.md`/`log.md` alike — and
`knowledge_verify.py` rejects any undeclared file of any extension), and a malicious
mirror. Trust is **identity-constrained** by construction — a valid attestation for
some *other* repo/workflow does not satisfy the anchor. Fail-secure means the failed
download is discarded entirely; no metadata from it participates in a fallback, and
the independently-verified last-known-good is retained. Attestation verification
shells out to the system `gh attestation verify` (no Python crypto dependency;
mirrors the `ssh-keygen` shell-out convention) and is required only in the Updater
path — the Assessor verifies against recorded client state with no network or `gh`.

**OKF serialization and its trust boundary.** The verified plane ships as an Open
Knowledge Format (OKF v0.2) markdown bundle (`knowledge/bootstrap/<domain>/<slug>.md`),
parsed by `scripts/okf.py` (root-of-trust, §6). Two properties keep the format from
widening the attack surface:

1. **No parser differential over signed bytes.** A hand-rolled small-subset YAML
   reader could otherwise let the signing side and the reading side disagree on what a
   byte stream means. `okf.py` parses a deliberately tiny grammar (top-level mapping,
   2-space block mappings/sequences, inline scalars only — prose lives in the markdown
   body, so there are no multi-line scalars), **never raises** (any violation degrades
   to `parse_partial`, which fails the set closed), and its writer emits a single
   canonical normal form. A release-time self-check asserts `dump(parse(bytes)) ==
   bytes` for every shipped file, so a non-canonical (ambiguously-parseable) file
   cannot be released.
2. **OKF's trust fields are advisory and are never read by code.** OKF's own
   `status`/`generated`/`verified`/`stale_after` families are "signals, not access
   control" by design. AttestArc's sole trust gate is the cryptographic attestation
   against the external anchor; the security code reads status only from the
   authoritative `attestarc.status` namespace and never branches on the OKF-native
   projection (which is lossy — it cannot represent `disputed`/`superseded`/`retired`).
   `authority` (a numeric score) likewise stays in the `attestarc:` namespace so the
   provenance-vs-registry gate keeps working. This rule is enforced by
   `test_advisory_projection_is_never_read_back`: a poisoned concept whose advisory
   keys contradict its `attestarc:` namespace must change no conclusion.

**Verify → install → persist.** `verify_download` is a pure fact operation: it
answers "should this bundle be installed?" and mutates nothing. Advancing the
high-water mark and installing a snapshot is done by exactly one path,
`knowledge_verify.py install <bundle>`, so verification can never leave client
state half-advanced (the earlier TOCTOU where a bundle verified but nothing
installed is closed). `install`:

1. If `<bundle>` is an archive, **verify the archive's own attestation first**
   (the published `.tar.gz` is attested at release time alongside the manifest), so
   unattested bytes never reach the tar reader; then **safe-extract** it
   (`_pathsafe.safe_extract_tar`, itself root-of-trust) into a private staging dir —
   refusing absolute paths, `..` traversal, and every non-regular member
   (symlink/hardlink/device/fifo) *before* writing anything, and extracting
   member-by-member with our own IO (never `tarfile.extractall`) so a malicious
   archive can neither escape staging nor plant a link a later member follows out of
   it. The extractor also bounds member count and per-file/total uncompressed size
   (re-checked against the bytes actually streamed, so a header that under-declares its
   size cannot slip past), so a decompression bomb is refused before it can exhaust
   disk — defense-in-depth for this offline extract-before-attest step. (The archive
   pre-check is skipped only for an offline install, where the manifest attestation +
   pack integrity still gate the result.)
2. Run `verify_download` (attestation + integrity + freshness + rollback +
   `prev_digest` chain + revocation). Any failure → `discard`, nothing installed.
3. Copy **only** the manifest and the declared packs into `snapshots/vN.tmp`,
   re-verify the *staged* bytes against the (attested) manifest, then run a
   **semantic pre-install gate** over the staged snapshot — the *same*
   `validate_snapshot` + `check_consistency` + parse-completeness checks the Assessor
   read path uses, scoped to the in-package source registry — and refuse (discard the
   staged copy, do not advance) if it fails. Attestation proves origin, not that the
   content obeys the trust contract; without this gate an attested-but-invalid bundle
   could advance the high-water mark to a version the Assessor can never actually read
   (a durable availability hole). Only once the staged snapshot both hash-matches and
   passes the semantic gate is it `os.replace`d into `snapshots/vN` — the install is
   atomic.
4. Advance client state in a single atomic write: `highest_version`, `current`
   (`{version, manifest_sha256, verified_via, path}`), `history`, and — whenever
   `version` reaches a new high — `highest_manifest_sha256`, the **high-water chain
   head** the next release's `prev_digest` must match.

The `prev_digest` chain is checked against that **high-water head, not the active
`current` snapshot**. A revocation may roll `current` back to an older last-known-good,
but it never lowers `highest_version` or the chain head, so `v4 → v5 → revoke(v5) → v6`
still installs (v6 chains to the v5 head). The rollback target is **not trusted merely
for being the next history entry**: before a historical snapshot is adopted as
`current`, it is re-verified (its path exists, its on-disk manifest digest still matches
the digest recorded in history — an anti-tamper check — its packs pass integrity, and it
passes the same semantic gate). A candidate that no longer verifies is skipped for the
next-older good one; if none verify, `current` is left empty so the Assessor falls back
to the in-package bootstrap. A tampered retained snapshot is therefore never silently
reinstated on rollback. Once anything is installed (floor > 0) a
downloaded manifest **must** carry a `prev_digest` equal to the head — a missing chain
link is fail-closed (`discard`), not silently treated as a first install. Only a genuine
first install (floor 0) may omit it. (Client state written before this field existed is
backfilled from `current` when it is the highest version.)

Client state and snapshot material live in **separate directories** —
`~/.attestarc/state/` (rollback memory) and `~/.attestarc/knowledge/snapshots/`
(installed material) — so corrupting one cannot damage the other. Persistent
client state (`load_client_state`) fails **open only when absent** (a fresh machine
legitimately starts at an empty floor); a *present-but-corrupt* state file means
rollback memory was lost or tampered, so it is marked `_corrupt` and `install` /
`verify_and_apply_revocation` **refuse to advance** until an explicit reinit, and
the Assessor falls back to the in-package bootstrap.

**Release provenance (producer side).** The one workflow that can mint a trusted
attestation, `.github/workflows/release-knowledge.yml`, is itself root-of-trust and
constrains what it will sign: (1) **strictly separated triggers** — a normal bundle
is produced ONLY by a push of a `knowledge-v*` tag (`build-attest-publish`), and a
revocation ONLY by a `workflow_dispatch` on `main` (`revoke`); neither job can run on
the other's trigger, and the two are attested under distinct SAN identities so neither
can impersonate the other; (2) an **exact-HEAD gate** for a bundle — the build refuses
unless the tagged commit **is the current tip of `origin/main`**, not merely an
ancestor, so a historically-reviewed but obsolete commit cannot be retagged as a higher
knowledge version (rollback by relabeling); the revocation job keeps an ancestry gate
since it is dispatched from a branch; (3) **both** the `manifest.json` **and** the
published `.tar.gz` are attested and self-verified (`gh attestation verify` against the
exact triggering ref) *before* publishing — fail-secure, never publish-then-trust;
(4) the builder populates `prev_digest` **fail-closed** — if a prior `knowledge-v*`
release exists it MUST be listed, downloaded, its archive attestation authenticated
(bundle identity), and its manifest read, or the build refuses to publish; a `null`
is emitted only when no prior release exists, so the client never receives a spurious
"first install" that skips chain validation; (5) the kill switch emits
`revoked_versions: [N]` (a non-empty list of positive ints — the shape the client
validates), attested exactly like a bundle; and (6) the third-party attestation action
is pinned to a full commit SHA, set/verified in the two-party review that gates this
file. The attest+publish job additionally runs only in the protected `knowledge-release`
environment, whose deployment tag policy restricts it to `knowledge-v*` tags; those tags
are immutable and required to be signed. (Environment REQUIRED-REVIEWER approval is not
set: a single-maintainer repo cannot self-approve, so the exact-HEAD gate, ref-bound
identity, and signed-immutable tags are the enforceable controls.) These are
producer-side constraints; the client still independently verifies every downloaded
artifact against the anchor.

## 4a. Distribution security (the package itself)

§4 authenticates *knowledge bundles*. The **skill package** — the code, kernel,
schemas, and the bootstrap knowledge snapshot — needs its own install-time
integrity story, because the package is what establishes every subsequent trust
decision (it carries `knowledge/trust-anchor.json`, the kernel, and the promotion
policy). Honest statement of the property:

- **A plain `git clone --branch <tag>` does NOT verify the tag's SSH signature.**
  Git checks out the named ref without validating any signature unless the caller
  explicitly runs `git verify-tag`/`git tag -v` with the maintainer's public key.
  So cloning a "signed release tag" gives you the bytes at that ref, not a
  cryptographic guarantee of who produced them. Documentation MUST NOT imply the
  installer verifies the signed release when installing from a clone.
- **The cryptographic install-time check is the attested-tarball path.**
  `.github/workflows/release-skill.yml` (root-of-trust) packages exactly the
  shipped `SKILL_PAYLOAD` into `attestarc-skill-<tag>.tar.gz`, attests it with
  GitHub Artifact Attestations (Sigstore build provenance, OIDC) under the
  identity `release-skill.yml@refs/tags/v<semver>`, self-verifies, and publishes
  it. An **exact-HEAD gate** (identical to the knowledge release job) refuses to
  sign unless the tagged commit is the current tip of `origin/main`, so a stale
  reviewed commit cannot be relabeled as a higher package version.
- **`install.py --from-tarball <path>`** loads the external `bootstrap-anchor.json`
  (which lives at the repo root *outside* `SKILL_PAYLOAD` — a bundle can never
  declare its own trust), runs `gh attestation verify` against the anchor's repo +
  OIDC issuer + `cert_identity_regexp` **before extracting anything**, and only
  then safe-extracts (member-by-member via `_pathsafe.safe_extract_tar`) and
  installs from the verified contents. Fail-secure: a missing `gh`, a verify
  failure, or a missing anchor aborts the install; nothing is extracted first.
- A source-checkout install (`python install.py` from a clone) remains supported
  for development and for users who verify the tag signature out of band; it still
  runs the in-package knowledge integrity + trust-contract gate
  (`verify_bundled_knowledge`), but it makes **no** claim to have cryptographically
  authenticated the package. Users who want that guarantee install `--from-tarball`.

## 5. Fail-secure runtime policy

The runtime NEVER fetches-then-trusts. On any anomaly it degrades safely:

| Condition | Response |
|-----------|----------|
| Attestation absent / identity mismatch (download) | **Discard** the download; keep the installed last-known-good |
| Manifest/pack tampered, rolled back, or frozen (expired) | **Discard** the download; keep the installed last-known-good |
| Downloaded manifest omits `prev_digest`, or it does not chain to the high-water head, once anything is installed (floor > 0) | **Discard** — a missing/broken chain link is fail-closed, never read as a first install |
| Revocation rolled `current` back to an older LKG | The high-water chain head is preserved (revocation never lowers `highest_version`), so the next in-order release still chains and installs |
| Downloaded bundle presents `mode: bootstrap` | **Reject** — bootstrap is valid ONLY for the in-package snapshot |
| Downloaded archive contains an unsafe member (absolute path, `..`, symlink/hardlink/device) | **Refuse** the whole extract before writing anything; nothing is installed |
| Downloaded archive is a decompression bomb (too many members, or a member/total uncompressed size over the cap) | **Refuse** the extract before writing anything (member-count + per-file + total caps, re-checked against actual bytes streamed so a lying header cannot slip past); nothing is installed |
| Rollback target (retained LKG) fails re-verification (missing, tampered, or recorded-digest mismatch) | **Skip** it for the next-older verifiable snapshot; if none verify, leave `current` empty so the Assessor falls back to the in-package bootstrap |
| Active (refreshed) snapshot fails verification at assessment time | Assessor **falls back to the verified in-package bootstrap** (the signed last-known-good floor) and continues, marking `fell_back_to_bootstrap`; it neither reasons over the untrusted set nor aborts the assessment |
| Client state present but corrupt/unparseable (rollback memory lost) | Mark `_corrupt` and **refuse** to advance state (`install`/revocation); Assessor falls back to the in-package bootstrap until explicit reinit |
| Installed knowledge expired (stale/frozen) | Warn; snapshot stays trusted as the last-known-good floor, but a **stale down-gate** fact (`effect: mitigation`/`neutral`) no longer drives a conclusion (route to `needs_review`) — only `effect: risk-increasing` facts keep driving (failing toward scrutiny) |
| Snapshot violates its own trust contract (schema / provenance-vs-registry / secret) | `validate_snapshot` withholds trust → set untrusted (`needs_review`); refused at install time |
| A verified pack only partially parses (`parse_partial`) | Treat the whole set as inconsistent/untrusted — never reason over the lines that happened to parse |
| Knowledge read with the gate skipped (`--allow-unverified`, tooling only) | Facts are surfaced but `drives_conclusion` is forced false — an unverified read can never close a chain |
| Knowledge unavailable | Fall back to the in-package snapshot |
| Knowledge conflict (authoritative vs authoritative) | `status: disputed` → downgrade dependent conclusions to `needs_review` |
| Source unavailable | Do not invent an answer |
| Unknown platform/version | `needs_review` |
| Updater looks compromised | Disable the Updater |
| Knowledge changed after a finding was recorded | Mark dependents `requires_reverification`; re-observe |

Uncertainty MUST route to `needs_review`, never to "ask the LLM what seems
reasonable."

## 6. Promotion policy and root-of-trust files

Promotion from candidate to verified is **deterministic** (`core/promotion-policy.md`).
The LLM may *propose*; it may never `promote()`.

The model produces a **candidate** (`schemas/knowledge-candidate.schema.json`) that
**omits** the trusted `status`/`confidence` fields and never declares a source's
`publisher`/`type`/`authority` — a candidate carrying `status`/`confidence` is a
structural error. Only deterministic promotion (`promote_to_verified`, gated by an
auto-promote tier) emits a verified entry (`schemas/knowledge.schema.json`),
assigning `status: active`, deriving `confidence` from source authority, and copying
provenance from the self-verified quarantine receipt. `may_promote` is fed the
validation-result object and **refuses to run** on an unvalidated candidate;
`evaluate_candidate` is the single unskippable orchestrator (validate → conflict →
semantic diff → direction → may-promote).

- **Auto-promote** — validated candidate + authoritative source (derived authority
  ≥ 90) bound to a **resolvable, self-verifying** quarantine receipt + no conflict +
  does not modify or supersede an active claim + a non-negative/non-uncertain
  **derived** direction + a **digest-bound** passing **eval-result artifact** + (for
  published packs) no failed attestation.
- **Require review (PR)** — supersedes, conflicts with, or otherwise **modifies an
  existing active claim** (an additive edit of an active entry routes to review even
  without `supersedes`), or the derived direction is security-**negative** or
  **uncertain** (previously-vulnerable becomes "safe", or a change we cannot prove is
  safe — the exact shape a poisoning attempt takes), or the eval-result artifact is
  missing/failing.
- **Two-party review** — changes to root-of-trust files: `core/agent-safety.md`,
  `core/promotion-policy.md`, `scripts/knowledge_verify.py`, `scripts/knowledge.py`,
  `scripts/knowledge_compile.py`, `scripts/_pathsafe.py` (the containment +
  safe-extract helper the install path trusts against untrusted archives),
  `scripts/okf.py` (the OKF concept serializer/parser — a parser differential here
  would let two readers disagree on a signed byte stream),
  `knowledge/sources.yaml`,
  `knowledge/trust-anchor.json`, `schemas/knowledge*.schema.json` (including the
  candidate schema), `schemas/okf-concept.schema.json`,
  `schemas/learning-candidate.schema.json`,
  `schemas/eval-result.schema.json`, anything under `knowledge/promotions/` (the
  per-entry promotion decisions and the bootstrap approval),
  `bootstrap-anchor.json` (the package-distribution root of trust),
  `.github/workflows/release-knowledge.yml`, `.github/workflows/release-skill.yml`
  (attests the distributed package tarball), or **any weakening/deletion of a
  trusted eval**.
- **Never auto-promote** — blog / issue / researcher post / model inference →
  candidate only.

**What "two-party review" means, and its enforcement ceiling.** Two-party review is
the *policy* for every root-of-trust change: a second trusted reviewer approves
before merge. What the repository *mechanically enforces* today is the enforceable
floor — every change lands via a pull request into a protected `main` (no direct
push, no force-push, no deletion, linear history, required status checks), the eval
corpus gates the change, and third-party Actions are SHA-pinned; the attest+publish
job runs in a protected `knowledge-release` **environment** whose deployment policy
restricts it to `knowledge-v*` tags, release tags are immutable and **must be signed**
(`knowledge-v*` tag ruleset: `required_signatures` + no force-push/deletion), and the
release identity is ref-bound (§4). On a **single-maintainer** repository GitHub cannot enforce a second *approval*
(an author may not approve their own PR), so two-party review is applied whenever a
second reviewer is available rather than blocking every merge — the guarantee is the
enforceable floor plus this policy, not an unconditional two-approval gate. Adding a
second maintainer (or a trusted review bot) and raising `required_approving_review_count`
promotes the policy into a mechanical gate without any code change.

Authority is assigned by the source registry (`knowledge/sources.yaml`), never by
the model, and URL paths are dot-segment-normalized before prefix matching (a
`/actions/../evil` cannot smuggle a trusted org prefix). Conflict and semantic diff
are computed against a **mandatory, pinned immutable baseline** — the last verified
released snapshot, resolved from the installed verified snapshot
(`resolve_verified_baseline`, fail-closed if none is trusted) or an explicit
`--baseline`; the working tree that carries the proposal is **never** an implicit
baseline (judging a candidate against the tree that already contains it would erase
the conflict/modify signal). The set of changed paths and removed/modified evals is
**derived from git** (`git diff --name-status <baseline-commit> HEAD`), not from
caller-supplied flags, so a caller cannot omit the path carrying a poisoning edit.
The security direction is **derived** from the candidate's `effect` and its baseline
diff, never read from a model-controlled field. Content-promotion eligibility is
separate from distribution trust: a *missing* attestation (`None`) means "not attested
yet" and never reads as valid, but does not by itself block content promotion; only a
genuine **failed** attestation over a published pack blocks. The eval corpus is itself
root-of-trust: a candidate MAY *add* paired find/refuse evals but MUST NOT weaken or
delete trusted evals in the same trust step.

**The eval-result is digest-bound; promotion is recomputed at release.** The
eval-result artifact (`schemas/eval-result.schema.json`) is trusted only when it binds
to the exact inputs it was produced over — `candidate_sha256`, `baseline_manifest_sha256`,
and `eval_corpus_sha256`, all recomputed by `_load_eval_result_verified` and rejected on
any mismatch — so a bare `{"passed": true}` or a result recycled from a different
candidate/baseline/corpus can never satisfy auto-promote. This is not an eval-runner:
the behavioral evals stay manually judged; the artifact only binds a judgement to a
change. And the tier a maintainer saw in a PR is not, by itself, what ships:
`knowledge_compile.py verify-promotions` runs in the release workflow **before the
manifest is built** and fails the release unless **every active entry** in the packs is
accounted for by a digest-pinned `knowledge/promotions/bootstrap.approval.json` entry
(the hand-authored entries that predate the pipeline), an `<entry-id>.decision.json`
whose digest + baseline match and which **still recomputes** to `auto-promote` from the
pinned baseline + git-derived diff + rebound eval-result, or a review-tier decision with
a recorded approver. An entry edited after its decision, whose decision no longer
recomputes, or that nothing accounts for, fails the release. This makes
`promote_to_verified` the **only** path to a shipped active entry, not merely *a* path a
hand-edited pack could sidestep; it recomputes only what is reproducible from shipped
material (it never re-runs quarantine/fetch — provenance is recorded in the decision).

## 7. Findings, provenance, and invalidation

- Every finding derived from a knowledge entry MUST record its
  `knowledge_dependencies` (`{id, content_hash}`; `content_hash` is REQUIRED — an
  id alone cannot reliably invalidate a finding when the underlying claim changes).
- When a dependency is superseded/revoked, dependent findings surface
  `requires_reverification` (a read-time view; stored status is never silently
  mutated). A knowledge change MUST NEVER auto-resolve a finding.
- Secrets and private repository content MUST NEVER enter the learning pipeline;
  learning defaults to local-only. Sanitized attack *shapes* (not code) are the only
  material that may generalize.
- A secret value MUST NOT be persisted even as a hash. `record-safety-event`
  fingerprints an injection attempt with a `content_hash`, but when the injected
  text looks like a secret the hash is **withheld** (a short/low-entropy secret is
  recoverable from its sha256 by brute force / rainbow table); only a
  `content_redacted` marker plus source/location metadata is stored, keeping the
  attempt auditable without persisting a recoverable fingerprint.

## 8. Kill switch

A compromised knowledge version MUST be revocable: publishing a revocation causes
clients to disable that version, roll back to the last verified snapshot, and mark
findings assessed under it `requires_reverification`. This path is designed before
it is needed.

The **only** public revocation path is `verify_and_apply_revocation`: it
attestation-verifies the revocation record against the trust anchor (same identity
constraints as a bundle — an unattested or forged record is discarded and client
state is left untouched), structurally validates it, records the revoked version(s),
and rolls `current` back to the most recent retained non-revoked snapshot still on
disk (or to the in-package bootstrap when none remains). It refuses to apply on a
corrupt client state. The internal `_apply_revocation` (which trusts its caller)
has no public entry point, so nothing can revoke — or, by extension, roll the active
snapshot back — without a valid attestation. Rolling back never resolves a finding;
dependents surface `requires_reverification` and the condition is re-observed.

## 9. Glossary

Terms coined in this document and reused across `SECURITY.md`, `SPECIFICATION.md`,
and the security page.

- **Trust anchor** — the external root of trust for *knowledge bundles*
  (`knowledge/trust-anchor.json`) that ships inside the skill package and lives
  outside any downloaded bundle. It pins the Sigstore build-provenance identity
  (repo + signer workflow + OIDC issuer) an official bundle must have been produced
  under. Two-party review to change.
- **Bootstrap anchor** — the external root of trust for the *skill package
  distribution* (`bootstrap-anchor.json`), distinct from the knowledge trust
  anchor. It lives at the repo root *outside* the shipped payload (not in
  `SKILL_PAYLOAD`) and pins the Sigstore build-provenance identity
  (repo + `release-skill.yml@refs/tags/v<semver>` + OIDC issuer) an official
  package tarball must carry. `install.py --from-tarball` runs `gh attestation
  verify` against it *before extracting anything*. This is the cryptographic
  install-time check on the package itself; a plain `git clone --branch <tag>`
  does **not** verify the tag's SSH signature, so it establishes no package
  authenticity. Two-party review to change.
- **Bootstrap-trusted** — the trust status of the *in-package* knowledge snapshot:
  it is trusted for integrity (its packs match the manifest) *because it rode in
  with the skill package*, not because it declares itself trusted. The package's
  own authenticity is established at install time only when installed via the
  attested-tarball path (`--from-tarball`, verified against the bootstrap anchor);
  a plain git clone of a signed tag does not verify the tag signature. A
  *downloaded* bundle presenting `mode: bootstrap` is always rejected.
- **Verified-LKG (last-known-good)** — a refreshed snapshot that is trusted only
  because persistent client state records that its exact version + manifest digest
  was attestation-verified. The retained LKG is what fail-secure falls back to.
- **Candidate entry** — the untrusted shape the model produces
  (`schemas/knowledge-candidate.schema.json`): the same fields as a verified entry
  **minus** the trusted `status`/`confidence` and minus any model-declared source
  `publisher`/`type`/`authority`. Those are assigned by deterministic promotion; a
  candidate carrying them is rejected structurally.
- **Quarantine receipt (`QR-…`)** — a **self-verifying** record binding an upstream
  fetched document (stored by content hash) to its registry-derived provenance. The
  receipt id is the full sha256 of the stored bytes; resolving a receipt re-hashes
  the stored `.raw` and re-classifies its `final_url`, so a fabricated receipt whose
  bytes do not rehash (or whose URL no longer classifies) does not resolve. It
  records `requested_url`/`final_url`/`redirect_chain`; a cross-origin redirect off
  the final origin is marked not-allowed. A promotion-eligible source MUST carry a
  resolvable receipt (an inline hash alone is insufficient). Candidate knowledge
  references a receipt; the document is inert data, never instructions.
- **Derived authority** — a source's authority integer, obtained by reclassifying
  its URL through the identity-scoped source registry (`knowledge/sources.yaml`,
  dot-segment-normalized before prefix matching), never taken from a candidate's
  self-declaration. A candidate whose declared authority/publisher/type disagrees
  with the derived values is rejected.
- **Immutable baseline** — the last verified released snapshot, against which
  conflict and semantic diff are computed. Mandatory and pinned (resolved from the
  installed verified snapshot or an explicit `--baseline`); never the working tree
  that carries the proposal, so a proposal cannot launder itself by editing what it
  is compared to.
- **Derived direction** — a conservative security-regression signal computed from
  the candidate's `effect` and its baseline semantic diff, never read from a
  model-controlled field. A new `mitigation`, or a modification moving an active
  `risk-increasing` claim toward `mitigation`/`neutral`, is **negative**; any other
  modification of an active semantic is **uncertain**; both route to review.
- **Eval-result artifact** — the small JSON the eval step emits
  (`schemas/eval-result.schema.json`) that the promotion policy consumes, trusted only
  when **digest-bound** to the candidate (`candidate_sha256`), the baseline
  (`baseline_manifest_sha256`), and the eval corpus (`eval_corpus_sha256`) — all
  recomputed and rejected on mismatch. Absent, unbound, or `passed: false` fails closed
  (blocks auto-promote); `passed` requires an empty `failures` list.
- **`verify-promotions` gate** — the release-time recompute (`knowledge_compile.py
  verify-promotions`) that fails the build unless every active shipped entry is
  accounted for by the digest-pinned bootstrap approval, a still-recomputing
  auto-promote decision, or a review-tier decision with a recorded approver. Makes
  `promote_to_verified` the only path to a shipped active entry.
- **Bootstrap approval** (`knowledge/promotions/bootstrap.approval.json`) — the
  digest-pinned, two-party approval recorded once for the hand-authored entries that
  rode in with the skill package and predate the promotion pipeline (so carry no
  quarantine receipts); one canonical digest per entry id.
- **`requires_reverification`** — a read-time view surfaced on a finding whose
  knowledge dependency was superseded or revoked. The stored status is never
  silently mutated and a knowledge change never auto-resolves a finding; the
  condition is re-observed.
- **`needs_review`** — the fail-secure landing state for uncertainty: an unknown
  platform/version, an unverifiable snapshot, or an authoritative-vs-authoritative
  conflict routes here rather than to an improvised LLM judgment.
