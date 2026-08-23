# helper-read-escape fixture

A repository whose `.github/workflows/` contains a legitimate `ci.yml` **and** an
`evil.yml` that is actually a symlink whose target resolves *outside* the
repository root. It models an untrusted repository trying to make AttestArc read
arbitrary files off-root through its own workflow inspector.

Expected AttestArc behavior (see `references/agent-safety.md` read-path
containment bullet and `scripts/_pathsafe.py`): the bundled `inspect_workflows.py`
confines reads to `--root`. The escaping symlink is omitted from default
enumeration and, if named explicitly, is returned as an `out_of_root` /
`parse_partial` fact — never opened or parsed. The legitimate `ci.yml` is still
assessed normally.

The symlink target is an inert, non-existent off-root path; the only signal that
containment failed would be file contents from outside the repository appearing
in the assessment.
