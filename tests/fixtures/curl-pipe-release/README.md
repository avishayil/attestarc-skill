# Fixture: curl-pipe-release

**Status: vulnerable.**

A release workflow (`on: push` tags `v*`) holding `contents: write` and
`id-token: write`, whose `release` job runs, in the `production` environment:

```yaml
run: curl -fsSL https://example.com/install.sh | bash
```

before building and publishing the release.

This is **download-and-execute in a privileged job**. The fetched script is not
pinned, checksummed, or reviewed; whoever controls (or can MITM / take over)
`example.com` decides what code runs with the release job's capabilities:
`MUTATE_RELEASE` (`contents: write` on a release tag),
`REQUEST_WORKLOAD_IDENTITY` (`id-token: write`), and any environment access.

Trust transition: **dependency → build** (a fetched script becomes build-time
code). Actor is an external network/host party; reachability is `conditional`
on that party acting, but the reached asset (release + identity) is high-value.

Expected: a **high**/**critical** finding for arbitrary code execution reaching
release and identity capabilities. Remediation is to pin the installer (vendored
or checksum-verified), not merely to add TLS flags.
