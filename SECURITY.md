# Security policy

## Reporting a vulnerability

Send vulnerability reports to **security@setix.com**.

We follow coordinated disclosure: 90 days standard, 30 days when a working proof-of-concept is provided. We acknowledge reports within two business days and aim to publish a fix and advisory within the disclosure window.

Please do not file public GitHub issues for security bugs.

## Release integrity

Every release of `@setix/thread` (npm) and `setix-thread` (PyPI) is:

1. Built from a **signed tag** in this repository (Ed25519; founder-personal key until v1.0.0, transitioning to the Setix Foundation attestation key after).
2. Published with **npm provenance** (TypeScript) and **PyPI Trusted Publishing** (Python). The provenance attestations are anchored in sigstore's public transparency log; both are verifiable independently of this repository.
3. Accompanied by **sigstore-signed artifact bundles** attached to the GitHub Release for the tag.

### Verifying a downloaded artifact

```bash
# TypeScript — verify the npm provenance attestation chain:
npm audit signatures

# Inspect the published dist integrity fields:
npm view @setix/thread@<version> --json | jq -r '.dist'

# Python — PyPI Trusted Publishing binds the artifact to this repository's
# release workflow; download and hash for cross-checking against the
# GitHub Release's sigstore bundle:
pip download setix-thread==<version> --no-deps -d /tmp/setix-thread
sha256sum /tmp/setix-thread/*.whl
```

A machine-readable per-release SHA-256 manifest additionally serves at
<https://mcp.setix.dev/.well-known/sdk-integrity.json> (rows are being
backfilled for the `0.0.x` releases; sigstore + provenance above are the
authoritative verification path while the band is pre-1.0).

If a downloaded artifact fails provenance verification or its hash does not match the release's signed bundle, do not use it — open a vulnerability report.

## Release signing key

Public-key fingerprint of the founder-personal Ed25519 release signing key:

```
SHA256:0C8edPhJc9qhT21cznp8FrH1FldkNYv9Ge8Xe01+xgc
```

Same key signs commits and tags in this repository; you can verify any commit or tag locally with `git verify-commit` / `git tag --verify` once you have the public key configured.

## Publisher compromise

If we detect or suspect that an npm or PyPI publisher account has been compromised, the operator runbook calls for: revoking the publisher 2FA tokens, yanking the affected releases on both registries, publishing an advisory at <https://setix.ai/security>, and re-publishing from a known-good source on a fresh publisher account. Recovery targets: detection-to-yank under 30 minutes; full re-publish under four hours.
