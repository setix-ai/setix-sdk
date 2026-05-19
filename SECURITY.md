# Security policy

## Reporting a vulnerability

Send vulnerability reports to **security@setix.com**.

We follow coordinated disclosure: 90 days standard, 30 days when a working proof-of-concept is provided. We acknowledge reports within two business days and aim to publish a fix and advisory within the disclosure window.

Please do not file public GitHub issues for security bugs.

## Release integrity

Every release of `@setix/thread` (npm) and `setix-thread` (PyPI) is:

1. Built from a tagged commit in this repository.
2. Signed with the founder-personal Ed25519 release key (transitions to the Setix Foundation attestation key after v1.0.0).
3. Mirrored in a SHA-256 release manifest at <https://setix.ai/.well-known/sdk-integrity.json>.
4. Published with npm provenance (TypeScript) and PyPI Trusted Publishing (Python). The provenance attestations are anchored in sigstore's public transparency log; both are verifiable independently of this repository.

### Verifying a downloaded artifact

After installing, compare the file hashes against the release manifest at <https://setix.ai/.well-known/sdk-integrity.json>:

```bash
# TypeScript
npm view @setix/thread@<version> --json | jq -r '.dist'

# Python
pip download setix-thread==<version> --no-deps -d /tmp/setix-thread
sha256sum /tmp/setix-thread/*.whl
```

The integrity endpoint serves an array of records, one per release:

```json
{
  "sdk_integrity_manifest": [
    {
      "tag": "v0.0.X",
      "files": [{ "path": "...", "sha256": "..." }],
      "signed_by": "founder-personal",
      "signed_at_slot": 0
    }
  ],
  "setix_foundation_attestation_pubkey_hex": "<hex>",
  "scope": "v0.0.x"
}
```

If a downloaded artifact's hash does NOT match the published manifest, do not use it — open a vulnerability report.

## Release signing key

Public-key fingerprint of the founder-personal Ed25519 release signing key:

```
SHA256:0C8edPhJc9qhT21cznp8FrH1FldkNYv9Ge8Xe01+xgc
```

Same key signs commits and tags in this repository; you can verify any commit or tag locally with `git verify-commit` / `git tag --verify` once you have the public key configured.

## Publisher compromise

If we detect or suspect that an npm or PyPI publisher account has been compromised, the operator runbook calls for: revoking the publisher 2FA tokens, yanking the affected releases on both registries, publishing an advisory at <https://setix.ai/security>, and re-publishing from a known-good source on a fresh publisher account. Recovery targets: detection-to-yank under 30 minutes; full re-publish under four hours.
