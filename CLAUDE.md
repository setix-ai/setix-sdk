# setix-sdk — operating context

You are working in `setix-sdk`, the public-facing thin-client SDK repository for the THREAD protocol.

**CRITICAL: this repo is published.** Every commit, every tag, every file, every identifier in this repository will eventually be visible to the public. The pre-commit hook at `.githooks/pre-commit` enforces three independent fail-closed layers (secret-shape scan, protocol-internal-field-name scan, public-clean vocabulary scan). Do not bypass with `--no-verify`. If the hook blocks, REWRITE the offending content.

---

## Repo identity

| Field | Value |
|---|---|
| Name | `setix-sdk` |
| Purpose | TypeScript + Python thin-client SDKs over the public THREAD protocol surface. Released to NPM as `@setix/thread` + PyPI as `setix-thread` at the operator-manual visibility flip. |
| Tag stream | Bare SemVer (no prefix): `v0.0.X`, `v0.1.X`, `v1.0.0` |
| Signing key fingerprint | `SHA256:0C8edPhJc9qhT21cznp8FrH1FldkNYv9Ge8Xe01+xgc` (1Password Ed25519) |

---

## Commit + signing

- **All commits SSH-signed** via the Ed25519 key above.
- **All commits authored as** `Usman Mustafa <usman@setix.ai>`.
- **No collaborator-attribution trailers** in commit messages. The hook catches the standard ones.
- **Pre-commit hook fail-closed.** `--no-verify` is FORBIDDEN.
- **Verify push** after every tag: `git ls-remote origin main` + `git ls-remote --tags origin | grep <tag>`.

---

## Brand vocabulary

- Lowercase `setix` in code, paths, identifiers, file names.
- Uppercase `SETIX` only as a code prefix.
- THREAD acronym preserved; never rename.

---

## Trunk-only branching

- All work on `main`. No feature branches.
- Pull before starting work: `git pull --ff-only origin main`.
- Push immediately after commit + tag.

---

## Tag stream + versioning

**Strict bare SemVer in the 0.x.y range.** No pre-release suffixes — no `-pre`, `-rc`, `-alpha`, `-beta`, `-post`, `+metadata`.

- `v0.0.X` — pre-public iteration; package builds verified locally
- `v0.1.X` — pre-public stabilization
- `v1.0.0` — first public NPM `@setix/thread` + PyPI `setix-thread` publication

Tag format: bare `vX.Y.Z`. Annotated. Signed via the Ed25519 key.

Tag annotation: one-line summary of the public-visible change. Avoid internal development-process vocabulary; the hook scans both tag annotations (via the commit-message check on the tagged commit) and file content.

---

## Multi-machine coherence

This repo is developed across two hosts (operator may switch between them depending on session). Both machines must have identical local git config. **Verify before starting any work session:**

```bash
git config user.email           # MUST = usman@setix.ai
git config user.name            # MUST = Usman Mustafa
git config user.signingkey      # MUST resolve to Ed25519 SHA256:0C8edPhJc9qhT21cznp8FrH1FldkNYv9Ge8Xe01+xgc
git config commit.gpgsign       # MUST = true
git config tag.gpgsign          # MUST = true
git config gpg.format           # MUST = ssh
git branch --show-current       # MUST = main
git status --short              # MUST be empty before starting work
git remote -v                   # origin = git@github.com:setix-ai/setix-sdk.git
```

---

## Public-clean discipline — three pre-commit hook layers

Apply continuously. The repo's `.githooks/pre-commit` enforces:

1. **Secret-shape scan** — well-known secret patterns (PEM blocks, cloud-provider API keys, source-control tokens, model-provider tokens, password-manager refs, etc.). If a legitimate match needs to ship, add the inline marker the hook documents on the offending line.
2. **Protocol-internal field-name scan** — internal document-tag constants and secret-key transmission patterns that must never appear in client code. The thin-client architecture means private keys never cross the SDK process boundary; this layer enforces that boundary.
3. **Public-clean vocabulary scan** — staged commit message + staged file content checked for internal development-process vocabulary. **The canonical list of forbidden patterns lives in `.githooks/pre-commit` — read that file directly when in doubt.** The hook is self-documenting; this CLAUDE.md does not reproduce the list inline (doing so would itself trigger the scan).

If the hook blocks, READ THE HOOK OUTPUT (it names the offending pattern), then REWRITE. Never bypass.

---

## What's in this repo

Native files (author here directly; subject to all three hook layers):

- `README.md`, `LICENSE`, `SECURITY.md`
- `.gitignore`, `.githooks/pre-commit`
- `.github/workflows/*.yml` (CI; npm publish; PyPI publish; sigstore signing)
- `typescript/package.json`, `typescript/tsconfig.json`
- `python/pyproject.toml`
- `CLAUDE.md` (this file)

Mirrored files (regenerated from upstream sources; do NOT edit directly here):

- `typescript/src/setix-thread.ts`
- `typescript/src/chain-tx-encoders.ts`
- `python/setix_thread/__init__.py`
- `python/setix_thread/chain_tx_encoders.py`

If you need to change a mirrored file, edit the upstream source + regenerate. The upstream regeneration is an operator-side action — not done from within this repo.

---

## Release integrity

Every release of `@setix/thread` + `setix-thread` is:

1. Built from a tagged commit in this repository
2. Signed with the founder-personal Ed25519 release key (transitions to the Setix Foundation attestation key after v1.0.0)
3. Mirrored in a SHA-256 release manifest at `https://setix.ai/.well-known/sdk-integrity.json`
4. Published with npm provenance (TypeScript) and PyPI Trusted Publishing (Python), anchored in sigstore's public transparency log

See `SECURITY.md` for downstream-verification commands and the disclosure mailbox.

---

## Visibility flip

This repository is private today. The visibility flip (private → public on GitHub, plus `npm publish @setix/thread` and `twine upload setix-thread`) is an operator-manual action with **no scheduled trigger** — it happens at the operator's choosing. Apply public-clean discipline continuously; there is no advance warning. The `if: github.event.repository.visibility == 'public'` gates on the publish workflows in `.github/workflows/` are defense-in-depth only.

---

## Drift check (run at session start)

```bash
echo "=== repo + branch ===" && git remote -v && git branch --show-current
echo "=== HEAD signed? (G = good signature) ===" && git log --format="%G? %h %s" -1
echo "=== latest tag ===" && git describe --tags --abbrev=0 2>/dev/null || echo "(no tags yet)"
echo "=== expected tag format ===" && echo "bare SemVer: v0.0.X / v0.1.X / v1.0.0 (no prefix; no suffixes)"
echo "=== sync with origin ===" && git fetch origin --tags 2>&1 | tail -2 && git status -sb
echo "=== machine ===" && hostname

echo "=== pre-commit hook present + executable? ==="
ls -la .githooks/pre-commit 2>&1 | head -1
ls -la .git/hooks/pre-commit 2>&1 | head -1

echo "=== self-scan via the actual hook (dry-run; HEAD as if just staged) ==="
# Run the same vocabulary pattern that the hook itself enforces.
# This sources the pattern from the hook so the check stays in sync.
PATTERN=$(grep '^FORBIDDEN_VOCAB=' .githooks/pre-commit | head -1 | sed -E "s/^[^']*'([^']+)'.*/\\1/")
[ -z "$PATTERN" ] && echo "(could not source pattern from hook; read .githooks/pre-commit manually)" || \
  git log --format="%s%n%b" -3 | grep -iE "$PATTERN" | head -5 && echo "WARNING: forbidden vocabulary in recent commit messages — review" || echo "OK"
```

Expected outcome:
- `%G?` = `G` (HEAD has a good signature)
- Latest tag matches bare SemVer
- Working tree clean; branch up-to-date with `origin/main`
- Pre-commit hook present at `.githooks/pre-commit`
- Self-scan via hook-sourced pattern = OK

---

*Operating context for sessions in this repo. Apply continuously.*
