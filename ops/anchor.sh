#!/usr/bin/env bash
# ops/anchor.sh — CANONICAL session-start anchor. BYTE-IDENTICAL across all Setix repos.
# Source of truth: setix-ai/setix:ops/anchor.sh — replicated via ops/scripts/sync-org-sync.sh.
# Contract: ops/ORG-SYNC.md (ADR-2026-0268). Pairs with ops/handover.sh (session end).
#
# WHY: a fresh session anchors on FACTS via ONE read-only sequential call — not a pile of
# parallel git/exploration calls. Kills cascade-cancel (one bad parallel call nukes the batch)
# and confabulation (guessing state, chasing phantom bugs). The single living truth is
# ops/WHERE-WE-STAND.md; this script just points you at it + the latest handover + MEMORY.
#
# READ-ONLY — mutates nothing. Usage:  bash ops/anchor.sh [--brief]
# Ritual: run this -> read WHERE-WE-STAND -> read the latest handover -> read MEMORY ->
# await the directive. Do NOT "fix" anything it reports healthy.

set +e
REPO="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "anchor: not inside a git repo"; exit 1; }
cd "$REPO" || exit 1
BRIEF=0; [ "${1:-}" = "--brief" ] && BRIEF=1
BR="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
PROJ="$HOME/.claude/projects/$(printf '%s' "$REPO" | sed 's#/#-#g')/memory"
hr(){ printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

# 1. FETCH FIRST — never trust a stale local origin ref (the 2026-06-04 stale-clone bug).
git fetch origin "$BR" -q 2>/dev/null

hr "repo"
echo "path:   $REPO"
echo "branch: $BR"
LOCAL="$(git rev-parse --short HEAD 2>/dev/null)"
ORIGIN="$(git rev-parse --short "origin/$BR" 2>/dev/null || echo '?')"
read -r AHEAD BEHIND <<<"$(git rev-list --left-right --count "HEAD...origin/$BR" 2>/dev/null | tr '\t' ' ')"
echo "HEAD:   $LOCAL    origin/$BR: $ORIGIN    (ahead ${AHEAD:-?} / behind ${BEHIND:-?})"
if [ "${BEHIND:-0}" -gt 0 ] 2>/dev/null; then
  printf '\033[1;33mWARN: %s commit(s) BEHIND origin — run: git pull --ff-only origin %s  BEFORE acting.\033[0m\n' "$BEHIND" "$BR"
fi
echo "tag:    $(git describe --tags --abbrev=0 2>/dev/null || echo none)"

hr "uncommitted (clean = nothing below)"
git status --short 2>/dev/null

hr "recent commits"
git log --oneline -6 2>/dev/null

hr "WHERE-WE-STAND — the single current-state truth (READ THIS)"
if [ -f ops/WHERE-WE-STAND.md ]; then
  grep -iE '^\*\*As.?of|^_As.?of|^# ' ops/WHERE-WE-STAND.md 2>/dev/null | head -2
  echo "  → ops/WHERE-WE-STAND.md"
else
  echo "  WARN: ops/WHERE-WE-STAND.md missing (per ORG-SYNC.md every repo has one)."
fi

hr "latest handover (READ NEXT — deltas only, NOT the source of truth)"
HODIR="$(ls -d ops/*handover*/ 2>/dev/null | grep -v '/archive' | head -1)"
if [ -n "$HODIR" ]; then
  ls -1t "$HODIR"*.md 2>/dev/null | grep -vi 'template' | head -1 || echo "  (none yet)"
else
  echo "  (no handover dir yet)"
fi

if [ "$BRIEF" = "0" ]; then  # MEMORY index + memory-health: skipped in --brief (the hook
                             # auto-inject) since the harness already loads MEMORY.md.
hr "MEMORY index"
MEMFILE=""; for m in MEMORY.md memory/MEMORY.md; do [ -f "$m" ] && { MEMFILE="$m"; break; }; done
if [ -n "$MEMFILE" ]; then grep -E '^- ' "$MEMFILE" 2>/dev/null | head -40 || echo "  (no entries)"; else echo "  (no MEMORY.md)"; fi

hr "memory persistence health"
if [ -L "$REPO/memory" ]; then echo "WARN: in-repo memory/ is a SYMLINK (should be a real dir)"
elif [ -d "$REPO/memory" ]; then echo "ok:   memory/ real dir, $(ls -1 "$REPO"/memory/*.md 2>/dev/null | wc -l | tr -d ' ') files, tracked=$(git ls-files memory MEMORY.md 2>/dev/null | wc -l | tr -d ' ')"
else echo "(no in-repo memory/ — repo may not use the memory store)"; fi
if [ -L "$PROJ" ]; then
  [ "$(readlink "$PROJ")" = "$REPO/memory" ] && echo "ok:   projects memory → $REPO/memory" || echo "WARN: projects memory → $(readlink "$PROJ") (expected $REPO/memory)"
elif [ -e "$PROJ" ]; then echo "WARN: projects memory is NOT a symlink — run the one-time ln from CLAUDE.md"
fi
fi  # end non-brief (MEMORY index + memory-health)

hr "cross-cut seam — open items"
for lane in ops/cross-cuts/incoming-from-* ops/cross-cuts-from-* ops/cross-cuts/outgoing-to-*; do
  [ -d "$lane" ] || continue
  n="$(ls -1 "$lane"/*.md 2>/dev/null | grep -viE 'README|gitkeep' | wc -l | tr -d ' ')"
  echo "  $(basename "$(dirname "$lane")")/$(basename "$lane"): $n"
done

if [ "$BRIEF" = "0" ]; then
  hr "north-star + doc freshness"
  grep -iE '^North:|Reconciled-against-LAUNCH:' OBJECTIVE.md 2>/dev/null | head -2 || echo "  (no North: header in OBJECTIVE.md)"
  for d in CHARTER.md LAUNCH.md MECHANICS.md OBJECTIVE.md ops/ORG-SYNC.md ops/WHERE-WE-STAND.md; do
    [ -f "$d" ] || continue
    stamp="$(grep -oE 'reconciled: [a-f0-9]{7,}' "$d" 2>/dev/null | head -1 | awk '{print $2}')"
    if [ -n "$stamp" ]; then
      behind="$(git rev-list --count "${stamp}..HEAD" 2>/dev/null || echo '?')"
      flag=""; [ "${behind:-0}" -gt 25 ] 2>/dev/null && flag=" \033[1;33m← STALE? re-reconcile\033[0m"
      printf '  %-26s stamp %s (%s commits behind)%b\n' "$d" "$stamp" "$behind" "$flag"
    fi
  done
fi

# optional per-repo extras (repo-specific facts; never fork the core for these)
if [ -f ops/anchor.local.sh ]; then hr "repo-specific"; bash ops/anchor.local.sh 2>/dev/null; fi

printf '\n\033[1manchored.\033[0m  Next: read ops/WHERE-WE-STAND.md + the latest handover, then await the directive.\n'
printf 'Trust this output — do NOT "fix" anything it reports as ok/clean.\n'
