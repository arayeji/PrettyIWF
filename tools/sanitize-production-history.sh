#!/bin/sh
# Rewrite blob contents AND commit messages across all local branches/tags to
# redact production deployment data. Commit authors, dates and history topology
# are preserved; every SHA changes.
#
# Remote URLs come from the environment - they are deliberately not defaults
# here, so an internal git host does not end up committed to this repo:
#   ORIGIN_URL=... PRETTY_URL=... tools/sanitize-production-history.sh
#
# NOTE: filter-repo also rewrites the literals inside the rules file itself as
# it walks history, so old revisions of tools/sanitize-production-*.txt will
# show already-redacted values. That is cosmetic. The verification below uses
# patterns held in this script, not in the rules file, so it stays meaningful.
set -e
cd "$(dirname "$0")/.."

if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "Install: pip install git-filter-repo" >&2
    exit 1
fi

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Working tree has uncommitted changes; commit or stash them first." >&2
    exit 1
fi

echo "Backing up all refs to ../IWF-backup-$(date +%Y%m%d-%H%M%S).bundle ..."
git bundle create "../IWF-backup-$(date +%Y%m%d-%H%M%S).bundle" --all >/dev/null

RULES=tools/sanitize-production-replacements.txt

echo "Rewriting history with $RULES ..."
# --replace-text covers file contents, --replace-message covers commit
# messages. Both are needed: operator and site names appear in both.
git filter-repo --force \
    --replace-text    "$RULES" \
    --replace-message "$RULES"

echo "Re-adding remotes (filter-repo removes them) ..."
if [ -n "$ORIGIN_URL" ]; then
    git remote add origin "$ORIGIN_URL" 2>/dev/null || \
        git remote set-url origin "$ORIGIN_URL"
else
    echo "  ORIGIN_URL unset - skipping 'origin'"
fi
if [ -n "$PRETTY_URL" ]; then
    git remote add pretty "$PRETTY_URL" 2>/dev/null || \
        git remote set-url pretty "$PRETTY_URL"
else
    echo "  PRETTY_URL unset - skipping 'pretty'"
fi

echo "Verifying ..."
PAT='10\.234\.241|172\.16\.7\.42|THR[0-9]|Irancell|HiWEB|mcinet|iwfsms|superadmin|mcc432|mnc0(11|12|20|35)'
git rev-list --all > .git/sanitize-revs.tmp
if xargs git grep -lIE "$PAT" < .git/sanitize-revs.tmp 2>/dev/null | head -1 | grep -q .; then
    rm -f .git/sanitize-revs.tmp
    echo "STILL PRESENT in blobs - add the literals to $RULES and re-run" >&2
    exit 1
fi
rm -f .git/sanitize-revs.tmp
if git log --all --format='%B' | grep -qIE "$PAT"; then
    echo "STILL PRESENT in commit messages - add the literals and re-run" >&2
    exit 1
fi
echo "Clean."

cat <<'EOF'

Done locally. The remotes still hold the old objects until you force-push:
  git push origin --force --all
  git push pretty --force --all
  git push origin --force --tags
  git push pretty --force --tags

A force-push does NOT erase what was already published. On a forge the old
commits stay reachable by SHA until it garbage-collects, and forks, clones,
caches and search indexes keep their own copies. Treat anything that was ever
pushed as disclosed, and rotate the credentials it exposed.
EOF
