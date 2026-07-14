#!/bin/sh
# Rewrite blob contents across all local branches/tags to redact production data.
# Preserves commit messages, authors, dates, and history topology (SHAs change).
set -e
cd "$(dirname "$0")/.."

if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "Install: pip install git-filter-repo" >&2
    exit 1
fi

ORIGIN_URL="${ORIGIN_URL:-http://172.16.7.42/DefaultCollection/IWF/_git/IWF}"
PRETTY_URL="${PRETTY_URL:-https://github.com/arayeji/PrettyIWF.git}"

echo "Rewriting history with tools/sanitize-production-replacements.txt ..."
git filter-repo --force \
    --replace-text tools/sanitize-production-replacements.txt

echo "Re-adding remotes (filter-repo removes them) ..."
git remote add origin "$ORIGIN_URL" 2>/dev/null || git remote set-url origin "$ORIGIN_URL"
git remote add pretty "$PRETTY_URL" 2>/dev/null || git remote set-url pretty "$PRETTY_URL"

echo "Verify — should print nothing:"
git grep -E '10\.234\.241|iwfsms|989350020001|989110020001|THR1EPC|THR1MSC|superadmin' \
    $(git rev-list --all) 2>/dev/null && exit 1 || true

echo "Done. Force-push when ready:"
echo "  git push origin --force --all"
echo "  git push pretty --force --all"
echo "  git push origin --force --tags   # if any"
echo "  git push pretty --force --tags"
