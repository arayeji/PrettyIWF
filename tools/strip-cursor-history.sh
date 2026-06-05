#!/bin/sh
cd "$(dirname "$0")/.."
export FILTER_BRANCH_SQUELCH_WARNING=1
git filter-branch -f --msg-filter "grep -v '^Co-authored-by: Cursor' | grep -v '^Co-authored-by: cursoragent' || true" master
git for-each-ref --format='delete %(refname)' refs/original | git update-ref --stdin
git reflog expire --expire=now --all
git gc --prune=now --aggressive
