#!/usr/bin/env bash
# Report new upstream (cyverse/ds-collection) commits touching the paths
# listed in scripts/upstream-watched-paths.txt.
#
# This repo has diverged too far from upstream (pinned iRODS 4.3.3, Ubuntu 24
# support, rewritten testing infra) for a wholesale merge/rebase to be safe.
# Instead, periodically run this script to see what changed upstream in the
# files that matter, then port relevant hunks by hand, adapting them to this
# fork's conventions (e.g. `on (errorcode(...) == 0)` -> `if (cyverse_hasKey(...))`).
#
# Usage: scripts/check-upstream.sh [base-ref]
#   base-ref defaults to the local main branch.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

base_ref="${1:-main}"
upstream_url="https://github.com/cyverse/ds-collection.git"

if ! git remote get-url upstream >/dev/null 2>&1; then
	git remote add upstream "$upstream_url"
fi

git fetch upstream --quiet

mapfile -t watched_paths < <(grep -v '^#' scripts/upstream-watched-paths.txt | grep -v '^\s*$')

for path in "${watched_paths[@]}"; do
	commits="$(git log "${base_ref}..upstream/main" --oneline -- "$path")"
	if [[ -z "$commits" ]]; then
		continue
	fi
	echo "== $path =="
	echo "$commits"
	echo
	echo "  diff: git diff ${base_ref} upstream/main -- $path"
	echo
done
