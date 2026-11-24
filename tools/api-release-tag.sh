#!/usr/bin/env bash
set -euo pipefail

latest=$(git for-each-ref --count=1 --sort=-version:refname \
  --format='%(refname:strip=2)' 'refs/tags/api/v*')
if [[ -z "$latest" ]]; then
  printf '%s\n' 'api/v0.3.0'
  exit 0
fi

if [[ ! "$latest" =~ ^api/v0\.([0-9]+)\.([0-9]+)$ ]]; then
  printf 'Unsupported API release tag: %s\n' "$latest" >&2
  exit 1
fi
minor=${BASH_REMATCH[1]}

if git merge-base --is-ancestor HEAD "$latest"; then
  exit 0
fi
if ! git merge-base --is-ancestor "$latest" HEAD; then
  printf 'Latest API release %s is not on the current history\n' "$latest" >&2
  exit 1
fi

if git diff --quiet "$latest" HEAD -- api/ proto/v0s/; then
  exit 0
else
  status=$?
  if [[ "$status" -ne 1 ]]; then
    exit "$status"
  fi
fi

printf 'api/v0.%d.0\n' "$((10#$minor + 1))"
