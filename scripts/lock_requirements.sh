#!/usr/bin/env bash
# Regenerate hash-pinned lock files for CI (pip install --require-hashes -r <file>.lock).
set -euo pipefail
cd "$(dirname "$0")/.."
for name in requirements-dev requirements-scan; do
  uv pip compile "$name.txt" --generate-hashes --python-version 3.13 --python-platform x86_64-unknown-linux-gnu \
    --no-header --quiet -o "$name.lock"
done
echo "lock files updated"
