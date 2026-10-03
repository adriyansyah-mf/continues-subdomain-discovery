#!/usr/bin/env bash
# Import arkadiyt/bounty-targets-data via the API (download, validate, normalize,
# deduplicate, record provenance, diff against the previous import).
set -euo pipefail
cd "$(dirname "$0")/.."
./bbctl bootstrap bounty-targets
