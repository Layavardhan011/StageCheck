#!/bin/sh
# The owner invokes this entry point; it never invokes the generator.
set -eu
export PYTHONDONTWRITEBYTECODE=1
stagecheck_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 "$stagecheck_dir/bin/orchestrate.py" "$@"
