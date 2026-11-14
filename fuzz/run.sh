#!/usr/bin/env bash
# Runs every fuzz target for the given number of seconds (default 60), starting from the seeds.
# FUZZ_TOOLCHAIN selects the nightly toolchain (default: nightly).
set -euo pipefail
cd "$(dirname "$0")"
seconds="${1:-60}"
toolchain="${FUZZ_TOOLCHAIN:-nightly}"
for target in head request response frame url framer; do
    mkdir -p "corpus/$target"
    cargo "+$toolchain" fuzz run "$target" "corpus/$target" "seeds/$target" -- \
        -max_total_time="$seconds" -dict=http.dict
done
