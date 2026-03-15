#!/usr/bin/env bash
set -euo pipefail

# Optimized release build with optional compiler+linker caches.
# Usage:
#   ./scripts/build_optimized.sh
#   PROFILE=dev ./scripts/build_optimized.sh

PROFILE="${PROFILE:-release}"
CARGO_CMD=(cargo build)
if [[ "$PROFILE" == "release" ]]; then
  CARGO_CMD+=(--release)
fi

# Prefer sccache when available for rustc output caching.
if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
  echo "[build] sccache detected: compiler cache enabled"
else
  echo "[build] sccache not found: building without compiler cache"
fi

# Use faster linkers on Linux when present.
EXTRA_RUSTFLAGS="${RUSTFLAGS:-}"
if [[ "$(uname -s)" == "Linux" ]]; then
  if command -v mold >/dev/null 2>&1; then
    EXTRA_RUSTFLAGS+=" -C link-arg=-fuse-ld=mold"
    echo "[build] mold detected: using mold linker"
  elif command -v ld.lld >/dev/null 2>&1; then
    EXTRA_RUSTFLAGS+=" -C link-arg=-fuse-ld=lld"
    echo "[build] lld detected: using lld linker"
  else
    echo "[build] mold/lld not found: using system linker"
  fi
fi
export RUSTFLAGS="$EXTRA_RUSTFLAGS"

# Keep debug builds iterative; release remains fully optimized via Cargo profile.
if [[ "$PROFILE" == "dev" ]]; then
  export CARGO_INCREMENTAL=1
fi

# Utilize all host CPUs for faster compile throughput.
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)}"

echo "[build] profile=$PROFILE jobs=$JOBS"
"${CARGO_CMD[@]}" --jobs "$JOBS"

if [[ -n "${RUSTC_WRAPPER:-}" ]] && command -v sccache >/dev/null 2>&1; then
  echo
  sccache --show-stats || true
fi
