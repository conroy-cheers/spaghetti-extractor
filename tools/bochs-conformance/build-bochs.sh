#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_tree=${1:-${BOCHS_SOURCE:-/tmp/bochs-3.0-src}}
build_root=${2:-"$root/build"}
jobs=${NIX_BUILD_CORES:-$(nproc)}

if [[ ! -x "$source_tree/configure" ]]; then
  echo "Bochs source tree is missing configure: $source_tree" >&2
  exit 1
fi

rm -rf "$build_root/source"
mkdir -p "$build_root"
cp -a --reflink=auto "$source_tree" "$build_root/source"
plugin="$build_root/source/instrument/bochs-conformance"
mkdir -p "$plugin"
cp "$root/Makefile.in" "$root/instrument.h" "$root/instrument.cc" \
  "$root/protocol.h" "$plugin/"

"$root/build-guest.sh" "$build_root/guest" >/dev/null

cd "$build_root/source"
./configure \
  --enable-cpu-level=6 \
  --enable-x86-64 \
  --enable-fpu \
  --enable-avx \
  --enable-evex \
  --enable-configurable-msrs \
  --disable-smp \
  --disable-debugger \
  --disable-readline \
  --disable-repeat-speedups \
  --enable-instrumentation=instrument/bochs-conformance \
  --with-nogui
make -j"$jobs"

printf '%s\n' "$build_root/source/bochs"
