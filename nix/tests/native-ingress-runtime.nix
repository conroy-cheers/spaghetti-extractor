# spaghetti-extractor-python-role: candidate
{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
in
pkgs.runCommand "spaghetti-extractor-native-ingress-runtime-check" {
  nativeBuildInputs = [
    context.pythonEnv
    compiler
    pkgs.wineWow64Packages.stableFull
    pkgs.xvfb-run
  ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONPATH=${context.sources.fullSource}/src:${context.sources.fullSource}
  mkdir generated
  python ${./fixtures/native-ingress-runtime/generate.py} generated
  cp ${./fixtures/native-ingress-runtime/harness.c} generated/harness.c
  ${compiler}/bin/i686-w64-mingw32-gcc -O2 -Wall -Wextra -Werror \
    generated/native-ingress-runtime.c \
    generated/native-ingress-runtime.s \
    generated/harness.c \
    -Igenerated -o native-ingress-runtime.exe
  export WINEPREFIX="$TMPDIR/wine-prefix"
  export WINEDEBUG=-all
  export WINEDLLOVERRIDES="mscoree,mshtml="
  xvfb-run -a wineboot -u >/dev/null 2>&1
  timeout 90 xvfb-run -a wine ./native-ingress-runtime.exe >runtime.log 2>&1 || {
    status=$?
    cat runtime.log >&2
    exit "$status"
  }
  wineserver -w >/dev/null 2>&1 || true
  grep -F 'native ingress runtime acceptance: pass' runtime.log
  mkdir -p "$out"
  cp runtime.log "$out/"
''
