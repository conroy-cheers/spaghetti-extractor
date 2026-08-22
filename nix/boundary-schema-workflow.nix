# spaghetti-extractor-python-role: expert
{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  spec,
  sources ? [ ],
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

pkgs.runCommand "${name}-checked-boundaries" {
  nativeBuildInputs = [ pythonEnv compiler ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH=${pythonSource}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 -m spaghetti_extractor expert boundary-check \
    --spec ${pkgs.lib.escapeShellArg "${spec}"} \
    --out "$out"
  ${pkgs.lib.concatMapStringsSep "\n" (source: ''
    ${compiler}/bin/i686-w64-mingw32-gcc \
      -std=c11 -Wall -Wextra -Werror -I"$out" \
      -c ${pkgs.lib.escapeShellArg "${source}"} \
      -o "$out/${baseNameOf source}.o"
  '') sources}
''
