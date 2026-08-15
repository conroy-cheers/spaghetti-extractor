# spaghetti-extractor-python-role: diagnostic
{
  pkgs,
  pythonEnv,
  authorityDiagnostics,
  namePrefix,
}:

let
  python = "${pythonEnv}/bin/python3";
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "diagnostic";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.runtime_frontiers" ];
    name = "${namePrefix}-runtime-frontiers-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-runtime-frontier-report-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.findutils pkgs.gnugrep ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH=${phaseSource}/src
  mkdir -p "$out"
  ${python} - \
    ${authorityDiagnostics}/authority-diagnostics-v3.json \
    "$out/runtime-frontiers.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.target_bundles.runtime_frontiers import (
      build_runtime_frontier_report,
  )

  build_runtime_frontier_report(
      authority_diagnostics=pathlib.Path(sys.argv[1]),
      out=pathlib.Path(sys.argv[2]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-runtime-frontier-report-v1" and
    (.status == "complete" or .status == "incomplete" or .status == "violated") and
    (.authorizing | not) and
    .policy.diagnostic_only and
    (.policy.candidate_generated | not) and
    (.policy.source_generated | not) and
    (.policy.object_code_emitted | not) and
    (.policy.runtime_executed | not) and
    (.policy.original_binary_executed | not)
  ' "$out/runtime-frontiers.json" >/dev/null
  if find "$out" -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' \
      -o -name '*.o' -o -name '*.obj' -o -name '*.exe' \) -print -quit \
      | grep -q .; then
    echo "runtime frontier report emitted implementation material" >&2
    exit 1
  fi
''
