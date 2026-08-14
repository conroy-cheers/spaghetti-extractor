{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  requirements,
  selectionAuthority,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.isa_frontier_report_v1" ];
    name = "${name}-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
in
pkgs.runCommand name (
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  // caAttrs
) ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${pythonClosure}/src

  mkdir -p "$out"
  ${pythonEnv}/bin/python3 -m spaghetti_extractor.isa_frontier_report_v1 \
    --requirements ${requirements} \
    --selection-authority ${selectionAuthority} \
    --out "$out/isa-frontiers-v1.json"

  jq -e '
    .format == "spaghetti-extractor-isa-frontier-report-v1" and
    (.status == "qualified" or .status == "incomplete" or .status == "violated") and
    .trust.diagnostic_only == true and
    .trust.changes_isa_selection == false and
    .trust.authorizes_candidate_generation == false and
    .counts.frontier_forms == (.frontiers | length)
  ' "$out/isa-frontiers-v1.json" >/dev/null
''
