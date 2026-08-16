# spaghetti-extractor-python-role: operator
{
  pkgs,
  pythonEnv,
  pythonSource,
  targetId,
  namePrefix,
  releaseHypotheses,
  catalogSearchIndex ? null,
  adoptionIntents ? { },
  checkedIslands ? { },
  generatedComponents ? { },
  implementations ? { },
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.library_status_v4" ];
    name = "${namePrefix}-library-status-python-closure";
  };
  receiptPaths = lib.mapAttrs
    (_: value: if value == null then null else "${value}/checked-library-island.json")
    checkedIslands;
  nonNullReceiptPaths = lib.filterAttrs (_: value: value != null) receiptPaths;
  status = pkgs.runCommand "${namePrefix}-library-status-v4" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${phasePythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg targetId} \
      ${releaseHypotheses} \
      ${lib.escapeShellArg (if catalogSearchIndex == null then "" else "${catalogSearchIndex}/catalog-search-index.json")} \
      ${lib.escapeShellArg (builtins.toJSON adoptionIntents)} \
      ${lib.escapeShellArg (builtins.toJSON nonNullReceiptPaths)} \
      ${lib.escapeShellArg (builtins.toJSON generatedComponents)} \
      ${lib.escapeShellArg (builtins.toJSON implementations)} \
      "$out/library-status.json" <<'PY'
    import json
    import pathlib
    import sys
    from spaghetti_extractor.target_bundles.library_status_v4 import build_library_status_v4

    build_library_status_v4(
        target_id=sys.argv[1],
        release_hypotheses=pathlib.Path(sys.argv[2]),
        catalog_search_index=(pathlib.Path(sys.argv[3]) if sys.argv[3] else None),
        adoption_intents=[pathlib.Path(value) for value in json.loads(sys.argv[4]).values()],
        checked_islands=[pathlib.Path(value) for value in json.loads(sys.argv[5]).values()],
        generated_components=[pathlib.Path(value) for value in json.loads(sys.argv[6]).values()],
        implementations=[pathlib.Path(value) for value in json.loads(sys.argv[7]).values()],
        out=pathlib.Path(sys.argv[8]),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-library-status-v4" and
      (.status == "ready" or .status == "incomplete" or .status == "violated") and
      (.authorizing | not) and
      (.executes_original_binary | not) and
      .policy.unselected_units_remain_machine_ir and
      (.policy.identity_match_authorizes_replacement | not) and
      (.policy.operator_adoption_authorizes_replacement | not) and
      .policy.checked_island_receipt_required and
      (.policy.handwritten_behavior_tests_required | not)
    ' "$out/library-status.json" >/dev/null
  '';
  check = pkgs.runCommand "${namePrefix}-library-check-v4" {
    nativeBuildInputs = [ pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    jq -e '
      .status == "ready" and
      .counts.adoption_intents > 0 and
      .counts.adoption_intents == .counts.ready_adoptions
    ' ${status}/library-status.json >/dev/null
    mkdir -p "$out"
    ln -s ${status}/library-status.json "$out/library-status.json"
  '';
in
{
  inherit status check;
}
