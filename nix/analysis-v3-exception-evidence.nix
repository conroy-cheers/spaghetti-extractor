{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  semanticIndex,
  launchProfile,
  name,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_a_exception_evidence_v3" ];
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
  export PYTHONPATH=${phasePythonSource}/src

  ${pythonEnv}/bin/python3 -m \
    spaghetti_extractor.stage_a_exception_evidence_v3 \
    --machine-ir ${lib.escapeShellArg (toString machineIr)} \
    --semantic-index ${lib.escapeShellArg (toString semanticIndex)} \
    --launch-profile ${lib.escapeShellArg (toString launchProfile)} \
    --out "$out"

  jq -e '
    .format == "spaghetti-extractor-exception-evidence-report-v3" and
    (.status == "complete" or .status == "incomplete" or .status == "violated") and
    .authorizing == false and
    (.record_ids | type == "array") and
    (.counts.faults | type == "number") and
    (.records | type == "array")
  ' "$out/metadata.json" >/dev/null
''
