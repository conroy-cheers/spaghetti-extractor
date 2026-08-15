# spaghetti-extractor-python-role: diagnostic
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  namePrefix,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "diagnostic";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.interpreter" ];
    name = "${namePrefix}-fallback-capability-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
in
pkgs.runCommand "${namePrefix}-fallback-capability-analysis-v1" (
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
  export PYTHONPATH=${phasePythonSource}/src

  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${machineIr}/machine-ir.jsonl \
    "$out/fallback-capability-analysis.json" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.interpreter import (
      write_fallback_capability_analysis,
  )

  write_fallback_capability_analysis(
      machine_ir=pathlib.Path(sys.argv[1]),
      out=pathlib.Path(sys.argv[2]),
  )
  PY

  jq -e '
    .format == "spaghetti-extractor-fallback-capability-analysis-v1" and
    (.status == "complete" or .status == "incomplete") and
    .counts.required_units > 0 and
    .counts.lowerable_units <= .counts.required_units and
    (.trust.proof_authority | not) and
    (.trust.candidate_executable | not) and
    (.trust.emits_source | not) and
    (.trust.emits_machine_code | not)
  ' "$out/fallback-capability-analysis.json" >/dev/null

  test "$(find "$out" -type f | wc -l)" -eq 1
''
