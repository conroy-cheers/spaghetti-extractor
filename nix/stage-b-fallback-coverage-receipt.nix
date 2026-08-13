{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  interpreterPackage,
  namePrefix,
  portableReplacements ? null,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_fallback_coverage" ];
    name = "${namePrefix}-fallback-coverage-receipt-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  portableReplacementArg =
    if portableReplacements == null then "" else toString portableReplacements;
in
pkgs.runCommand "${namePrefix}-fallback-coverage-receipt-v3" (
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
    ${machineIr}/machine-ir-manifest.json \
    ${interpreterPackage} \
    ${lib.escapeShellArg portableReplacementArg} \
    "$out/fallback-coverage-receipt.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.stage_b_fallback_coverage import (
      write_stage_b_fallback_coverage_receipt,
  )

  machine_ir, manifest, interpreter, portable, output = sys.argv[1:]
  write_stage_b_fallback_coverage_receipt(
      machine_ir=pathlib.Path(machine_ir),
      machine_ir_manifest=pathlib.Path(manifest),
      interpreter_package=pathlib.Path(interpreter),
      portable_replacements=(pathlib.Path(portable) if portable else None),
      out=pathlib.Path(output),
  )
  PY

  jq -e '
    .format == "stage-b-fallback-coverage-receipt-v3" and
    .status == "complete" and
    (.authority | contains("implementation availability only")) and
    .policy.structural_units_require_lowering and
    .policy.one_implementation_kind_per_structural_unit and
    (.policy.rooted_containment_authority | not) and
    .counts.structural_units == .counts.implementation_entries and
    .counts.blockers == 0
  ' "$out/fallback-coverage-receipt.json" >/dev/null
''
