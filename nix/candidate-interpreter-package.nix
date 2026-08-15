# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  capabilityAnalysis,
  finalAuthorityGate,
  namePrefix,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.interpreter" ];
    name = "${namePrefix}-interpreter-package-python-closure";
  };
in
pkgs.runCommand
  "${namePrefix}-machine-ir-interpreter-v1"
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phasePythonSource}/src
    jq -e '
      .format == "spaghetti-extractor-final-authority-gate-v3" and
      .status == "complete" and
      .authorizing
    ' ${finalAuthorityGate}/authority-gate.json >/dev/null
    jq -e --arg machineIrSha256 \
      "$(sha256sum ${machineIr}/machine-ir.jsonl | cut -d' ' -f1)" '
      .format == "spaghetti-extractor-fallback-capability-analysis-v1" and
      .status == "complete" and
      .machine_ir.sha256 == $machineIrSha256 and
      .counts.required_units == .counts.lowerable_units and
      .counts.blockers == 0
    ' ${capabilityAnalysis}/fallback-capability-analysis.json >/dev/null
    ${pythonEnv}/bin/python3 - \
      ${machineIr}/machine-ir.jsonl "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.interpreter import (
        write_spx_interpreter_package,
    )

    machine_ir, output = map(pathlib.Path, sys.argv[1:])
    write_spx_interpreter_package(
        machine_ir=machine_ir,
        out=output,
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-semantic-interpreter-package-v1" and
      .status == "ready" and
      .input_mode == "sanitized_machine_ir_v2" and
      .counts.input_transfers > 0 and
      .counts.transfers == .counts.input_transfers and
      .counts.blocked_transfers == 0 and
      .execution_policy == "complete_transfer_inventory_v1" and
      .semantic_coverage.status == "complete"
    ' "$out/state-machine-interpreter-package.json" >/dev/null
    test "$(jq -r .lowering.program_source_sha256 \
      ${capabilityAnalysis}/fallback-capability-analysis.json)" = \
      "$(sha256sum "$out/state-machine-program.c" | cut -d' ' -f1)"
    test "$(jq -r .lowering.interpreter_source_sha256 \
      ${capabilityAnalysis}/fallback-capability-analysis.json)" = \
      "$(sha256sum "$out/state-machine-interpreter.c" | cut -d' ' -f1)"
    test "$(jq -r .lowering.runtime_header_sha256 \
      ${capabilityAnalysis}/fallback-capability-analysis.json)" = \
      "$(sha256sum "$out/state-machine-runtime.h" | cut -d' ' -f1)"
    test "$(jq -r .lowering.interpreter_header_sha256 \
      ${capabilityAnalysis}/fallback-capability-analysis.json)" = \
      "$(sha256sum "$out/state-machine-interpreter.h" | cut -d' ' -f1)"
    test "$(jq -r .lowering.interpreter_internal_header_sha256 \
      ${capabilityAnalysis}/fallback-capability-analysis.json)" = \
      "$(sha256sum "$out/state-machine-interpreter-internal.h" | cut -d' ' -f1)"
  ''
