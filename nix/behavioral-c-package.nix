# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  namePrefix,
  layoutIntent ? null,
  runtimeQualification ? null,
  compiler ? pkgs.stdenv.cc,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.behavioral_c" ];
    name = "${namePrefix}-behavioral-c-python-closure";
  };
  layoutArgument = if layoutIntent == null then "-" else toString layoutIntent;
  runtimeArgument =
    if runtimeQualification == null then "-" else toString runtimeQualification;
in
pkgs.runCommand
  "${namePrefix}-behavioral-c-v1"
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils compiler ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phasePythonSource}/src
    ${pythonEnv}/bin/python3 - \
      ${machineIr}/machine-ir.jsonl "$out" \
      ${pkgs.lib.escapeShellArg layoutArgument} \
      ${pkgs.lib.escapeShellArg runtimeArgument} <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.behavioral_c import (
        write_spx_behavioral_c_package,
    )

    machine_ir = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    layout = None if sys.argv[3] == "-" else pathlib.Path(sys.argv[3])
    runtime = None if sys.argv[4] == "-" else pathlib.Path(sys.argv[4])
    write_spx_behavioral_c_package(
        machine_ir=machine_ir,
        out=output,
        layout_intent=layout,
        runtime_qualification=runtime,
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-package-v1" and
      .status == "ready" and
      .input_mode == "sanitized_machine_ir_v3" and
      .representation == "direct_structured_behavioral_c_v1" and
      .counts.required_units > 0 and
      .counts.required_units == .counts.lowered_units and
      .counts.required_units == .counts.owned_units and
      (.constraints.original_instruction_bytes_embedded | not) and
      (.constraints.runtime_instruction_decoder | not) and
      (.constraints.semantic_opcode_tables | not) and
      (.constraints.per_transfer_pc_interpreter_loop | not)
    ' "$out/behavioral-c-package.json" >/dev/null
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-coverage-v1" and
      .status == "complete" and .counts.blockers == 0
    ' "$out/behavioral-c-coverage.json" >/dev/null
    ${compiler}/bin/${compiler.targetPrefix}cc \
      -std=c11 -Wall -Wextra -Werror -I "$out" \
      -c "$out/behavioral-c.c" -o "$out/behavioral-c.o"
  ''
