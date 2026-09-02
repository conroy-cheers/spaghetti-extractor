# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  semanticObject,
  namePrefix,
  layoutIntent ? null,
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
in
pkgs.runCommand
  "${namePrefix}-behavioral-c-v2"
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
    export PYTHONPATH=${phasePythonSource.pythonPath}
    ${pythonEnv}/bin/python3 - \
      ${semanticObject} "$out" \
      ${pkgs.lib.escapeShellArg layoutArgument} <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.behavioral_c import (
        write_spx_behavioral_c_package_from_semantic_object,
    )

    semantic_object = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    layout = None if sys.argv[3] == "-" else pathlib.Path(sys.argv[3])
    write_spx_behavioral_c_package_from_semantic_object(
        semantic_object=semantic_object,
        out=output,
        layout_intent=layout,
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-package-v2" and
      .status == "ready" and
      .input_mode == "semantic_object_v1" and
      .representation == "direct_structured_behavioral_c_v1" and
      .counts.required_units > 0 and
      .counts.required_units == .counts.lowered_units and
      .counts.required_units == .counts.owned_units and
      (.constraints.original_instruction_bytes_embedded | not) and
      (.constraints.runtime_instruction_decoder | not) and
      (.constraints.semantic_opcode_tables | not) and
      (.constraints.per_transfer_pc_dispatch_loop | not)
    ' "$out/behavioral-c-package.json" >/dev/null
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-coverage-v2" and
      .status == "complete" and .counts.blockers == 0 and
      .operation_coverage.format ==
        "spaghetti-extractor-transfer-operation-coverage-v2" and
      .operation_coverage.status == "complete" and
      (.operation_coverage.domain_ids | sort) == [
        "behavioral_c", "concrete_evaluator", "definedness",
        "reference_provenance", "z3_reconstruction"
      ]
    ' "$out/behavioral-c-coverage.json" >/dev/null
    while IFS= read -r source; do
      object="$out/$(basename "$source" .c).o"
      ${compiler}/bin/${compiler.targetPrefix}cc \
        -std=c11 -Wall -Wextra -Werror -I "$out" \
        -c "$source" -o "$object"
    done < <(find "$out" -maxdepth 1 -type f \
      \( -name 'behavioral-fn-*.c' -o -name 'behavioral-dispatch.c' \
         -o -name 'behavioral-support.c' \) | sort)
  ''
