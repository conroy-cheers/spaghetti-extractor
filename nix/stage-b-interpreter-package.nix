{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  namePrefix,
}:

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
    export PYTHONPATH=${pythonSource}/src
    ${pythonEnv}/bin/python3 - \
      ${machineIr}/machine-ir.jsonl "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_interpreter_backend import (
        write_stage_b_interpreter_package,
    )

    machine_ir, output = map(pathlib.Path, sys.argv[1:])
    write_stage_b_interpreter_package(machine_ir=machine_ir, out=output)
    PY
    jq -e '
      .format == "stage-b-semantic-interpreter-package-v1" and
      .status == "ready" and
      .input_mode == "sanitized_machine_ir_v2" and
      .counts.input_transfers > 0 and
      .counts.transfers == .counts.input_transfers and
      .counts.blocked_transfers == 0
    ' "$out/state-machine-interpreter-package.json" >/dev/null
  ''
