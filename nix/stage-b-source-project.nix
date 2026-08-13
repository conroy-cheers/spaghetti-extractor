{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  machineIr,
  specification,
  sourceRoot,
  linkedIslands ? null,
}:

assert builtins.isString namePrefix && namePrefix != "";

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.source_project" ];
    name = "${namePrefix}-source-project-python-closure";
  };
  linkedIslandsArg =
    if linkedIslands == null then
      "-"
    else
      lib.escapeShellArg (toString linkedIslands);
in
pkgs.runCommand "${namePrefix}-source-project-binding-v1"
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export PYTHONPATH=${phasePythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg (toString machineIr)} \
      ${lib.escapeShellArg (toString specification)} \
      ${lib.escapeShellArg (toString sourceRoot)} \
      ${linkedIslandsArg} \
      "$out/source-project-binding.json" <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.source_project import bind_source_project

    machine_ir, specification, source_root, linked_islands, output = sys.argv[1:]
    bind_source_project(
        machine_ir=pathlib.Path(machine_ir),
        specification=pathlib.Path(specification),
        source_root=pathlib.Path(source_root),
        linked_islands=(
            None if linked_islands == "-" else pathlib.Path(linked_islands)
        ),
        out=pathlib.Path(output),
    )
    PY
    specification_sha256="$(${pkgs.jq}/bin/jq -r \
      .specification_sha256 ${lib.escapeShellArg (toString specification)})"
    ${pkgs.jq}/bin/jq -e \
      --arg specification_sha256 "$specification_sha256" '
      .format == "stage-b-source-project-binding-v1" and
      .status == "bound" and .equivalence_status == "not_proven" and
      (.executes_original_binary | not) and
      .bindings.specification_sha256 == $specification_sha256 and
      (.sources | length) > 0 and (.islands | length) > 0 and
      .coverage.reviewed_scope.fully_source_bound and
      .coverage.reviewed_scope.remaining_machine_units == 0 and
      (.authority.proves_source_semantics | not) and
      (.authority.can_authorize_machine_override | not)
    ' "$out/source-project-binding.json" >/dev/null
  ''
