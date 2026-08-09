{
  pkgs,
  pythonEnv,
  pythonSource,
  nativeBuildPythonSource ? pythonSource,
  interpreterPackage,
  nativeEnginePackage,
  nativeRuntimePackage,
  compiler,
  namePrefix,
  regionOverridePackage ? null,
  entrySymbol ? "stage_b_payload_entry",
  diagnosticFailureTrap ? false,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = nativeBuildPythonSource;
    modules = [ "spaghetti_extractor.stage_b_interpreter_native_build" ];
    name = "${namePrefix}-native-object-python-closure";
  };
  graph = pkgs.runCommand "${namePrefix}-native-object-graph-v2" {
    nativeBuildInputs = [ pythonEnv compiler pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phasePythonSource}/src
    ${python} - \
      ${interpreterPackage} ${nativeEnginePackage} ${nativeRuntimePackage} \
      ${lib.escapeShellArg (if regionOverridePackage == null then "" else toString regionOverridePackage)} \
      ${compiler}/bin/i686-w64-mingw32-gcc \
      ${lib.escapeShellArg entrySymbol} \
      ${if diagnosticFailureTrap then "1" else "0"} "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        prepare_stage_b_interpreter_native_object_graph,
    )

    prepare_stage_b_interpreter_native_object_graph(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        native_runtime_package=pathlib.Path(sys.argv[3]),
        region_override_package=pathlib.Path(sys.argv[4]) if sys.argv[4] else None,
        compiler=pathlib.Path(sys.argv[5]),
        entry_symbol=sys.argv[6],
        diagnostic_failure_trap=sys.argv[7] == "1",
        out_dir=pathlib.Path(sys.argv[8]),
    )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-object-graph-v2" and
      .status == "ready" and (.executes_original_binary | not) and
      .counts.compile_units == (.units | length) and
      all(.units[];
        (.compile_key_sha256 | test("^[0-9a-f]{64}$")) and
        (.dependencies | type == "array") and
        (.root_mappings | type == "array"))
    ' "$out/native-object-graph.json" >/dev/null
  '';

  # The unit inventory is produced by static analysis, so reading it during
  # evaluation would be IFD.  That is not compatible with CA inputs:
  # their output paths are deliberately unknown until realization.  Compile
  # the checked graph inside one CA node for now.  A future explicit two-pass
  # command may feed a realized manifest back to Nix to recover per-unit nodes
  # without introducing a hidden evaluation-time dependency.
  compiledObjects = [ ];
  objectReceipts = [ ];
  package = pkgs.runCommand "${namePrefix}-native-object-package-v2" {
    nativeBuildInputs = [ pythonEnv compiler pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phasePythonSource}/src
    ${python} - ${graph} "$out" <<'PY'
    import pathlib
    import json
    import sys
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        assemble_stage_b_interpreter_native_objects,
        compile_stage_b_interpreter_native_object,
    )

    graph = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    payload = json.loads((graph / "native-object-graph.json").read_text(encoding="utf-8"))
    work = output.parent / (output.name + "-objects")
    packages = []
    for index, unit in enumerate(payload["units"]):
        package = work / f"{index:04d}"
        compile_stage_b_interpreter_native_object(
            graph=graph,
            unit_id=unit["id"],
            out_dir=package,
        )
        packages.append(package)
    assemble_stage_b_interpreter_native_objects(
        graph=graph,
        out_dir=output,
        object_packages=packages,
    )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-object-package-v2" and
      .status == "complete" and (.executes_original_binary | not) and
      .counts.objects == (.objects | length) and
      .counts.objects == (.units | length)
    ' "$out/native-object-package.json" >/dev/null
  '';
in
{
  inherit graph compiledObjects objectReceipts package;
  objects = objectReceipts;
  unitCount = null;
}
