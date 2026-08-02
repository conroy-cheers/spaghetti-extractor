{
  pkgs,
  pythonEnv,
  pythonSource,
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
  graph = pkgs.runCommand "${namePrefix}-native-object-graph-v1" {
    nativeBuildInputs = [ pythonEnv compiler pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${pythonSource}/src
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
      .format == "stage-b-interpreter-native-object-graph-v1" and
      .status == "ready" and (.executes_original_binary | not) and
      .counts.compile_units == (.units | length)
    ' "$out/native-object-graph.json" >/dev/null
  '';

  # Deliberate IFD: static extraction determines the source inventory.  The
  # graph is CA, small, and changes only when a package source actually changes.
  graphData = builtins.fromJSON (
    builtins.unsafeDiscardStringContext (
      builtins.readFile "${graph}/native-object-graph.json"
    )
  );
  mkObject = unit: pkgs.runCommand
    "${namePrefix}-native-object-${lib.strings.sanitizeDerivationName unit.id}-v1"
    {
      nativeBuildInputs = [ pythonEnv compiler ];
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
      ${python} - ${graph} ${lib.escapeShellArg unit.id} "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_interpreter_native_build import (
          compile_stage_b_interpreter_native_object,
      )

      compile_stage_b_interpreter_native_object(
          graph=pathlib.Path(sys.argv[1]),
          unit_id=sys.argv[2],
          out_dir=pathlib.Path(sys.argv[3]),
      )
      PY
    '';
  objects = map mkObject graphData.units;
  objectArgs = lib.concatMapStringsSep " "
    (object: lib.escapeShellArg (toString object)) objects;
  package = pkgs.runCommand "${namePrefix}-native-object-package-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${pythonSource}/src
    ${python} - ${graph} "$out" ${objectArgs} <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        assemble_stage_b_interpreter_native_objects,
    )

    assemble_stage_b_interpreter_native_objects(
        graph=pathlib.Path(sys.argv[1]),
        out_dir=pathlib.Path(sys.argv[2]),
        object_packages=[pathlib.Path(value) for value in sys.argv[3:]],
    )
    PY
    jq -e --argjson expected ${toString (builtins.length graphData.units)} '
      .format == "stage-b-interpreter-native-object-package-v1" and
      .status == "complete" and (.executes_original_binary | not) and
      .counts.objects == $expected and (.objects | length) == $expected
    ' "$out/native-object-package.json" >/dev/null
  '';
in
{
  inherit graph objects package;
  unitCount = builtins.length graphData.units;
}
