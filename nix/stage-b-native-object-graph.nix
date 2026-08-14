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
      .counts.compile_units == (.bundles | length) and
      all(.units[];
        (.compile_key_sha256 | test("^[0-9a-f]{64}$")) and
        (.dependencies | type == "array") and
        (.root_mappings | type == "array"))
    ' "$out/native-object-graph.json" >/dev/null
    jq -e '
      .format == "stage-b-interpreter-native-bundle-index-v1" and
      .status == "ready" and (.executes_original_binary | not) and
      .counts.compile_units == (.bundles | length) and
      all(.bundles[];
        (.unit_id | type == "string") and
        (.compile_key_sha256 | test("^[0-9a-f]{64}$")) and
        (.bundle_sha256 | test("^[0-9a-f]{64}$")) and
        (.path | startswith("bundles/")))
    ' "$out/native-object-bundles.json" >/dev/null
  '';

  # The unit inventory is binary-derived and therefore not statically known to
  # Nix. Keep this small metadata/source-normalization phase input-addressed so
  # controlled IFD can discover it. Each normalized bundle is then imported by
  # content, severing object invalidation from the parent package store paths.
  graphPayload = builtins.fromJSON (
    builtins.readFile "${graph}/native-object-bundles.json"
  );
  unitCount = builtins.length graphPayload.bundles;
  mkObject = binding:
    let
      sourceBundle = pkgs.runCommand
        "${namePrefix}-${binding.unit_id}-native-source-bundle-v1"
        {
          nativeBuildInputs = [ pkgs.jq ];
          preferLocalBuild = false;
          allowSubstitutes = true;
          __contentAddressed = true;
        }
        ''
          set -euo pipefail
          mkdir -p "$out"
          cp -R ${graph}/${binding.path}/. "$out/"
          jq -e \
            --arg unit ${lib.escapeShellArg binding.unit_id} \
            --arg key ${lib.escapeShellArg binding.compile_key_sha256} \
            --arg bundle ${lib.escapeShellArg binding.bundle_sha256} '
            .format == "stage-b-interpreter-native-source-bundle-v1" and
            .status == "ready" and
            .unit_id == $unit and
            .compile_key_sha256 == $key and
            .bundle_sha256 == $bundle
          ' "$out/native-source-bundle.json" >/dev/null
        '';
    in
    pkgs.runCommand "${namePrefix}-${binding.unit_id}-native-object-v2" {
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
      ${python} - ${sourceBundle} ${compiler}/bin/i686-w64-mingw32-gcc "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_interpreter_native_build import (
          compile_stage_b_interpreter_native_source_bundle,
      )

      compile_stage_b_interpreter_native_source_bundle(
          source_bundle=pathlib.Path(sys.argv[1]),
          compiler=pathlib.Path(sys.argv[2]),
          out_dir=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e \
        --arg unit ${lib.escapeShellArg binding.unit_id} \
        --arg key ${lib.escapeShellArg binding.compile_key_sha256} '
        .format == "stage-b-interpreter-native-object-v2" and
        .status == "compiled" and (.executes_original_binary | not) and
        .unit_id == $unit and
        .compile_key_sha256 == $key and
        (.source_bundle_sha256 | test("^[0-9a-f]{64}$")) and
        (.object.sha256 | test("^[0-9a-f]{64}$"))
      ' "$out/native-object.json" >/dev/null
    '';
  objectReceipts = map mkObject graphPayload.bundles;
  compiledObjects = objectReceipts;
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
    ${python} - ${graph} "$out" ${lib.escapeShellArgs (map toString objectReceipts)} <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        assemble_stage_b_interpreter_native_objects,
    )

    graph = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    assemble_stage_b_interpreter_native_objects(
        graph=graph,
        out_dir=output,
        object_packages=[pathlib.Path(value) for value in sys.argv[3:]],
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
  inherit unitCount;
}
