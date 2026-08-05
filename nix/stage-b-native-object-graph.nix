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

  # Deliberate IFD: checked static extraction determines a small compile-unit
  # inventory. Expensive compiler nodes below do not depend on this graph.
  graphData = builtins.fromJSON (
    builtins.unsafeDiscardStringContext (
      builtins.readFile "${graph}/native-object-graph.json"
    )
  );

  ownerRoots = {
    interpreter = interpreterPackage;
    native_engine = nativeEnginePackage;
    native_runtime = nativeRuntimePackage;
    generated = graph;
  } // lib.optionalAttrs (regionOverridePackage != null) {
    region_overrides = regionOverridePackage;
  };

  sourcePath = file:
    let
      root = ownerRoots.${file.owner} or (
        throw "native object graph references unknown source owner ${file.owner}"
      );
    in "${root}/${file.path}";

  mkCopy = file: ''
    source=${lib.escapeShellArg (sourcePath file)}
    target="$out/${file.bundle_path}"
    test "$(sha256sum "$source" | cut -d ' ' -f 1)" = ${lib.escapeShellArg file.sha256}
    mkdir -p "$(dirname "$target")"
    cp "$source" "$target"
  '';

  mkSourceBundle = unit:
    pkgs.runCommand
      "stage-b-native-source-${builtins.substring 0 20 unit.compile_key_sha256}"
      {
        nativeBuildInputs = [ pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        ${lib.concatMapStringsSep "\n" (mapping:
          ''mkdir -p "$out/roots/${mapping.owner}"''
        ) unit.root_mappings}
        ${lib.concatMapStringsSep "\n" mkCopy ([ unit.source ] ++ unit.dependencies)}
        find "$out" -type f -exec touch -d @1 {} +
      '';

  actualFlags = unit: bundle:
    unit.compile_flags
    ++ lib.concatMap (mapping:
      let root = "${bundle}/roots/${mapping.owner}";
      in [
        "-ffile-prefix-map=${root}=/stage-b/${mapping.label}"
        "-fdebug-prefix-map=${root}=/stage-b/${mapping.label}"
        "-fmacro-prefix-map=${root}=/stage-b/${mapping.label}"
      ]) unit.root_mappings;

  mkCompiledObject = unit:
    let
      bundle = mkSourceBundle unit;
      includeArgs = lib.concatMapStringsSep " "
        (mapping: "-I ${lib.escapeShellArg "${bundle}/roots/${mapping.owner}"}")
        unit.root_mappings;
      flagArgs = lib.concatMapStringsSep " " lib.escapeShellArg
        (actualFlags unit bundle);
    in pkgs.runCommand
      "stage-b-native-object-${builtins.substring 0 20 unit.compile_key_sha256}"
      {
        nativeBuildInputs = [ compiler ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C.UTF-8
        export SOURCE_DATE_EPOCH=1
        mkdir -p "$out"
        ${compiler}/bin/i686-w64-mingw32-gcc \
          -x ${lib.escapeShellArg unit.language} -c \
          ${lib.escapeShellArg "${bundle}/${unit.source.bundle_path}"} \
          -o "$out/object.o" ${includeArgs} ${flagArgs}
        test -s "$out/object.o"
        touch -d @1 "$out/object.o"
      '';

  mkObjectReceipt = unit:
    let compiled = mkCompiledObject unit;
    in pkgs.runCommand
      "stage-b-native-object-receipt-${builtins.substring 0 20 unit.compile_key_sha256}"
      {
        nativeBuildInputs = [ pkgs.coreutils pkgs.jq ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        cp ${compiled}/object.o "$out/object.o"
        object_sha256="$(sha256sum "$out/object.o" | cut -d ' ' -f 1)"
        object_size="$(stat -c %s "$out/object.o")"
        jq -n \
          --arg format stage-b-interpreter-native-object-v2 \
          --arg status compiled \
          --arg unit_id ${lib.escapeShellArg unit.id} \
          --arg compile_key_sha256 ${lib.escapeShellArg unit.compile_key_sha256} \
          --arg object_sha256 "$object_sha256" \
          --argjson object_size "$object_size" \
          '{
            format: $format,
            status: $status,
            executes_original_binary: false,
            unit_id: $unit_id,
            compile_key_sha256: $compile_key_sha256,
            object: {
              path: "object.o",
              sha256: $object_sha256,
              size: $object_size
            }
          }' > "$out/.receipt-core.json"
        receipt_sha256="$(jq -cS . "$out/.receipt-core.json" | tr -d '\n' | sha256sum | cut -d ' ' -f 1)"
        jq --arg receipt_sha256 "$receipt_sha256" \
          '. + {object_receipt_sha256: $receipt_sha256}' \
          "$out/.receipt-core.json" > "$out/native-object.json"
        rm "$out/.receipt-core.json"
        touch -d @1 "$out/object.o" "$out/native-object.json"
      '';

  compiledObjects = map mkCompiledObject graphData.units;
  objectReceipts = map mkObjectReceipt graphData.units;
  objectArgs = lib.concatMapStringsSep " "
    (object: lib.escapeShellArg (toString object)) objectReceipts;
  package = pkgs.runCommand "${namePrefix}-native-object-package-v2" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phasePythonSource}/src
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
      .format == "stage-b-interpreter-native-object-package-v2" and
      .status == "complete" and (.executes_original_binary | not) and
      .counts.objects == $expected and (.objects | length) == $expected
    ' "$out/native-object-package.json" >/dev/null
  '';
in
{
  inherit graph compiledObjects objectReceipts package;
  objects = objectReceipts;
  unitCount = builtins.length graphData.units;
}
