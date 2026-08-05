{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  machineImportProfiles,
  namePrefix,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  allowDeferredPotentialTransfers ? false,
  diagnosticFailureTrap ? false,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  loadImageContract = "${staticExport}/load-image-contract.json";
  mkPythonClosure = suffix: modules: import ./python-module-closure.nix {
    inherit pkgs modules;
    source = pythonSource;
    name = "${namePrefix}-${suffix}-python-closure";
  };
  nativeEnginePythonSource = mkPythonClosure "native-engine" [
    "spaghetti_extractor.stage_b_native_engine"
    "spaghetti_extractor.stage_b_native_image"
  ];
  nativeRuntimePythonSource = mkPythonClosure "native-runtime" [
    "spaghetti_extractor.stage_b_native_runtime"
  ];
  nativeBuildPythonSource = mkPythonClosure "native-build" [
    "spaghetti_extractor.stage_b_interpreter_native_build"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;

  interpreter = import ./stage-b-interpreter-package.nix {
    inherit pkgs pythonEnv machineIr namePrefix;
    inherit pythonSource;
    inherit allowDeferredPotentialTransfers;
  };

  nativeEngine = pkgs.runCommand "${namePrefix}-native-engine-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${nativeEnginePythonSource}/src
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${loadImageContract} \
      "$out" ${profileArgs} <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.stage_b_native_engine import (
        write_stage_b_native_engine_package,
    )
    from spaghetti_extractor.stage_b_native_image import (
        derive_native_image_inputs,
        select_native_termination_import,
    )

    machine_ir = pathlib.Path(sys.argv[1])
    load_contract = pathlib.Path(sys.argv[2])
    output = pathlib.Path(sys.argv[3])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[4:])
    reference_sha256 = None
    with machine_ir.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            unit = json.loads(line)
            export = unit.get("source", {}).get("semantic_export")
            if isinstance(export, dict):
                reference_sha256 = export.get("reference_contract_sha256")
            if reference_sha256 is not None:
                break
    inputs = derive_native_image_inputs(
        load_image_contract=load_contract,
        reference_contract_sha256=reference_sha256,
    )
    termination = select_native_termination_import(
        profile_paths=profiles,
        import_iat_vas=inputs.import_iat_vas,
    )
    write_stage_b_native_engine_package(
        machine_ir=machine_ir,
        entry_rva=inputs.entry_rva,
        callback_targets=inputs.callback_targets,
        import_iat_vas=inputs.import_iat_vas,
        termination_import=termination,
        base_relocation_evidence=inputs.base_relocation_evidence,
        fixed_image_base=inputs.fixed_image_base,
        allow_deferred_potential_transfers=${if allowDeferredPotentialTransfers then "True" else "False"},
        out=output,
        initial_zero_ranges=inputs.initial_zero_ranges,
    )
    PY
    jq -e '
      .format == "stage-b-native-engine-package-v1" and
      (.status == "ready" or .status == "incomplete") and
      .counts.input_transfers > 0 and
      .counts.transfers + .counts.deferred_transfers == .counts.input_transfers and
      (.authority | contains("candidate generation only"))
    ' "$out/native-engine-package.json" >/dev/null
  '';

  nativeRuntime = pkgs.runCommand "${namePrefix}-native-runtime-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${nativeRuntimePythonSource}/src
    ${python} - ${interpreter} ${nativeEngine} \
      ${lib.escapeShellArg (toString (builtins.head machineImportProfiles))} \
      "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_native_runtime import (
        write_stage_b_native_runtime_package,
    )

    write_stage_b_native_runtime_package(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        external_profile=pathlib.Path(sys.argv[3]),
        out=pathlib.Path(sys.argv[4]),
    )
    PY
    jq -e '
      .format == "stage-b-native-runtime-package-v1" and
      .status == "ready" and
      (.acceptance_authority | not)
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  nativeObjects = import ./stage-b-native-object-graph.nix {
    inherit pkgs pythonEnv;
    inherit pythonSource;
    interpreterPackage = interpreter;
    nativeEnginePackage = nativeEngine;
    nativeRuntimePackage = nativeRuntime;
    inherit compiler namePrefix diagnosticFailureTrap;
  };

  candidate = pkgs.runCommand "${namePrefix}-hybrid-candidate-v1" {
    nativeBuildInputs = [ pythonEnv compiler pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${nativeBuildPythonSource}/src
    ${python} - \
      ${interpreter} ${nativeEngine} ${nativeRuntime} \
      ${loadImageContract} ${nativeObjects.package} \
      ${compiler}/bin/i686-w64-mingw32-gcc "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        build_stage_b_interpreter_native_candidate,
    )

    build_stage_b_interpreter_native_candidate(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        native_runtime_package=pathlib.Path(sys.argv[3]),
        load_image_contract=pathlib.Path(sys.argv[4]),
        precompiled_objects=pathlib.Path(sys.argv[5]),
        compiler=pathlib.Path(sys.argv[6]),
        diagnostic_failure_trap=${if diagnosticFailureTrap then "True" else "False"},
        out_dir=pathlib.Path(sys.argv[7]),
    )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated" and
      .acceptance_authority == "none"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
  '';
in
{
  inherit interpreter nativeEngine nativeRuntime nativeObjects candidate;
}
