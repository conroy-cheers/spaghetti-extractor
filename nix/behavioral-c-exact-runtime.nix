# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  staticAuthority,
  nativeIngressPlan,
  machineImportProfiles,
  interpreterPackage,
  namePrefix,
  nativeProcessTermination ? null,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  loadImageContract = "${staticExport}/load-image-contract.json";
  mkPythonClosure = suffix: modules: import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs modules;
    name = "${namePrefix}-${suffix}-python-closure";
  };
  enginePythonSource = mkPythonClosure "behavioral-engine" [
    "spaghetti_extractor.candidate.engine"
    "spaghetti_extractor.candidate.image"
  ];
  runtimePythonSource = mkPythonClosure "behavioral-runtime" [
    "spaghetti_extractor.candidate.runtime"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  terminationIntent = pkgs.writeText
    "${namePrefix}-native-process-termination.json"
    (builtins.toJSON nativeProcessTermination);
  canonicalExternalSites =
    staticAuthority.graph.phases."canonical-external-sites-v3".artifact;
  callbackAuthority =
    staticAuthority.graph.phases."callback-authority-v4".artifact;
  rootClosure = staticAuthority.graph.phases."launch-root-closure-v3".artifact;
  targetCertificates =
    staticAuthority.graph.phases."indirect-target-certificates-v3".artifact;
  parametricSummaries =
    staticAuthority.graph.phases."parametric-scc-summaries-v3".artifact;
  machineImportProfileBundle = pkgs.runCommand
    "${namePrefix}-behavioral-machine-import-profile-bundle-v1"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    }
    ''
      export PYTHONHASHSEED=0
      export PYTHONPATH=${runtimePythonSource}/src
      mkdir -p "$out"
      ${python} - "$out/profile.json" ${profileArgs} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.external.machine_import_profiles import (
          load_machine_import_profile_set,
      )
      from spaghetti_extractor.util import write_json

      selected = load_machine_import_profile_set(
          [pathlib.Path(value) for value in sys.argv[2:]]
      )
      write_json(pathlib.Path(sys.argv[1]), {
          "format": "spaghetti-extractor-static-machine-import-profile-v2",
          "id": "${namePrefix}-behavioral-machine-import-profile-bundle-v1",
          "provenance": {
              "kind": "resolved_machine_import_profile_graph_v1",
              "source_profiles": [
                  {"id": profile.profile_id, "sha256": profile.sha256}
                  for profile in selected.profiles
              ],
          },
          "machine_import_call_contracts": [
              dict(contract.contract) for contract in selected.contracts
          ],
      })
      PY
    '';
  nativeEngine = pkgs.runCommand "${namePrefix}-behavioral-native-engine-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${enginePythonSource}/src
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${machineIr}/recovered-executable-data.json \
      ${nativeIngressPlan}/native-ingress-plan.json \
      ${loadImageContract} \
      ${machineImportProfileBundle}/profile.json \
      ${lib.escapeShellArg (toString canonicalExternalSites)} \
      ${lib.escapeShellArg (toString callbackAuthority)} \
      ${lib.escapeShellArg (toString rootClosure)} \
      ${lib.escapeShellArg (toString targetCertificates)} \
      ${lib.escapeShellArg (toString parametricSummaries)} \
      ${terminationIntent} "$out" ${profileArgs} <<'PY'
    import json
    import pathlib
    import sys
    from spaghetti_extractor.candidate.engine import write_spx_native_engine_package
    from spaghetti_extractor.candidate.image import (
        derive_native_image_inputs,
        select_native_termination_import,
    )

    machine_ir = pathlib.Path(sys.argv[1])
    manifest = pathlib.Path(sys.argv[2])
    recovered = pathlib.Path(sys.argv[3])
    ingress_plan = pathlib.Path(sys.argv[4])
    load_contract = pathlib.Path(sys.argv[5])
    profile_bundle = pathlib.Path(sys.argv[6])
    external_sites = pathlib.Path(sys.argv[7])
    callbacks = pathlib.Path(sys.argv[8])
    roots = pathlib.Path(sys.argv[9])
    targets = pathlib.Path(sys.argv[10])
    summaries = pathlib.Path(sys.argv[11])
    termination_intent = json.loads(pathlib.Path(sys.argv[12]).read_text())
    output = pathlib.Path(sys.argv[13])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[14:])
    static_program_sha256 = None
    with machine_ir.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            unit = json.loads(line)
            export = unit.get("source", {}).get("semantic_export")
            if isinstance(export, dict):
                static_program_sha256 = export.get("static_program_contract_sha256")
            if static_program_sha256 is not None:
                break
    inputs = derive_native_image_inputs(
        load_image_contract=load_contract,
        static_program_contract_sha256=static_program_sha256,
    )
    termination = select_native_termination_import(
        profile_paths=profiles,
        import_slots=inputs.import_slots,
        preferred_identity=termination_intent,
    )
    write_spx_native_engine_package(
        machine_ir=machine_ir,
        machine_ir_manifest=manifest,
        recovered_executable_data=recovered,
        native_ingress_plan=ingress_plan,
        import_slots=inputs.import_slots,
        termination_import=termination,
        base_relocation_evidence=inputs.base_relocation_evidence,
        fixed_image_base=inputs.fixed_image_base,
        preferred_image_base=inputs.image_base,
        canonical_external_sites=external_sites,
        callback_authority=callbacks,
        root_closure=roots,
        target_certificates=targets,
        parametric_summaries=summaries,
        out=output,
        initial_zero_ranges=inputs.initial_zero_ranges,
        selected_portable_components=(),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-native-engine-package-v1" and
      .status == "ready" and .counts.blockers == 0 and
      .semantic_coverage.status == "complete"
    ' "$out/native-engine-package.json" >/dev/null
  '';
  nativeRuntime = pkgs.runCommand "${namePrefix}-behavioral-native-runtime-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${runtimePythonSource}/src
    ${python} - ${interpreterPackage} ${nativeEngine} \
      ${machineImportProfileBundle}/profile.json "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.runtime import write_spx_native_runtime_package

    write_spx_native_runtime_package(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        external_profile=pathlib.Path(sys.argv[3]),
        out=pathlib.Path(sys.argv[4]),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-native-runtime-package-v1" and
      .status == "ready" and (.acceptance_authority | not)
    ' "$out/native-runtime-package.json" >/dev/null
  '';
in
{
  inherit machineImportProfileBundle nativeEngine nativeRuntime;
}
