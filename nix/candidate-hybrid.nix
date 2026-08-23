# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  staticAuthority ? null,
  nativeIngressPlan,
  moduleInterface,
  candidateFilename,
  structuralExecutionGate,
  machineImportProfiles,
  namePrefix,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  interpreterPackage,
  componentRuntimePackage,
  nativeProcessTermination ? null,
}:

assert pkgs.lib.assertMsg
  (staticAuthority != null)
  "structural candidates require checked static analysis artifacts";
assert pkgs.lib.assertMsg
  (structuralExecutionGate != null)
  "structural candidates require structural-executable-v1";
assert pkgs.lib.assertMsg
  (componentRuntimePackage != null)
  "static-closed candidates require a component runtime package";

let
  lib = pkgs.lib;
  structuralExecutionArg = lib.escapeShellArg
    "${structuralExecutionGate}/structural-executable.json";
  canonicalExternalSites =
    staticAuthority.graph.phases."canonical-external-sites-v3".artifact
      or (throw "static authority omitted canonical-external-sites-v3");
  canonicalExternalSitesArg = lib.escapeShellArg (toString canonicalExternalSites);
  callbackAuthority =
    staticAuthority.graph.phases."callback-authority-v4".artifact
      or (throw "static authority omitted callback-authority-v4");
  callbackAuthorityArg = lib.escapeShellArg (toString callbackAuthority);
  rootClosure = staticAuthority.graph.phases."launch-root-closure-v3".artifact
    or (throw "static authority omitted launch-root-closure-v3");
  targetCertificates = staticAuthority.graph.phases."indirect-target-certificates-v3".artifact
    or (throw "static authority omitted indirect-target-certificates-v3");
  parametricSummaries = staticAuthority.graph.phases."parametric-scc-summaries-v3".artifact
    or (throw "static authority omitted parametric-scc-summaries-v3");
  python = "${pythonEnv}/bin/python3";
  loadImageContract = "${staticExport}/load-image-contract.json";
  mkPythonClosure = suffix: modules: import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs modules;
    name = "${namePrefix}-${suffix}-python-closure";
  };
  nativeEnginePythonSource = mkPythonClosure "native-engine" [
    "spaghetti_extractor.candidate.engine"
    "spaghetti_extractor.candidate.image"
  ];
  nativeRuntimePythonSource = mkPythonClosure "native-runtime" [
    "spaghetti_extractor.candidate.runtime"
  ];
  nativeBuildPythonSource = mkPythonClosure "native-build" [
    "spaghetti_extractor.candidate.build"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  terminationIntent = pkgs.writeText
    "${namePrefix}-native-process-termination.json"
    (builtins.toJSON nativeProcessTermination);
  interpreter = interpreterPackage;
  componentRuntime = componentRuntimePackage;
  portableReplacementSelection =
    "${componentRuntime}/portable-component-selection.json";
  portableReplacementArg = lib.escapeShellArg
    (toString portableReplacementSelection);
  componentRuntimeArg = lib.escapeShellArg (toString componentRuntime);
  ingressPayload = builtins.fromJSON (
    builtins.readFile "${nativeIngressPlan}/native-ingress-plan.json"
  );
  moduleIngresses = builtins.filter
    (row: builtins.elem row.role [ "process_entry" "dll_entry" ])
    ingressPayload.ingresses;
  entrySymbol = assert lib.assertMsg (builtins.length moduleIngresses == 1)
    "native ingress plan must contain one module entry";
    (builtins.head moduleIngresses).bridge_symbol;
  machineImportProfileBundle = pkgs.runCommand
    "${namePrefix}-machine-import-profile-bundle-v1"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    }
    ''
      export PYTHONHASHSEED=0
      export PYTHONPATH=${nativeRuntimePythonSource}/src
      mkdir -p "$out"
      ${python} - "$out/profile.json" ${profileArgs} <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.external.machine_import_profiles import (
          load_machine_import_profile_set,
      )
      from spaghetti_extractor.util import write_json

      destination = pathlib.Path(sys.argv[1])
      selected = load_machine_import_profile_set(
          [pathlib.Path(value) for value in sys.argv[2:]]
      )
      write_json(destination, {
          "format": "spaghetti-extractor-static-machine-import-profile-v2",
          "id": "${namePrefix}-machine-import-profile-bundle-v1",
          "provenance": {
              "kind": "resolved_machine_import_profile_graph_v1",
              "source_profiles": [
                  {
                      "id": profile.profile_id,
                      "sha256": profile.sha256,
                  }
                  for profile in selected.profiles
              ],
          },
          "machine_import_call_contracts": [
              dict(contract.contract) for contract in selected.contracts
          ],
      })
      PY
    '';

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
    jq -e '
      .format == "spaghetti-extractor-structural-executable-v1" and
      .status == "complete" and .executable
    ' ${structuralExecutionGate}/structural-executable.json >/dev/null
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${machineIr}/recovered-executable-data.json \
      ${nativeIngressPlan}/native-ingress-plan.json \
      ${loadImageContract} \
      ${portableReplacementArg} \
      ${machineImportProfileBundle}/profile.json \
      ${canonicalExternalSitesArg} \
      ${callbackAuthorityArg} \
      ${lib.escapeShellArg (toString rootClosure)} \
      ${lib.escapeShellArg (toString targetCertificates)} \
      ${lib.escapeShellArg (toString parametricSummaries)} \
      ${terminationIntent} "$out" ${profileArgs} <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.candidate.engine import (
        write_spx_native_engine_package,
    )
    from spaghetti_extractor.candidate.image import (
        derive_native_image_inputs,
        select_native_termination_import,
    )

    machine_ir = pathlib.Path(sys.argv[1])
    machine_ir_manifest = pathlib.Path(sys.argv[2])
    recovered_executable_data = pathlib.Path(sys.argv[3])
    ingress_plan = pathlib.Path(sys.argv[4])
    load_contract = pathlib.Path(sys.argv[5])
    portable_path = sys.argv[6]
    profile_bundle = pathlib.Path(sys.argv[7])
    canonical_external_sites_path = sys.argv[8]
    callback_authority_path = pathlib.Path(sys.argv[9])
    root_closure_path = pathlib.Path(sys.argv[10])
    target_certificates_path = pathlib.Path(sys.argv[11])
    parametric_summaries_path = pathlib.Path(sys.argv[12])
    termination_intent = json.loads(pathlib.Path(sys.argv[13]).read_text())
    output = pathlib.Path(sys.argv[14])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[15:])
    selected_portable_components = ()
    if portable_path:
        portable_payload = json.loads(
            pathlib.Path(portable_path).read_text(encoding="utf-8")
        )
        selected_portable_components = (
            portable_payload["entries"]
            if isinstance(portable_payload, dict)
            else portable_payload
        )
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
        machine_ir_manifest=machine_ir_manifest,
        recovered_executable_data=recovered_executable_data,
        native_ingress_plan=ingress_plan,
        import_slots=inputs.import_slots,
        termination_import=termination,
        base_relocation_evidence=inputs.base_relocation_evidence,
        fixed_image_base=inputs.fixed_image_base,
        preferred_image_base=inputs.image_base,
        canonical_external_sites=pathlib.Path(canonical_external_sites_path),
        callback_authority=callback_authority_path,
        root_closure=root_closure_path,
        target_certificates=target_certificates_path,
        parametric_summaries=parametric_summaries_path,
        out=output,
        initial_zero_ranges=inputs.initial_zero_ranges,
        selected_portable_components=selected_portable_components,
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-native-engine-package-v1" and
      .status == "ready" and
      .counts.input_transfers > 0 and
      .counts.transfers == .counts.input_transfers and
      .counts.blockers == 0 and
      .policy.execution_scope == "structural-executable-v1" and
      .policy.structural_execution_receipt_required and
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
      ${machineImportProfileBundle}/profile.json \
      "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.runtime import (
        write_spx_native_runtime_package,
    )

    write_spx_native_runtime_package(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        external_profile=pathlib.Path(sys.argv[3]),
        out=pathlib.Path(sys.argv[4]),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-native-runtime-package-v1" and
      .status == "ready" and
      .policy.execution_scope == "structural-executable-v1" and
      .policy.structural_execution_receipt_required and
      (.acceptance_authority | not)
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  nativeObjects = import ./candidate-native-object-graph.nix {
    inherit pkgs pythonEnv;
    inherit pythonSource;
    interpreterPackage = interpreter;
    nativeEnginePackage = nativeEngine;
    nativeRuntimePackage = nativeRuntime;
    inherit compiler namePrefix;
    regionOverridePackage = componentRuntime;
    inherit entrySymbol;
  };

  baseCandidate = pkgs.runCommand "${namePrefix}-linked-base-module-v1" {
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
    jq -e '
      .format == "spaghetti-extractor-structural-executable-v1" and
      .status == "complete" and .executable
    ' ${structuralExecutionGate}/structural-executable.json >/dev/null
    ${python} - \
      ${interpreter} ${nativeEngine} ${nativeRuntime} \
      ${structuralExecutionArg} \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${componentRuntimeArg} \
      ${loadImageContract} \
      ${machineIr}/recovered-executable-data.json \
      ${nativeObjects.package} \
      ${compiler}/bin/i686-w64-mingw32-gcc "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.build import (
        build_spx_interpreter_native_candidate,
    )

    def optional_path(value):
        return pathlib.Path(value) if value else None

    build_spx_interpreter_native_candidate(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        native_runtime_package=pathlib.Path(sys.argv[3]),
        candidate_authority=None,
        final_authority=None,
        structural_execution_receipt=pathlib.Path(sys.argv[4]),
        machine_ir=pathlib.Path(sys.argv[5]),
        machine_ir_manifest=pathlib.Path(sys.argv[6]),
        fallback_coverage_receipt=None,
        component_runtime_package=pathlib.Path(sys.argv[7]),
        region_override_package=optional_path(sys.argv[7]),
        load_image_contract=pathlib.Path(sys.argv[8]),
        recovered_executable_data=pathlib.Path(sys.argv[9]),
        precompiled_objects=pathlib.Path(sys.argv[10]),
        compiler=pathlib.Path(sys.argv[11]),
        out_dir=pathlib.Path(sys.argv[12]),
        native_ingress_plan=pathlib.Path(
            ${builtins.toJSON "${nativeIngressPlan}/native-ingress-plan.json"}
        ),
        candidate_filename=${builtins.toJSON candidateFilename},
      )
    PY
    jq -e '
      .format == "spaghetti-extractor-interpreter-native-build-v1" and
      .status == "candidate-generated" and
      .acceptance_authority == "none" and
      .inputs.candidate_authority == null and
      .inputs.structural_executable.status == "complete" and
      .inputs.structural_executable.executable and
      .inputs.execution_scope.execution_scope == "structural-executable-v1" and
      .inputs.execution_scope.acceptance_authority == "none" and
      .policy.candidate_class == "structural-executable-hybrid"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/${candidateFilename}"
  '';
  nativeIngressLinkReceipt = import ./native-ingress-link-receipt.nix {
    inherit pkgs pythonEnv nativeIngressPlan namePrefix;
    linkedModule = "${baseCandidate}/${candidateFilename}";
    linkerMap = "${baseCandidate}/payload.map";
  };
  candidate = import ./pe32-module-composition.nix {
    inherit pkgs pythonEnv nativeIngressPlan candidateFilename namePrefix;
    baseCandidate = "${baseCandidate}/${candidateFilename}";
    baseCompositionManifest =
      "${baseCandidate}/pe-composition-manifest.json";
    originalModuleInterface = moduleInterface;
    nativeIngressLinkReceipt = nativeIngressLinkReceipt;
  };
in
{
  inherit
    interpreter
    structuralExecutionGate
    componentRuntime
    machineImportProfileBundle
    nativeEngine
    nativeRuntime
    nativeObjects
    baseCandidate
    nativeIngressLinkReceipt
    candidate
    ;
}
