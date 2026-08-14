# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  staticAuthority ? null,
  machineImportProfiles,
  namePrefix,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  interpreterPackage,
  componentRuntimePackage,
}:

assert pkgs.lib.assertMsg
  (staticAuthority != null)
  "static-closed candidates require v3 final authority";
assert pkgs.lib.assertMsg
  (componentRuntimePackage != null)
  "static-closed candidates require a component runtime package";

let
  lib = pkgs.lib;
  candidateAuthorityArg = lib.escapeShellArg
    "${candidateAuthorityGate}/candidate-authority.json";
  finalAuthorityArg = lib.escapeShellArg
    (toString staticAuthority.finalAuthorityArtifact);
  canonicalExternalSites =
    staticAuthority.graph.outputs."canonical-external-sites-v3"
      or (throw "static authority omitted canonical-external-sites-v3");
  canonicalExternalSitesArg = lib.escapeShellArg (toString canonicalExternalSites);
  fallbackCoverageArg = lib.escapeShellArg
    "${fallbackCoverageReceipt}/fallback-coverage-receipt.json";
  python = "${pythonEnv}/bin/python3";
  loadImageContract = "${staticExport}/load-image-contract.json";
  mkPythonClosure = suffix: modules: import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs modules;
    source = pythonSource;
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
  candidateAuthorityPythonSource = mkPythonClosure "candidate-authority-v3" [
    "spaghetti_extractor.candidate.authority"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  interpreter = interpreterPackage;
  componentRuntime = componentRuntimePackage;
  portableReplacementSelection =
    "${componentRuntime}/portable-component-selection.json";
  portableReplacementArg = lib.escapeShellArg
    (toString portableReplacementSelection);
  componentRuntimeArg = lib.escapeShellArg (toString componentRuntime);
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
          "format": "stage-a-external-environment-profile-v1",
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

  fallbackCoverageReceipt = import ./stage-b-fallback-coverage-receipt.nix {
    inherit pkgs pythonEnv pythonSource machineIr namePrefix;
    interpreterPackage = interpreter;
    portableReplacements = portableReplacementSelection;
  };

  candidateAuthorityReport = pkgs.runCommand
    "${namePrefix}-candidate-authority-v3"
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
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${candidateAuthorityPythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${staticAuthority.finalAuthorityArtifact} \
        ${machineIr}/machine-ir.jsonl \
        ${machineIr}/machine-ir-manifest.json \
        ${fallbackCoverageReceipt}/fallback-coverage-receipt.json \
        ${componentRuntime} \
        "$out/candidate-authority.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.candidate.authority import (
          build_candidate_authority,
      )

      (
          final_authority,
          machine_ir,
          manifest,
          fallback_receipt,
          component_runtime,
          output,
      ) = sys.argv[1:]
      receipt = build_candidate_authority(
          final_authority=pathlib.Path(final_authority),
          machine_ir=pathlib.Path(machine_ir),
          machine_ir_manifest=pathlib.Path(manifest),
          fallback_coverage_receipt=pathlib.Path(fallback_receipt),
          component_runtime_package=pathlib.Path(component_runtime),
      )
      pathlib.Path(output).write_text(receipt.to_json(), encoding="ascii")
      PY
      jq -e '
        .format == "spaghetti-extractor-stage-b-candidate-authority-receipt-v3" and
        (.status == "authorized" or .status == "incomplete" or .status == "violated") and
        .policy.final_authority_v3_required and
        .policy.candidate_generation_fails_closed
      ' "$out/candidate-authority.json" >/dev/null
    '';

  candidateAuthorityGate = pkgs.runCommand
    "${namePrefix}-candidate-authority-gate-v3"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export PYTHONPATH=${candidateAuthorityPythonSource}/src
      mkdir -p "$out"
      ${python} - ${candidateAuthorityReport}/candidate-authority.json \
        "$out/candidate-authority.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.candidate.authority import (
          parse_candidate_authority,
          require_candidate_authority,
      )

      source, output = map(pathlib.Path, sys.argv[1:])
      receipt = require_candidate_authority(
          parse_candidate_authority(source.read_bytes())
      )
      output.write_text(receipt.to_json(), encoding="ascii")
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
      .format == "spaghetti-extractor-stage-b-candidate-authority-receipt-v3" and
      .status == "authorized"
    ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${machineIr}/recovered-executable-data.json \
      ${loadImageContract} \
      ${portableReplacementArg} \
      ${machineImportProfileBundle}/profile.json \
      ${canonicalExternalSitesArg} \
      "$out" ${profileArgs} <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.candidate.engine import (
        write_stage_b_native_engine_package,
    )
    from spaghetti_extractor.candidate.image import (
        derive_native_image_inputs,
        select_native_termination_import,
    )

    machine_ir = pathlib.Path(sys.argv[1])
    machine_ir_manifest = pathlib.Path(sys.argv[2])
    recovered_executable_data = pathlib.Path(sys.argv[3])
    load_contract = pathlib.Path(sys.argv[4])
    portable_path = sys.argv[5]
    profile_bundle = pathlib.Path(sys.argv[6])
    canonical_external_sites_path = sys.argv[7]
    output = pathlib.Path(sys.argv[8])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[9:])
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
        machine_ir_manifest=machine_ir_manifest,
        recovered_executable_data=recovered_executable_data,
        entry_rva=inputs.entry_rva,
        callback_targets=inputs.callback_targets,
        import_iat_vas=inputs.import_iat_vas,
        termination_import=termination,
        base_relocation_evidence=inputs.base_relocation_evidence,
        fixed_image_base=inputs.fixed_image_base,
        preferred_image_base=inputs.image_base,
        machine_import_profiles=(profile_bundle,),
        canonical_external_sites=(
            pathlib.Path(canonical_external_sites_path)
            if canonical_external_sites_path else None
        ),
        candidate_mode="static-closed",
        allow_deferred_potential_transfers=False,
        out=output,
        initial_zero_ranges=inputs.initial_zero_ranges,
        selected_portable_components=selected_portable_components,
    )
    PY
    jq -e '
      .format == "stage-b-native-engine-package-v1" and
      .status == "ready" and
      .counts.input_transfers > 0 and
      .counts.transfers + .counts.deferred_transfers == .counts.input_transfers and
      .counts.deferred_transfers == 0 and
      .counts.blockers == 0 and
      .policy.candidate_mode == "static-closed" and
      .policy.static_hybrid_closure_receipt_required and
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
      .policy.candidate_mode == "static-closed" and
      .policy.static_hybrid_closure_receipt_required and
      (.acceptance_authority | not)
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  nativeObjects = import ./stage-b-native-object-graph.nix {
    inherit pkgs pythonEnv;
    inherit pythonSource;
    interpreterPackage = interpreter;
    nativeEnginePackage = nativeEngine;
    nativeRuntimePackage = nativeRuntime;
    inherit compiler namePrefix;
    diagnosticFailureTrap = false;
    regionOverridePackage = componentRuntime;
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
    jq -e '
      .format == "spaghetti-extractor-stage-b-candidate-authority-receipt-v3" and
      .status == "authorized"
    ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ${python} - \
      ${interpreter} ${nativeEngine} ${nativeRuntime} \
      ${candidateAuthorityArg} \
      ${finalAuthorityArg} \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${fallbackCoverageArg} \
      ${componentRuntimeArg} \
      ${loadImageContract} \
      ${machineIr}/recovered-executable-data.json \
      ${nativeObjects.package} \
      ${compiler}/bin/i686-w64-mingw32-gcc "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.candidate.build import (
        build_stage_b_interpreter_native_candidate,
    )

    def optional_path(value):
        return pathlib.Path(value) if value else None

    build_stage_b_interpreter_native_candidate(
        interpreter_package=pathlib.Path(sys.argv[1]),
        native_engine_package=pathlib.Path(sys.argv[2]),
        native_runtime_package=pathlib.Path(sys.argv[3]),
        candidate_authority=optional_path(sys.argv[4]),
        final_authority=optional_path(sys.argv[5]),
        machine_ir=pathlib.Path(sys.argv[6]),
        machine_ir_manifest=pathlib.Path(sys.argv[7]),
        fallback_coverage_receipt=optional_path(sys.argv[8]),
        component_runtime_package=pathlib.Path(sys.argv[9]),
        region_override_package=optional_path(sys.argv[9]),
        load_image_contract=pathlib.Path(sys.argv[10]),
        recovered_executable_data=pathlib.Path(sys.argv[11]),
        precompiled_objects=pathlib.Path(sys.argv[12]),
        compiler=pathlib.Path(sys.argv[13]),
        diagnostic_failure_trap=False,
        candidate_mode="static-closed",
        out_dir=pathlib.Path(sys.argv[14]),
      )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated" and
      .acceptance_authority == "none" and
      .inputs.candidate_authority.status == "authorized" and
      .inputs.execution_scope.candidate_mode == "static-closed" and
      .inputs.execution_scope.acceptance_authority == "none" and
      .policy.candidate_class == "release-static-closed"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
  '';
in
{
  inherit
    interpreter
    componentRuntime
    machineImportProfileBundle
    fallbackCoverageReceipt
    candidateAuthorityReport
    candidateAuthorityGate
    nativeEngine
    nativeRuntime
    nativeObjects
    candidate
    ;
}
