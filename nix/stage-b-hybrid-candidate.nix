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
  candidateMode ? "static-closed",
  allowDeferredPotentialTransfers ? candidateMode == "structural-diagnostic",
  diagnosticFailureTrap ? false,
  componentConfiguration ? null,
  callableExternalRuntimeContract ? null,
  externalSiteProposals ? null,
}:

assert pkgs.lib.assertMsg
  (builtins.elem candidateMode [ "static-closed" "structural-diagnostic" ])
  "candidateMode must be static-closed or structural-diagnostic";
assert pkgs.lib.assertMsg
  ((candidateMode == "static-closed") == (!allowDeferredPotentialTransfers))
  "only structural-diagnostic candidates may defer potential transfers";
assert pkgs.lib.assertMsg
  (candidateMode != "structural-diagnostic" || diagnosticFailureTrap)
  "structural-diagnostic candidates require diagnosticFailureTrap = true";
assert pkgs.lib.assertMsg
  (candidateMode != "static-closed" ||
    staticAuthority != null)
  "static-closed candidates require v3 final authority";
assert pkgs.lib.assertMsg
  (externalSiteProposals == null || candidateMode == "structural-diagnostic")
  "proposal-only external-site evidence is diagnostic-only";
assert pkgs.lib.assertMsg
  (candidateMode != "static-closed" || componentConfiguration != null)
  "static-closed candidates require a component runtime configuration";

let
  lib = pkgs.lib;
  staticClosed = candidateMode == "static-closed";
  candidateAuthorityArg = lib.escapeShellArg (
    if staticClosed then
      "${candidateAuthorityGate}/candidate-authority.json"
    else ""
  );
  finalAuthorityArg = lib.escapeShellArg (
    if staticClosed then toString staticAuthority.finalAuthorityArtifact else ""
  );
  fallbackCoverageArg = lib.escapeShellArg (
    if staticClosed then
      "${fallbackCoverageReceipt}/fallback-coverage-receipt.json"
    else ""
  );
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
  candidateAuthorityPythonSource = mkPythonClosure "candidate-authority-v3" [
    "spaghetti_extractor.candidate.authority"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  componentRuntime =
    if componentConfiguration == null then null
    else import ./stage-b-component-runtime-package.nix {
      inherit pkgs pythonEnv pythonSource machineIr namePrefix compiler;
      interpreterPackage = interpreter;
      inherit componentConfiguration;
    };
  portableReplacementSelection =
    if componentRuntime == null then null
    else "${componentRuntime}/portable-component-selection.json";
  hasPortableComponents =
    componentConfiguration != null && componentConfiguration.enabledIds != [ ];
  portableReplacementArg = lib.escapeShellArg (
    if portableReplacementSelection == null then ""
    else toString portableReplacementSelection
  );
  componentRuntimeArg = lib.escapeShellArg (
    if componentRuntime == null then "" else toString componentRuntime
  );
  callableExternalRuntimeArg = lib.escapeShellArg (
    if callableExternalRuntimeContract == null then ""
    else toString callableExternalRuntimeContract
  );
  externalSiteProposalsArg = lib.escapeShellArg (
    if externalSiteProposals == null then ""
    else toString externalSiteProposals
  );
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

      from spaghetti_extractor.machine_import_profiles import (
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

  interpreter = import ./stage-b-interpreter-package.nix {
    inherit pkgs pythonEnv machineIr namePrefix;
    inherit pythonSource;
    inherit allowDeferredPotentialTransfers;
  };

  fallbackCoverageReceipt = import ./stage-b-fallback-coverage-receipt.nix {
    inherit pkgs pythonEnv pythonSource machineIr namePrefix;
    interpreterPackage = interpreter;
    portableReplacements = portableReplacementSelection;
  };

  candidateAuthorityReport = if !staticClosed then null else pkgs.runCommand
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

  candidateAuthorityGate = if !staticClosed then null else pkgs.runCommand
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
    ${lib.optionalString staticClosed ''
      jq -e '
        .format == "spaghetti-extractor-stage-b-candidate-authority-receipt-v3" and
        .status == "authorized"
      ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ''}
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${machineIr}/recovered-executable-data.json \
      ${loadImageContract} \
      ${portableReplacementArg} \
      ${machineImportProfileBundle}/profile.json \
      ${callableExternalRuntimeArg} \
      ${externalSiteProposalsArg} \
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
    machine_ir_manifest = pathlib.Path(sys.argv[2])
    recovered_executable_data = pathlib.Path(sys.argv[3])
    load_contract = pathlib.Path(sys.argv[4])
    portable_path = sys.argv[5]
    profile_bundle = pathlib.Path(sys.argv[6])
    callable_external_path = sys.argv[7]
    external_site_proposals_path = sys.argv[8]
    output = pathlib.Path(sys.argv[9])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[10:])
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
        callable_external_contract=(
            pathlib.Path(callable_external_path)
            if callable_external_path else None
        ),
        external_site_proposals=(
            pathlib.Path(external_site_proposals_path)
            if external_site_proposals_path else None
        ),
        candidate_mode=${builtins.toJSON candidateMode},
        allow_deferred_potential_transfers=${if allowDeferredPotentialTransfers then "True" else "False"},
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
      ${if staticClosed then ".counts.deferred_transfers == 0" else ".counts.deferred_transfers >= 0"} and
      .counts.blockers == 0 and
      .policy.candidate_mode == "${candidateMode}" and
      .policy.static_hybrid_closure_receipt_required == ${if staticClosed then "true" else "false"} and
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
      ${callableExternalRuntimeArg} \
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
        callable_external_contract=(
            pathlib.Path(sys.argv[4]) if sys.argv[4] else None
        ),
        out=pathlib.Path(sys.argv[5]),
    )
    PY
    jq -e '
      .format == "stage-b-native-runtime-package-v1" and
      .status == "ready" and
      .policy.candidate_mode == "${candidateMode}" and
      .policy.static_hybrid_closure_receipt_required == ${if staticClosed then "true" else "false"} and
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
    regionOverridePackage = if hasPortableComponents then componentRuntime else null;
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
    ${lib.optionalString staticClosed ''
      jq -e '
        .format == "spaghetti-extractor-stage-b-candidate-authority-receipt-v3" and
        .status == "authorized"
      ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ''}
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
    from spaghetti_extractor.stage_b_interpreter_native_build import (
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
        component_runtime_package=(
            optional_path(sys.argv[9])
            if ${if staticClosed then "True" else "False"}
            else None
        ),
        region_override_package=optional_path(sys.argv[9]),
        load_image_contract=pathlib.Path(sys.argv[10]),
        recovered_executable_data=pathlib.Path(sys.argv[11]),
        precompiled_objects=pathlib.Path(sys.argv[12]),
        compiler=pathlib.Path(sys.argv[13]),
        diagnostic_failure_trap=${if diagnosticFailureTrap then "True" else "False"},
        candidate_mode=${builtins.toJSON candidateMode},
        out_dir=pathlib.Path(sys.argv[14]),
      )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated" and
      .acceptance_authority == "none" and
      ${if staticClosed then ".inputs.candidate_authority.status == \"authorized\"" else ".inputs.candidate_authority == null"} and
      .inputs.execution_scope.candidate_mode == "${candidateMode}" and
      .inputs.execution_scope.acceptance_authority == "none" and
      .policy.candidate_class == "${if staticClosed then (if diagnosticFailureTrap then "diagnostic-static-closed" else "release-static-closed") else "structural-diagnostic"}"
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
