{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  staticCompletenessReport,
  staticAuthorityV2,
  machineImportProfiles,
  namePrefix,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  allowDeferredPotentialTransfers ? false,
  diagnosticFailureTrap ? false,
  portableReplacements ? null,
}:

assert pkgs.lib.assertMsg (!allowDeferredPotentialTransfers)
  "static-hybrid candidates require allowDeferredPotentialTransfers = false";

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
  fallbackCoveragePythonSource = mkPythonClosure "fallback-coverage" [
    "spaghetti_extractor.stage_b_fallback_coverage"
  ];
  candidateAuthorityPythonSource = mkPythonClosure "candidate-authority-v2" [
    "spaghetti_extractor.stage_b_candidate_authority_v2"
  ];
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  portableReplacementSelection =
    if portableReplacements == null then null
    else if builtins.isList portableReplacements then
      pkgs.writeText "${namePrefix}-portable-replacements-v1.json"
        (builtins.toJSON {
          format = "stage-b-portable-replacement-selection-v1";
          replacements = portableReplacements;
        })
    else portableReplacements;
  portableReplacementArg = lib.escapeShellArg (
    if portableReplacementSelection == null then ""
    else toString portableReplacementSelection
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

  fallbackCoverageReceipt = pkgs.runCommand
    "${namePrefix}-fallback-coverage-receipt-v2"
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
      export PYTHONPATH=${fallbackCoveragePythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${machineIr}/machine-ir.jsonl \
        ${machineIr}/machine-ir-manifest.json \
        ${interpreter} \
        ${portableReplacementArg} \
        "$out/fallback-coverage-receipt.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.stage_b_fallback_coverage import (
          write_stage_b_fallback_coverage_receipt,
      )

      machine_ir, manifest, interpreter, portable, output = sys.argv[1:]
      write_stage_b_fallback_coverage_receipt(
          machine_ir=pathlib.Path(machine_ir),
          machine_ir_manifest=pathlib.Path(manifest),
          interpreter_package=pathlib.Path(interpreter),
          portable_replacements=(pathlib.Path(portable) if portable else None),
          out=pathlib.Path(output),
      )
      PY
      jq -e '
        .format == "stage-b-fallback-coverage-receipt-v2" and
        .status == "complete" and
        (.authority | contains("no behavioral acceptance authority")) and
        .policy.rooted_reachable_units_require_lowering and
        .policy.one_implementation_kind_per_reachable_unit and
        .counts.rooted_reachable_units == .counts.implementation_entries and
        .counts.blockers == 0
      ' "$out/fallback-coverage-receipt.json" >/dev/null
    '';

  candidateAuthorityReport = pkgs.runCommand
    "${namePrefix}-candidate-authority-v2"
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
        ${staticAuthorityV2.finalAudit.artifact} \
        ${staticAuthorityV2.authorityBundle.artifact} \
        ${machineIr}/machine-ir.jsonl \
        ${machineIr}/machine-ir-manifest.json \
        ${fallbackCoverageReceipt}/fallback-coverage-receipt.json \
        ${staticCompletenessReport}/static-hybrid-completeness.json \
        "$out/candidate-authority.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.stage_b_candidate_authority_v2 import (
          build_stage_b_candidate_authority_v2,
      )

      (
          final_audit,
          authority_bundle,
          machine_ir,
          manifest,
          fallback_receipt,
          legacy_report,
          output,
      ) = sys.argv[1:]
      receipt = build_stage_b_candidate_authority_v2(
          final_static_hybrid_audit=pathlib.Path(final_audit),
          authority_bundle=pathlib.Path(authority_bundle),
          machine_ir=pathlib.Path(machine_ir),
          machine_ir_manifest=pathlib.Path(manifest),
          fallback_coverage_receipt=pathlib.Path(fallback_receipt),
          legacy_diagnostic_artifacts=(pathlib.Path(legacy_report),),
      )
      pathlib.Path(output).write_text(receipt.to_json(), encoding="ascii")
      PY
      jq -e '
        .format == "spaghetti-extractor-stage-b-candidate-authority-v2" and
        (.status == "authorized" or .status == "incomplete" or .status == "violated") and
        (.policy.v1_authority_accepted | not) and
        .policy.v2_static_audit_required and
        .policy.candidate_generation_fails_closed
      ' "$out/candidate-authority.json" >/dev/null
    '';

  candidateAuthorityGate = pkgs.runCommand
    "${namePrefix}-candidate-authority-gate-v2"
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
      from spaghetti_extractor.stage_b_candidate_authority_v2 import (
          parse_stage_b_candidate_authority_v2,
          require_stage_b_candidate_authority_v2,
      )

      source, output = map(pathlib.Path, sys.argv[1:])
      receipt = require_stage_b_candidate_authority_v2(
          parse_stage_b_candidate_authority_v2(source.read_bytes())
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
      .format == "spaghetti-extractor-stage-b-candidate-authority-v2" and
      .status == "authorized"
    ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${machineIr}/recovered-executable-data.json \
      ${loadImageContract} \
      ${portableReplacementArg} \
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
    output = pathlib.Path(sys.argv[6])
    profiles = tuple(pathlib.Path(value) for value in sys.argv[7:])
    selected_portable_components = ()
    if portable_path:
        portable_payload = json.loads(
            pathlib.Path(portable_path).read_text(encoding="utf-8")
        )
        selected_portable_components = (
            portable_payload["replacements"]
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
      .counts.deferred_transfers == 0 and
      .counts.blockers == 0 and
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
    jq -e '
      .format == "spaghetti-extractor-stage-b-candidate-authority-v2" and
      .status == "authorized"
    ' ${candidateAuthorityGate}/candidate-authority.json >/dev/null
    ${python} - \
      ${interpreter} ${nativeEngine} ${nativeRuntime} \
      ${candidateAuthorityGate}/candidate-authority.json \
      ${staticAuthorityV2.finalAudit.artifact} \
      ${staticAuthorityV2.authorityBundle.artifact} \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${fallbackCoverageReceipt}/fallback-coverage-receipt.json \
      ${loadImageContract} \
      ${machineIr}/recovered-executable-data.json \
      ${nativeObjects.package} \
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
        candidate_authority=pathlib.Path(sys.argv[4]),
        final_static_hybrid_audit=pathlib.Path(sys.argv[5]),
        authority_bundle=pathlib.Path(sys.argv[6]),
        machine_ir=pathlib.Path(sys.argv[7]),
        machine_ir_manifest=pathlib.Path(sys.argv[8]),
        fallback_coverage_receipt=pathlib.Path(sys.argv[9]),
        load_image_contract=pathlib.Path(sys.argv[10]),
        recovered_executable_data=pathlib.Path(sys.argv[11]),
        precompiled_objects=pathlib.Path(sys.argv[12]),
        compiler=pathlib.Path(sys.argv[13]),
        diagnostic_failure_trap=${if diagnosticFailureTrap then "True" else "False"},
        out_dir=pathlib.Path(sys.argv[14]),
      )
    PY
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated" and
      .acceptance_authority == "none" and
      .inputs.candidate_authority.status == "authorized" and
      (.policy.allow_deferred_potential_transfers | not) and
      .policy.candidate_class == "${if diagnosticFailureTrap then "diagnostic-static-closed" else "release-static-closed"}"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
  '';
in
{
  inherit
    interpreter
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
