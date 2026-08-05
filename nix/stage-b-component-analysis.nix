{
  pkgs,
  pythonEnv,
  pythonSource,
  staticPythonSource ? pythonSource,
  planningPythonSource ? pythonSource,
  componentDiscoveryPythonSource ? pythonSource,
  original,
  externalProfile,
  externalInterfaceProfiles ? [ ],
  externalOperationProfiles ? [ ],
  indirectTargetProfile ? null,
  namePrefix,
  maxUnits ? 512,
  maxCandidatesPerSeed ? 12,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  commonAttrs = {
    nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };
  commonEnvironment = source: ''
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${source}/src
  '';
  machineImportProfiles = [ externalProfile ] ++ externalInterfaceProfiles;
  machineImportProfilesJson = builtins.toJSON (
    map toString machineImportProfiles
  );
  externalInterfaceProfilesJson = builtins.toJSON (
    map toString externalInterfaceProfiles
  );
  externalOperationProfilesJson = builtins.toJSON (
    map toString externalOperationProfiles
  );

  originalInventory = pkgs.runCommand
    "${namePrefix}-original-inventory-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg (toString original)} \
        "$out/inventory.json" <<'PY' > "$out/inventory.stdout"
      import pathlib
      import sys
      from spaghetti_extractor.analysis.binary_inventory import (
          stage_a_inventory_binary,
      )

      print(stage_a_inventory_binary(
          binary=pathlib.Path(sys.argv[1]),
          linker_map=None,
          side="original",
          out=pathlib.Path(sys.argv[2]),
      ))
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-binary-cutpoint-inventory-v1" and
        .status == "pass" and .side == "original" and
        .binary_sha256 == $expected_sha256 and
        .counts.issues == 0 and .counts.regions > 0 and
        .counts.extraction_regions >= .counts.regions
      ' "$out/inventory.json" >/dev/null
    '';

  staticExport = pkgs.runCommand
    "${namePrefix}-opaque-static-export-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      ${python} - \
        ${lib.escapeShellArg (toString original)} \
        ${originalInventory}/inventory.json \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.opaque_reconstruction import (
          stage_a_export_opaque_reconstruction,
      )

      original, inventory, output = map(pathlib.Path, sys.argv[1:])
      stage_a_export_opaque_reconstruction(
          original=original,
          inventory=inventory,
          out=output,
      )
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-opaque-static-export-v1" and
        .status == "ready" and
        .original.sha256 == $expected_sha256 and
        .counts.regions > 0 and .counts.transfers == .counts.regions and
        (.trust.executes_original_binary | not) and
        (.trust.uses_linker_map | not) and
        (.trust.uses_symbols_for_authority | not) and
        .trust.includes_all_recovered_code and
        (.trust.reference_contract_is_formal_acceptance | not)
      ' "$out/opaque-static-export.json" >/dev/null
    '';

  mkRootedStateMachine = {
    name,
    inputStateMachine,
    controlManifest ? null,
  }: pkgs.runCommand
    name
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${inputStateMachine} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/reference-contract.json \
        ${lib.escapeShellArg machineImportProfilesJson} \
        ${if controlManifest == null then "-" else "${controlManifest}/machine-ir-manifest.json"} \
        "$out/state-machine.jsonl" \
        "$out/rooted-control-closure.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.rooted_state_machine import (
          close_state_machine_rooted_direct_control,
      )

      source, original, reference, profiles_json, control_manifest, output, report = sys.argv[1:]
      close_state_machine_rooted_direct_control(
          state_machine=pathlib.Path(source),
          original_pe=pathlib.Path(original),
          reference_contract=pathlib.Path(reference),
          machine_import_profiles=tuple(
              pathlib.Path(path) for path in json.loads(profiles_json)
          ),
          control_manifest=(
              None if control_manifest == "-" else pathlib.Path(control_manifest)
          ),
          out=pathlib.Path(output),
          report=pathlib.Path(report),
      )
      PY
      jq -e '
        .format == "stage-b-rooted-static-control-closure-v1" and
        .status == "complete" and
        .counts.base_transfers > 0 and
        .counts.output_transfers >= .counts.base_transfers and
        .counts.remaining_missing_direct_targets == 0 and
        (.trust.executes_original_binary | not) and
        .trust.indirect_control_is_not_silently_closed
      ' "$out/rooted-control-closure.json" >/dev/null
    '';

  mkMachineIr = {
    name,
    stateMachineInput,
    requireClosedRootedDirect,
  }: pkgs.runCommand name commonAttrs ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      ${python} - \
        ${stateMachineInput} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/reference-contract.json \
        ${if indirectTargetProfile == null then "-" else lib.escapeShellArg (toString indirectTargetProfile)} \
        ${lib.escapeShellArg machineImportProfilesJson} \
        ${lib.escapeShellArg externalInterfaceProfilesJson} \
        ${lib.escapeShellArg externalOperationProfilesJson} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      (
          state_machine,
          original,
          reference,
          target_profile,
          machine_profiles_json,
          interface_profiles_json,
          operation_profiles_json,
          output,
      ) = sys.argv[1:]
      export_machine_ir_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          reference_contract=pathlib.Path(reference),
          indirect_target_profile=(
              None if target_profile == "-" else pathlib.Path(target_profile)
          ),
          machine_import_profiles=tuple(
              pathlib.Path(path) for path in json.loads(machine_profiles_json)
          ),
          external_interface_profiles=tuple(
              pathlib.Path(path) for path in json.loads(interface_profiles_json)
          ),
          external_operation_profiles=tuple(
              pathlib.Path(path) for path in json.loads(operation_profiles_json)
          ),
          out=pathlib.Path(output),
      )
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      if ! jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-machine-ir-v2" and
        (.status == "qualified" or .status == "incomplete") and
        .binary.sha256 == $expected_sha256 and
        .counts.units > 0 and .counts.instructions > 0 and
        .counts.violated_issues == 0 and
        .coverage.counts.unknown_bytes == 0 and
        .control.counts.roots > 0 and
        ${if requireClosedRootedDirect then ''
          ([.control.reachability.frontiers[] |
            select(.reason == "unresolved_direct_target" or
                   .reason == "unresolved_internal_call_target")] | length) == 0 and
        '' else ""}
        (.authority | contains("no original execution"))
      ' "$out/machine-ir-manifest.json" >/dev/null; then
        jq '{
          status,
          counts,
          coverage: .coverage.counts,
          control: .control.counts,
          reachability: {
            status: .control.reachability.status,
            counts: .control.reachability.counts,
            direct_frontiers: [
              .control.reachability.frontiers[] |
              select(.reason == "unresolved_direct_target" or
                     .reason == "unresolved_internal_call_target")
            ][0:16]
          }
        }' "$out/machine-ir-manifest.json" >&2
        exit 1
      fi
    '';

  # Direct recursive decoding is cheap.  Provenance analysis is expensive but
  # cached as its own derivation, and proposes the additional rooted targets
  # needed by the final exact decode.  The final IR then checks the closed
  # state-machine artifact independently.
  directStateMachine = mkRootedStateMachine {
    name = "${namePrefix}-direct-rooted-state-machine-v1";
    inputStateMachine = "${staticExport}/state-machine.jsonl";
  };

  provisionalMachineIr = mkMachineIr {
    name = "${namePrefix}-provisional-machine-ir-v2";
    stateMachineInput = "${directStateMachine}/state-machine.jsonl";
    requireClosedRootedDirect = false;
  };

  stateMachine = mkRootedStateMachine {
    name = "${namePrefix}-rooted-state-machine-v1";
    inputStateMachine = "${directStateMachine}/state-machine.jsonl";
    controlManifest = provisionalMachineIr;
  };

  machineIr = mkMachineIr {
    name = "${namePrefix}-machine-ir-v2";
    stateMachineInput = "${stateMachine}/state-machine.jsonl";
    requireClosedRootedDirect = true;
  };

  reconstructionPlan = pkgs.runCommand
    "${namePrefix}-reconstruction-plan-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment planningPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${lib.escapeShellArg (toString externalProfile)} \
        "$out/reconstruction-plan.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.component_backend import (
          write_reconstruction_plan,
      )

      machine_ir, profile, output = map(pathlib.Path, sys.argv[1:])
      write_reconstruction_plan(
          machine_ir=machine_ir,
          signature_catalog=profile,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-b-reconstruction-plan-v1" and
        (.status == "qualified" or .status == "incomplete") and
        .counts.clusters > 0 and
        .control_analysis.reachability_status != null and
        (.executes_original_binary | not)
      ' "$out/reconstruction-plan.json" >/dev/null
    '';

  componentProposals = import ./stage-b-component-discovery.nix {
    inherit pkgs pythonEnv machineIr;
    pythonSource = componentDiscoveryPythonSource;
    reconstructionPlan = reconstructionPlan;
    inherit namePrefix maxUnits maxCandidatesPerSeed;
  };
in
{
  inherit
    originalInventory
    staticExport
    directStateMachine
    provisionalMachineIr
    stateMachine
    machineIr
    reconstructionPlan
    componentProposals
    ;
}
