{
  pkgs,
  pythonEnv,
  sideTool,
  staticPythonSource,
  planningPythonSource,
  componentDiscoveryPythonSource,
  original,
  externalProfile,
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

  originalInventory = pkgs.runCommand
    "${namePrefix}-original-inventory-v1"
    (commonAttrs // { nativeBuildInputs = [ sideTool pkgs.jq pkgs.coreutils ]; })
    ''
      set -euo pipefail
      mkdir -p "$out"
      spaghetti-extractor-side inventory-binary \
        --binary ${lib.escapeShellArg (toString original)} \
        --side original \
        --out "$out/inventory.json" \
        > "$out/inventory.stdout"
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

  stateMachine = pkgs.runCommand
    "${namePrefix}-opaque-state-machine-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${staticExport}/state-machine.jsonl \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/opaque-self-map.json \
        ${lib.escapeShellArg (toString externalProfile)} \
        "$out/state-machine.jsonl" \
        "$out/padding-bridges.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_state_machine import (
          augment_state_machine_with_padding_bridges,
      )
      from spaghetti_extractor.util import write_json

      source, original, block_map, profile, output, report = map(
          pathlib.Path, sys.argv[1:]
      )
      result = augment_state_machine_with_padding_bridges(
          state_machine=source,
          original_pe=original,
          block_map=block_map,
          external_profile=profile,
          out=output,
      )
      write_json(report, {
          "format": "stage-b-padding-bridge-augmentation-v1",
          "status": "complete",
          "state_machine": {"path": output.name, "sha256": result.sha256},
          "counts": {
              "input_transfers": result.input_transfer_count,
              "padding_bridges": result.padding_bridge_count,
              "output_transfers": result.output_transfer_count,
              "terminating_transfers": len(result.terminating_transfer_rvas),
          },
          "bridged_rvas": list(result.bridged_rvas),
          "terminating_transfer_rvas": list(result.terminating_transfer_rvas),
          "trust": {
              "executes_original_binary": False,
              "external_termination_profile_bound": True,
          },
      })
      PY
      jq -e '
        .format == "stage-b-padding-bridge-augmentation-v1" and
        .status == "complete" and
        .counts.input_transfers > 0 and
        .counts.output_transfers >= .counts.input_transfers and
        (.trust.executes_original_binary | not) and
        .trust.external_termination_profile_bound
      ' "$out/padding-bridges.json" >/dev/null
    '';

  machineIr = pkgs.runCommand
    "${namePrefix}-machine-ir-v2"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticPythonSource}
      ${python} - \
        ${stateMachine}/state-machine.jsonl \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/reference-contract.json \
        ${if indirectTargetProfile == null then "-" else lib.escapeShellArg (toString indirectTargetProfile)} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      state_machine, original, reference, target_profile, output = sys.argv[1:]
      export_machine_ir_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          reference_contract=pathlib.Path(reference),
          indirect_target_profile=(
              None if target_profile == "-" else pathlib.Path(target_profile)
          ),
          out=pathlib.Path(output),
      )
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-machine-ir-v2" and
        (.status == "qualified" or .status == "incomplete") and
        .binary.sha256 == $expected_sha256 and
        .counts.units > 0 and .counts.instructions > 0 and
        .counts.violated_issues == 0 and
        .coverage.counts.unknown_bytes == 0 and
        .control.counts.roots > 0 and
        .control.counts.unresolved_direct_targets == 0 and
        (.authority | contains("no original execution"))
      ' "$out/machine-ir-manifest.json" >/dev/null
    '';

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
      from spaghetti_extractor.reconstruction_workspace import (
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
    stateMachine
    machineIr
    reconstructionPlan
    componentProposals
    ;
}
