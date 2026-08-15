# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  original,
  externalProfile,
  additionalMachineImportProfiles ? [ ],
  externalInterfaceProfiles ? [ ],
  launchProfile ? null,
  launchProfileTemplate ? null,
  namePrefix,
  maxUnits ? 512,
  maxCandidatesPerSeed ? 12,
}:

assert !(launchProfile != null && launchProfileTemplate != null);
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
  mkPythonClosure = suffix: modules:
    import ./python-module-closure.nix {
      phaseRole = "proposal";
      inherit pkgs modules;
      name = "${namePrefix}-${suffix}-python-closure";
    };
  inventoryPythonSource = mkPythonClosure "inventory" [
    "spaghetti_extractor.extraction.binary_inventory"
  ];
  staticExportPythonSource = mkPythonClosure "static-export" [
    "spaghetti_extractor.pe32.behavioral_roots"
    "spaghetti_extractor.reconstruction.static_export"
  ];
  rootedControlPythonSource = mkPythonClosure "rooted-control" [
    "spaghetti_extractor.reconstruction.rooted_state_machine"
  ];
  machineIrPreparationPythonSource = mkPythonClosure "machine-ir-preparation" [
    "spaghetti_extractor.reconstruction.ir"
  ];
  machineIrExportPythonSource = mkPythonClosure "machine-ir-export" [
      "spaghetti_extractor.reconstruction.ir"
      "spaghetti_extractor.authority_inputs.finite_values"
    ];
  launchAssumptionProjectionPythonSource = mkPythonClosure
    "launch-assumption-projection" [
      "spaghetti_extractor.authority_inputs.launch_assumptions"
      "spaghetti_extractor.pe32.stage_binary"
    ];
  reconstructionPlanPythonSource = mkPythonClosure "reconstruction-plan" [
    "spaghetti_extractor.reconstruction.plan"
  ];
  machineImportProfiles =
    [ externalProfile ]
    ++ additionalMachineImportProfiles
    ++ externalInterfaceProfiles;
  # Exact extraction depends only on whether a fixed-arity import returns.
  # Full ABI/effect/profile bindings belong to interprocedural and external-site
  # phases.  As a CA artifact this projection retains the same output path when
  # an unrelated returning import contract changes.
  machineImportControlProfile = import ./machine-import-control-profile.nix {
    inherit pkgs pythonEnv;
    profiles = machineImportProfiles;
    name = "${namePrefix}-machine-import-control-dispositions-v1";
  };

  # Structural analysis consumes only explicit machine-state assumptions.  A
  # finalized launch profile also contains roots and callback contracts, which
  # belong to later authority phases and must not invalidate the joint SCC
  # fixed point.  CA realization preserves the same output path when only
  # those ignored fields change.
  launchAssumptionInput =
    if launchProfile != null then launchProfile else launchProfileTemplate;
  launchAnalysisAssumptions =
    if launchAssumptionInput == null then null else
    pkgs.runCommand
      "${namePrefix}-launch-analysis-assumptions-v2"
      commonAttrs
      ''
        set -euo pipefail
        ${commonEnvironment launchAssumptionProjectionPythonSource}
        mkdir -p "$out"
        ${python} - \
          ${lib.escapeShellArg (toString original)} \
          ${lib.escapeShellArg (toString launchAssumptionInput)} \
          "$out/launch-analysis-assumptions-v2.json" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.authority_inputs.launch_assumptions import (
            build_launch_analysis_assumptions_v2,
        )
        from spaghetti_extractor.pe32.stage_binary import _parse_stage_a_pe

        original, source, output = map(pathlib.Path, sys.argv[1:])
        binary = _parse_stage_a_pe(original)
        payload = build_launch_analysis_assumptions_v2(
            json.loads(source.read_text(encoding="utf-8")),
            pe_sha256=binary.sha256,
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
        ).to_payload()
        output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
        jq -e '
          .format == "spaghetti-extractor-launch-analysis-assumptions-v2" and
          .schema_version == 2 and
          (.proof_authority | not) and
          .constraints.root_and_callback_fields_ignored and
          .constraints.final_launch_profile_validation_required and
          (.constraints.original_binary_executed | not) and
          (.assumptions | keys | length) == 6
        ' "$out/launch-analysis-assumptions-v2.json" >/dev/null
      '';

  originalInventory = pkgs.runCommand
    "${namePrefix}-original-inventory-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment inventoryPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg (toString original)} \
        "$out/inventory.json" <<'PY' > "$out/inventory.stdout"
      import pathlib
      import sys
      from spaghetti_extractor.extraction.binary_inventory import (
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
    "${namePrefix}-static-program-export-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment staticExportPythonSource}
      ${python} - \
        ${lib.escapeShellArg (toString original)} \
        ${originalInventory}/inventory.json \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction.static_export import (
          export_static_reconstruction,
      )
      from spaghetti_extractor.pe32.behavioral_roots import generate_behavioral_roots
      from spaghetti_extractor.util import write_json

      original, inventory, output = map(pathlib.Path, sys.argv[1:])
      export_static_reconstruction(
          original=original,
          inventory=inventory,
          out=output,
      )
      write_json(
          output / "behavioral-roots.json",
          generate_behavioral_roots(original),
      )
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "spaghetti-extractor-static-program-export-v1" and
        .status == "ready" and
        .original.sha256 == $expected_sha256 and
        .counts.units > 0 and
        .counts.semantic_transfers == .counts.units and
        .counts.state_machine_transfers == .counts.semantic_transfers and
        (.trust.executes_original_binary | not) and
        (.trust.uses_candidate_binary | not) and
        (.trust.uses_binary_mapping | not) and
        (.trust.claims_whole_program_equivalence | not) and
        .trust.behavioral_reachability_separate
      ' "$out/static-program-export.json" >/dev/null
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-behavioral-roots-v1" and
        .status == "complete" and
        .pe.sha256 == $expected_sha256 and
        .counts.roots == (.roots | length) and
        (.constraints.original_binary_executed | not)
      ' "$out/behavioral-roots.json" >/dev/null
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
      ${commonEnvironment rootedControlPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${inputStateMachine} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/static-program-contract.json \
        ${lib.escapeShellArg (builtins.toJSON [ "${machineImportControlProfile}/control-dispositions.json" ])} \
        ${if controlManifest == null then "-" else "${controlManifest}/machine-ir-manifest.json"} \
        "$out/state-machine.jsonl" \
        "$out/rooted-control-closure.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction.rooted_state_machine import (
          close_state_machine_rooted_direct_control,
      )

      source, original, static_program, profiles_json, control_manifest, output, report = sys.argv[1:]
      close_state_machine_rooted_direct_control(
          state_machine=pathlib.Path(source),
          original_pe=pathlib.Path(original),
          static_program_contract=pathlib.Path(static_program),
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
        (.status == "complete" or .status == "incomplete") and
        .counts.base_transfers > 0 and
        .counts.output_transfers >= .counts.base_transfers and
        (.trust.executes_original_binary | not) and
        .trust.indirect_control_is_not_silently_closed
      ' "$out/rooted-control-closure.json" >/dev/null
    '';

  mkMachineIr = {
    name,
    stateMachineInput,
    preparedMachineIr ? null,
  }: pkgs.runCommand name commonAttrs ''
      set -euo pipefail
      ${commonEnvironment machineIrExportPythonSource}
      ${python} - \
        ${stateMachineInput} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/static-program-contract.json \
        ${if preparedMachineIr == null then "-" else toString preparedMachineIr} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.authority_inputs.finite_values import FiniteU32Dataflow
      from spaghetti_extractor.reconstruction.ir import export_machine_ir_package

      (
          state_machine,
          original,
          static_program,
          prepared_machine_ir,
          output,
      ) = sys.argv[1:]
      export_machine_ir_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          static_program_contract=pathlib.Path(static_program),
          prepared_machine_ir=(
              None
              if prepared_machine_ir == "-"
              else pathlib.Path(prepared_machine_ir)
          ),
          interprocedural_control=False,
          finite_dataflow_factory=FiniteU32Dataflow,
          out=pathlib.Path(output),
      )
      PY
      expected_sha256="$(sha256sum ${lib.escapeShellArg (toString original)} | cut -d ' ' -f 1)"
      if ! jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-machine-ir-v2" and
        (.status == "qualified" or .status == "incomplete" or .status == "violated") and
        .binary.sha256 == $expected_sha256 and
        .counts.units > 0 and .counts.instructions > 0 and
        .counts.prepared_units_reused + .counts.prepared_units_computed ==
          .counts.prepared_input_units and
        .counts.units + .counts.precontrol_excluded_units +
          .control.target_cutpoint_materialization.counts.superseded_input_units ==
          .counts.prepared_input_units + .counts.materialized_target_units and
        .control.counts.roots > 0 and
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
      jq -e --arg expected_sha256 "$expected_sha256" '
        .format == "stage-a-recovered-executable-data-v1" and
        .status == "checked" and
        .original.pe_sha256 == $expected_sha256 and
        (.constraints.original_binary_executed | not) and
        (.constraints.executable_code_bytes_exported | not) and
        .constraints.ranges_are_readable_immutable_initialized_data and
        .constraints.ranges_do_not_overlap_rooted_reachable_transfers and
        .constraints.indirect_dispatch_into_ranges_must_fail_closed and
        .counts.ranges == (.ranges | length) and
        .counts.bytes == ([.ranges[].size] | add // 0)
      ' "$out/recovered-executable-data.json" >/dev/null
    '';

  mkPreparedMachineIr = {
    name,
    stateMachineInput,
    reuse ? null,
  }: pkgs.runCommand name commonAttrs ''
      set -euo pipefail
      ${commonEnvironment machineIrPreparationPythonSource}
      ${python} - \
        ${stateMachineInput} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/static-program-contract.json \
        ${if reuse == null then "-" else toString reuse} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction.ir import (
          prepare_machine_ir_units_package,
      )

      state_machine, original, static_program, reuse, output = sys.argv[1:]
      prepare_machine_ir_units_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          static_program_contract=pathlib.Path(static_program),
          prepared_machine_ir=None if reuse == "-" else pathlib.Path(reuse),
          out=pathlib.Path(output),
      )
      PY
      jq -e '
        .format == "stage-a-prepared-machine-ir-v1" and
        .status == "prepared" and .counts.units > 0 and
        .counts.units_reused + .counts.units_computed == .counts.units and
        (.constraints.original_binary_executed | not) and
        .constraints.unit_bytes_bound_to_original_pe and
        .constraints.prepared_unit_reuse_is_exact_input_hash_bound
      ' "$out/prepared-machine-ir-manifest.json" >/dev/null
    '';

  # Exact decode is prepared once. Dependency closure and induction belong to
  # the content-addressed native v3 authority graph, not this extraction phase.
  directStateMachine = mkRootedStateMachine {
    name = "${namePrefix}-direct-rooted-state-machine-v1";
    inputStateMachine = "${staticExport}/state-machine.jsonl";
  };

  directPreparedMachineIr = mkPreparedMachineIr {
    name = "${namePrefix}-direct-prepared-machine-ir-v1";
    stateMachineInput = "${directStateMachine}/state-machine.jsonl";
  };

  machineIr = mkMachineIr {
    name = "${namePrefix}-machine-ir-v2";
    stateMachineInput = "${directStateMachine}/state-machine.jsonl";
    preparedMachineIr = directPreparedMachineIr;
  };

  provisionalMachineIr = machineIr;
  stateMachine = directStateMachine;
  preparedMachineIr = directPreparedMachineIr;

  reconstructionPlan = pkgs.runCommand
    "${namePrefix}-reconstruction-plan-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${commonEnvironment reconstructionPlanPythonSource}
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${lib.escapeShellArg (toString externalProfile)} \
        "$out/reconstruction-plan.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction.plan import (
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
    reconstructionPlan = reconstructionPlan;
    inherit namePrefix maxUnits maxCandidatesPerSeed;
  };
in
{
  inherit
    originalInventory
    staticExport
    machineImportControlProfile
    launchAnalysisAssumptions
    directStateMachine
    directPreparedMachineIr
    provisionalMachineIr
    stateMachine
    preparedMachineIr
    machineIr
    reconstructionPlan
    componentProposals
    ;
}
