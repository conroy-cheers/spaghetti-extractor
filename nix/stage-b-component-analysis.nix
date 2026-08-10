{
  pkgs,
  pythonEnv,
  pythonSource,
  staticPythonSource ? pythonSource,
  planningPythonSource ? pythonSource,
  componentDiscoveryPythonSource ? pythonSource,
  isaPythonSource ? pythonSource,
  original,
  externalProfile,
  additionalMachineImportProfiles ? [ ],
  externalInterfaceProfiles ? [ ],
  externalOperationProfiles ? [ ],
  callableExternalProfiles ? [ ],
  internalFunctionContractProfiles ? [ ],
  indirectTargetProfile ? null,
  checkedExternalSites ? null,
  launchProfile ? null,
  launchProfileTemplate ? null,
  isaSelectionAuthority ? null,
  exceptionCertificates ? null,
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
  mkPythonClosure = source: suffix: modules:
    import ./python-module-closure.nix {
      inherit pkgs source modules;
      name = "${namePrefix}-${suffix}-python-closure";
    };
  inventoryPythonSource = mkPythonClosure staticPythonSource "inventory" [
    "spaghetti_extractor.analysis.binary_inventory"
  ];
  staticExportPythonSource = mkPythonClosure staticPythonSource "static-export" [
    "spaghetti_extractor.behavioral_roots"
    "spaghetti_extractor.opaque_reconstruction"
  ];
  rootedControlPythonSource = mkPythonClosure staticPythonSource "rooted-control" [
    "spaghetti_extractor.rooted_state_machine"
  ];
  machineIrPythonSource = mkPythonClosure staticPythonSource "machine-ir" [
    "spaghetti_extractor.reconstruction_ir"
  ];
  reconstructionPlanPythonSource = mkPythonClosure planningPythonSource "reconstruction-plan" [
    "spaghetti_extractor.component_backend"
  ];
  machineImportProfiles =
    [ externalProfile ]
    ++ additionalMachineImportProfiles
    ++ externalInterfaceProfiles;
  machineImportProfilesJson = builtins.toJSON (
    map toString machineImportProfiles
  );
  externalInterfaceProfilesJson = builtins.toJSON (
    map toString externalInterfaceProfiles
  );
  externalOperationProfilesJson = builtins.toJSON (
    map toString externalOperationProfiles
  );
  callableExternalProfilesJson = builtins.toJSON (
    map toString callableExternalProfiles
  );
  internalFunctionContractProfilesJson = builtins.toJSON (
    map toString internalFunctionContractProfiles
  );
  selectedProfileInventory = pkgs.writeText
    "${namePrefix}-selected-profile-inventory-v2.json"
    (builtins.toJSON {
      format = "spaghetti-extractor-selected-profile-inventory-v2";
      machine_import_profiles = map toString machineImportProfiles;
      external_interface_profiles = map toString externalInterfaceProfiles;
      external_operation_profiles = map toString externalOperationProfiles;
      callable_external_profiles = map toString callableExternalProfiles;
      internal_function_contract_profiles =
        map toString internalFunctionContractProfiles;
    });

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
      ${commonEnvironment staticExportPythonSource}
      ${python} - \
        ${lib.escapeShellArg (toString original)} \
        ${originalInventory}/inventory.json \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.opaque_reconstruction import (
          stage_a_export_opaque_reconstruction,
      )
      from spaghetti_extractor.behavioral_roots import generate_behavioral_roots
      from spaghetti_extractor.util import write_json

      original, inventory, output = map(pathlib.Path, sys.argv[1:])
      stage_a_export_opaque_reconstruction(
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
      ${commonEnvironment machineIrPythonSource}
      ${python} - \
        ${stateMachineInput} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/reference-contract.json \
        ${if preparedMachineIr == null then "-" else toString preparedMachineIr} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      (
          state_machine,
          original,
          reference,
          prepared_machine_ir,
          output,
      ) = sys.argv[1:]
      export_machine_ir_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          reference_contract=pathlib.Path(reference),
          prepared_machine_ir=(
              None
              if prepared_machine_ir == "-"
              else pathlib.Path(prepared_machine_ir)
          ),
          interprocedural_control=False,
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
      ${commonEnvironment machineIrPythonSource}
      ${python} - \
        ${stateMachineInput} \
        ${lib.escapeShellArg (toString original)} \
        ${staticExport}/reference-contract.json \
        ${if reuse == null then "-" else toString reuse} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import (
          prepare_machine_ir_units_package,
      )

      state_machine, original, reference, reuse, output = sys.argv[1:]
      prepare_machine_ir_units_package(
          state_machine=pathlib.Path(state_machine),
          original_pe=pathlib.Path(original),
          reference_contract=pathlib.Path(reference),
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

  # Exact decode is prepared once. Interprocedural closure belongs exclusively
  # to the content-addressed v2 SCC phase below.
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

  staticHybridCompleteness = import ./stage-b-static-hybrid-completeness.nix {
    inherit pkgs pythonEnv machineIr namePrefix;
    inherit pythonSource machineImportProfiles externalInterfaceProfiles;
    inherit original;
    behavioralRoots = "${staticExport}/behavioral-roots.json";
    loadImageContract = "${staticExport}/load-image-contract.json";
  };

  # The v1 report remains useful diagnostic input, but none of its status
  # fields authorize these phases.  Every v2 producer below replays the exact
  # artifact it owns and emits incomplete when its checked producer is absent.
  staticHybridAuthorityV2 = import ./stage-b-static-hybrid-authority-v2.nix {
    inherit pkgs pythonEnv pythonSource namePrefix;
    phases = {
      exactUnitPrep = {
        derivationSuffix = "exact-unit-prep-v2";
        kind = "exact-unit-prep";
        artifactName = "exact-unit-prep.json";
        expectedFormat = "spaghetti-extractor-exact-unit-preparation-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.machine_ir_authority_v2" ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
          prepared_manifest =
            "${preparedMachineIr}/prepared-machine-ir-manifest.json";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.machine_ir_authority_v2 import (
              build_machine_ir_authority_bindings,
          )

          def read_object(path):
              value = json.loads(path.read_text(encoding="utf-8"))
              if not isinstance(value, dict):
                  raise ValueError(f"{path.name} is not a JSON object")
              return value

          issues = []
          rows = []
          for line_number, line in enumerate(
              inputs["machine_ir"].read_text(encoding="utf-8").splitlines(), 1
          ):
              if not line.strip():
                  continue
              row = json.loads(line)
              if not isinstance(row, dict):
                  issues.append({"status": "violated", "code": "unit_not_object", "line": line_number})
                  continue
              rows.append(row)
          manifest = read_object(inputs["machine_ir_manifest"])
          prepared = read_object(inputs["prepared_manifest"])
          pe_sha256 = hashlib.sha256(inputs["original_pe"].read_bytes()).hexdigest()
          machine_ir_sha256 = hashlib.sha256(inputs["machine_ir"].read_bytes()).hexdigest()
          if manifest.get("format") != "stage-a-machine-ir-v2":
              issues.append({"status": "violated", "code": "machine_ir_manifest_format"})
          if prepared.get("format") != "stage-a-prepared-machine-ir-v1":
              issues.append({"status": "violated", "code": "prepared_manifest_format"})
          if manifest.get("binary", {}).get("sha256") != pe_sha256:
              issues.append({"status": "violated", "code": "binary_hash_mismatch"})
          if manifest.get("artifacts", {}).get("machine_ir", {}).get("sha256") != machine_ir_sha256:
              issues.append({"status": "violated", "code": "machine_ir_hash_mismatch"})
          expected_bindings = build_machine_ir_authority_bindings(
              rows, pe_sha256=pe_sha256
          )
          observed_bindings = manifest.get("authority_bindings")
          if observed_bindings is None:
              issues.append({"status": "incomplete", "code": "v2_authority_bindings_missing"})
          elif observed_bindings != expected_bindings:
              issues.append({"status": "violated", "code": "v2_authority_bindings_stale"})
          status = (
              "violated" if any(row["status"] == "violated" for row in issues)
              else "incomplete" if issues else "complete"
          )
          payload = {
              "format": "spaghetti-extractor-exact-unit-preparation-v2",
              "status": status,
              "binary": {"sha256": pe_sha256},
              "machine_ir": {"sha256": machine_ir_sha256, "units": len(rows)},
              "authority_bindings": expected_bindings,
              "issues": sorted(issues, key=lambda row: (row["status"], row["code"])),
          }
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      baseGraph = {
        derivationSuffix = "base-graph-v2";
        kind = "base-graph";
        artifactName = "base-graph.json";
        expectedFormat = "stage-a-rooted-control-graph-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.control_analysis_v2" ];
        inputs = {
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
          behavioral_roots = "${staticExport}/behavioral-roots.json";
        };
        program = ''
          from spaghetti_extractor.control_analysis_v2 import (
              derive_rooted_control_graph_v2,
          )

          rows = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          payload = derive_rooted_control_graph_v2(
              rows=rows,
              manifest=json.loads(
                  inputs["machine_ir_manifest"].read_text(encoding="utf-8")
              ),
              behavioral_roots=json.loads(
                  inputs["behavioral_roots"].read_text(encoding="utf-8")
              ),
          )
          exact = json.loads(
              inputs["exact_unit_prep"].read_text(encoding="utf-8")
          )
          if exact.get("status") != "complete":
              payload["status"] = (
                  "violated"
                  if exact.get("status") == "violated"
                  else "incomplete"
              )
              payload.setdefault("issues", []).append({
                  "status": payload["status"],
                  "code": "exact_unit_prep_not_complete",
              })
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      interproceduralSeed = {
        derivationSuffix = "interprocedural-seed-v2";
        kind = "interprocedural-seed-v2";
        artifactName = "interprocedural-seed-v2.json";
        expectedFormat = "stage-a-interprocedural-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.interprocedural_phase_v2"
          "spaghetti_extractor.internal_function_contracts"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
          selected_profiles = selectedProfileInventory;
        };
        program = ''
          import hashlib

          from spaghetti_extractor.external_capabilities import load_callable_external_profile
          from spaghetti_extractor.external_interface_profiles import load_external_interface_profile
          from spaghetti_extractor.external_operation_profiles import load_external_operation_profile
          from spaghetti_extractor.import_abi import load_selected_import_abis
          from spaghetti_extractor.internal_function_contracts import load_internal_function_contracts
          from spaghetti_extractor.interprocedural_phase_v2 import derive_interprocedural_result_v2
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          manifest = json.loads(inputs["machine_ir_manifest"].read_text(encoding="utf-8"))
          graph = json.loads(inputs["base_graph"].read_text(encoding="utf-8"))
          inventory = json.loads(inputs["selected_profiles"].read_text(encoding="utf-8"))
          binary = _parse_stage_a_pe(inputs["original_pe"])
          machine_ir_sha256 = hashlib.sha256(
              inputs["machine_ir"].read_bytes()
          ).hexdigest()
          internal_paths = tuple(
              pathlib.Path(path)
              for path in inventory["internal_function_contract_profiles"]
          )
          payload = derive_interprocedural_result_v2(
              manifest,
              units=units,
              graph=graph,
              binary=binary,
              machine_ir_sha256=machine_ir_sha256,
              global_slot_invariants=[],
              import_abis=load_selected_import_abis(
                  tuple(
                      pathlib.Path(path)
                      for path in inventory["machine_import_profiles"]
                  )
              ),
              interface_profiles=tuple(
                  load_external_interface_profile(path)
                  for path in inventory["external_interface_profiles"]
              ),
              operation_profiles=tuple(
                  load_external_operation_profile(path)
                  for path in inventory["external_operation_profiles"]
              ),
              callable_profiles=tuple(
                  load_callable_external_profile(path)
                  for path in inventory["callable_external_profiles"]
              ),
              internal_function_contracts=(
                  None
                  if not internal_paths
                  else load_internal_function_contracts(
                      internal_paths,
                      binary_sha256=binary.sha256,
                      units=units,
                  )
              ),
              static_recoveries=None,
              proposal_only=True,
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      controlInvariantCertificates = {
        derivationSuffix = "control-invariants-v2";
        kind = "control-invariants-v2";
        artifactName = "control-invariants-v2.json";
        expectedFormat = "spaghetti-extractor-control-invariant-phase-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.control_invariant_phase_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.control_invariant_phase_v2 import (
              derive_checked_control_invariants_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          payload = derive_checked_control_invariants_v2(
              units=units,
              binary=_parse_stage_a_pe(inputs["original_pe"]),
              machine_ir_sha256=hashlib.sha256(
                  inputs["machine_ir"].read_bytes()
              ).hexdigest(),
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      memoryRangeInvariants = {
        derivationSuffix = "memory-range-invariants-v2";
        kind = "memory-range-invariants-v2";
        artifactName = "memory-range-invariants-v2.json";
        expectedFormat = "spaghetti-extractor-memory-range-invariants-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.memory_range_invariants_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.memory_range_invariants_v2 import (
              derive_memory_range_invariants_v2,
          )

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          payload = derive_memory_range_invariants_v2(
              units=units,
              binary_sha256=hashlib.sha256(
                  inputs["original_pe"].read_bytes()
              ).hexdigest(),
              machine_ir_sha256=hashlib.sha256(
                  inputs["machine_ir"].read_bytes()
              ).hexdigest(),
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      jointInterproceduralV2 = {
        derivationSuffix = "joint-interprocedural-v2";
        kind = "joint-interprocedural-v2";
        artifactName = "joint-interprocedural-v2.json";
        expectedFormat = "spaghetti-extractor-joint-interprocedural-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.checked_memory_address_domain_v2"
          "spaghetti_extractor.global_slot_analysis_v2"
          "spaghetti_extractor.global_slot_authority_v2"
          "spaghetti_extractor.interprocedural_phase_v2"
          "spaghetti_extractor.joint_fixed_point_v2"
          "spaghetti_extractor.joint_interprocedural_analysis_v2"
          "spaghetti_extractor.launch_profile_v2"
          "spaghetti_extractor.memory_range_invariants_v2"
          "spaghetti_extractor.mutable_slot_candidates_v2"
          "spaghetti_extractor.internal_function_contracts"
          "spaghetti_extractor.stack_range_analysis_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
          selected_profiles = selectedProfileInventory;
        } // lib.optionalAttrs (launchProfile != null) {
          launch_profile = launchProfile;
        } // lib.optionalAttrs (launchProfileTemplate != null) {
          launch_profile_template = launchProfileTemplate;
        };
        program = ''
          import hashlib
          import sys
          import time

          from spaghetti_extractor.control_analysis_v2 import (
              derive_rooted_control_closure_v2,
              exact_control_inventory_v2,
          )
          from spaghetti_extractor.artifact_identity_v2 import canonical_sha256
          from spaghetti_extractor.external_capabilities import load_callable_external_profile
          from spaghetti_extractor.external_interface_profiles import load_external_interface_profile
          from spaghetti_extractor.external_operation_profiles import load_external_operation_profile
          from spaghetti_extractor.global_slot_analysis_v2 import analyze_global_slots_v2
          from spaghetti_extractor.global_slot_authority_v2 import (
              replay_global_slot_authority_v2,
          )
          from spaghetti_extractor.global_slot_image_v2 import (
              GlobalSlotImageV2Error,
              loader_initial_bytes_v2,
          )
          from spaghetti_extractor.import_abi import load_selected_import_abis
          from spaghetti_extractor.internal_function_contracts import load_internal_function_contracts
          from spaghetti_extractor.interprocedural_phase_v2 import derive_interprocedural_result_v2
          from spaghetti_extractor.joint_fixed_point_v2 import (
              JointFixedPointCallbacks,
              derive_joint_fixed_point_v2,
          )
          from spaghetti_extractor.joint_interprocedural_analysis_v2 import (
              build_proposal_control_graph_v2,
              merge_recovery_proposals_v2,
          )
          from spaghetti_extractor.launch_profile_v2 import (
              parse_launch_assumption_template_v1,
              parse_launch_profile_v2,
          )
          from spaghetti_extractor.mutable_slot_candidates_v2 import (
              derive_dependency_scoped_slot_inventory_v2,
              derive_mutable_slot_candidates,
              derive_proposal_slot_dependencies,
          )
          from spaghetti_extractor.stack_range_analysis_v2 import (
              derive_stack_range_analysis_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          manifest = json.loads(inputs["machine_ir_manifest"].read_text(encoding="utf-8"))
          base_graph = json.loads(inputs["base_graph"].read_text(encoding="utf-8"))
          seed = json.loads(inputs["interprocedural_seed"].read_text(encoding="utf-8"))
          inventory = json.loads(inputs["selected_profiles"].read_text(encoding="utf-8"))
          checked_control_invariants = json.loads(
              inputs["control_invariants"].read_text(encoding="utf-8")
          ).get("authority_records", [])
          memory_range_invariants = json.loads(
              inputs["memory_range_invariants"].read_text(encoding="utf-8")
          )
          binary = _parse_stage_a_pe(inputs["original_pe"])
          if "launch_profile" in inputs:
              launch = parse_launch_profile_v2(
                  json.loads(inputs["launch_profile"].read_text(encoding="utf-8"))
              )
              if launch.binary.pe_sha256 != binary.sha256:
                  raise ValueError("launch profile is bound to another PE")
              assumptions = {item.kind: item.value.to_value() for item in launch.assumptions}
          elif "launch_profile_template" in inputs:
              launch = parse_launch_assumption_template_v1(
                  json.loads(inputs["launch_profile_template"].read_text(encoding="utf-8"))
              )
              assumptions = launch.assumption_map
          else:
              assumptions = {}
          machine_ir_sha256 = hashlib.sha256(inputs["machine_ir"].read_bytes()).hexdigest()
          launch_assumptions_sha256 = canonical_sha256({"assumptions": assumptions})
          analysis_finite_value_budget = 32
          exact = exact_control_inventory_v2(units)
          control = manifest.get("control", {})
          static_proposals = control.get("recovered_indirect_targets", [])
          discovery = seed.get("proposal_artifacts", {}).get("recoveries", [])
          discovery_call_frames = seed.get("proposal_artifacts", {}).get(
              "call_frame_hypotheses", []
          )
          proposals = merge_recovery_proposals_v2(
              exact_exits=exact["indirect_exits"],
              proposal_sets=[static_proposals, discovery],
          )
          proposal_slot_dependencies = derive_proposal_slot_dependencies(
              binary,
              proposals,
          )
          proposal_graph = build_proposal_control_graph_v2(
              units=units,
              base_graph=base_graph,
              recoveries=proposals,
          )
          provenance = control.get("external_interface_provenance", {})
          internal_paths = tuple(
              pathlib.Path(path)
              for path in inventory["internal_function_contract_profiles"]
          )
          import_abis = load_selected_import_abis(
              tuple(pathlib.Path(path) for path in inventory["machine_import_profiles"])
          )
          interface_profiles = tuple(
              load_external_interface_profile(path)
              for path in inventory["external_interface_profiles"]
          )
          operation_profiles = tuple(
              load_external_operation_profile(path)
              for path in inventory["external_operation_profiles"]
          )
          callable_profiles = tuple(
              load_callable_external_profile(path)
              for path in inventory["callable_external_profiles"]
          )
          internal_contracts = (
              None if not internal_paths else load_internal_function_contracts(
                  internal_paths,
                  binary_sha256=binary.sha256,
                  units=units,
              )
          )

          def derive_interprocedural(
              global_slot_invariants,
              checked_stack_entry_offsets,
              checked_stack_range_facts,
              static_recoveries,
          ):
              return derive_interprocedural_result_v2(
                  manifest,
                  units=units,
                  graph=base_graph,
                  binary=binary,
                  machine_ir_sha256=machine_ir_sha256,
                  global_slot_invariants=global_slot_invariants,
                  checked_stack_entry_offsets=checked_stack_entry_offsets,
                  checked_stack_range_facts=checked_stack_range_facts,
                  checked_control_invariants=checked_control_invariants,
                  stack_launch_assumptions_sha256=launch_assumptions_sha256,
                  import_abis=import_abis,
                  interface_profiles=interface_profiles,
                  operation_profiles=operation_profiles,
                  callable_profiles=callable_profiles,
                  internal_function_contracts=internal_contracts,
                  static_recoveries=static_recoveries,
                  finite_value_budget=analysis_finite_value_budget,
                  proposal_only=static_recoveries is not None,
                  authority_only=static_recoveries is None,
                  progress=emit_progress,
              )

          def derive_inductive_interprocedural(
              global_slot_invariants,
              checked_stack_entry_offsets,
              checked_stack_range_facts,
              hypothesis_recoveries,
              hypothesis_call_frames,
          ):
              return derive_interprocedural_result_v2(
                  manifest,
                  units=units,
                  graph=base_graph,
                  binary=binary,
                  machine_ir_sha256=machine_ir_sha256,
                  global_slot_invariants=global_slot_invariants,
                  checked_stack_entry_offsets=checked_stack_entry_offsets,
                  checked_stack_range_facts=checked_stack_range_facts,
                  checked_control_invariants=checked_control_invariants,
                  stack_launch_assumptions_sha256=launch_assumptions_sha256,
                  import_abis=import_abis,
                  interface_profiles=interface_profiles,
                  operation_profiles=operation_profiles,
                  callable_profiles=callable_profiles,
                  internal_function_contracts=internal_contracts,
                  static_recoveries=None,
                  inductive_hypothesis_recoveries=hypothesis_recoveries,
                  inductive_hypothesis_call_frames=hypothesis_call_frames,
                  finite_value_budget=analysis_finite_value_budget,
                  proposal_only=False,
                  authority_only=True,
                  progress=emit_progress,
              )

          def derive_stack_ranges(graph, interprocedural):
              operation = interprocedural.get("operation_provenance", {})
              return derive_stack_range_analysis_v2(
                  units=units,
                  graph=graph,
                  launch_assumptions={"assumptions": assumptions},
                  pe_sha256=binary.sha256,
                  machine_ir_sha256=machine_ir_sha256,
                  image_base=binary.image_base,
                  size_of_image=binary.size_of_image,
                  call_summaries=interprocedural.get("call_summaries", {}),
                  indirect_recoveries=interprocedural.get(
                      "recovered_targets", []
                  ),
                  call_site_effects=operation.get("call_site_effects", []),
                  finite_offset_budget=analysis_finite_value_budget,
              )

          def derive_global_slots(graph, stack_ranges):
              candidate_slots = derive_mutable_slot_candidates(
                  binary,
                  provenance,
                  units=units,
                  graph=graph,
              )
              launch_initial_values = {}
              for address in candidate_slots:
                  try:
                      data, _kind = loader_initial_bytes_v2(
                          binary,
                          rva_start=address - binary.image_base,
                          width_bytes=4,
                      )
                  except GlobalSlotImageV2Error:
                      continue
                  launch_initial_values[address] = int.from_bytes(data, "little")
              return analyze_global_slots_v2(
                  units=units,
                  graph=graph,
                  candidate_slot_addresses=candidate_slots,
                  image_base=binary.image_base,
                  size_of_image=binary.size_of_image,
                  checked_memory_spatial_facts=stack_ranges.get(
                      "checked_spatial_facts", []
                  ),
                  range_authority_binding=stack_ranges.get("binding"),
                  launch_initial_values=launch_initial_values,
                  memory_range_invariant_analysis=memory_range_invariants,
                  pe_sha256=binary.sha256,
                  machine_ir_sha256=machine_ir_sha256,
              )

          def derive_dependency_scoped_global_slots(
              graph,
              stack_ranges,
              interprocedural,
          ):
              slot_rvas, dependencies = derive_dependency_scoped_slot_inventory_v2(
                  binary,
                  interprocedural.get("recovered_targets", []),
                  proposal_dependencies=proposal_slot_dependencies,
              )
              candidate_slots = [
                  binary.image_base + slot_rva for slot_rva in slot_rvas
              ]
              launch_initial_values = {}
              for address in candidate_slots:
                  try:
                      data, _kind = loader_initial_bytes_v2(
                          binary,
                          rva_start=address - binary.image_base,
                          width_bytes=4,
                      )
                  except GlobalSlotImageV2Error:
                      continue
                  launch_initial_values[address] = int.from_bytes(data, "little")
              return analyze_global_slots_v2(
                  units=units,
                  graph=graph,
                  candidate_slot_addresses=candidate_slots,
                  image_base=binary.image_base,
                  size_of_image=binary.size_of_image,
                  checked_memory_spatial_facts=stack_ranges.get(
                      "checked_spatial_facts", []
                  ),
                  range_authority_binding=stack_ranges.get("binding"),
                  relevant_read_dependencies=dependencies,
                  launch_initial_values=launch_initial_values,
                  checked_memory_access_facts=(
                      interprocedural.get("operation_provenance", {}).get(
                          "checked_memory_access_facts", []
                      )
                  ),
                  checked_memory_address_domains=(
                      interprocedural.get("operation_provenance", {}).get(
                          "checked_memory_address_domains", []
                      )
                  ),
                  call_site_effects=(
                      interprocedural.get("operation_provenance", {}).get(
                          "call_site_effects", []
                      )
                  ),
                  memory_range_invariant_analysis=memory_range_invariants,
                  pe_sha256=binary.sha256,
                  machine_ir_sha256=machine_ir_sha256,
                  interprocedural_authority_sha256=(
                      interprocedural.get("fixed_point", {}).get(
                          "authority_artifact_sha256"
                      )
                  ),
              )

          def derive_global_slot_authority(
              slot_analysis,
              stack_ranges,
              graph,
              interprocedural,
          ):
              return replay_global_slot_authority_v2(
                  submitted_analysis=slot_analysis,
                  provenance=provenance,
                  units=units,
                  graph=graph,
                  interprocedural=interprocedural,
                  stack_range_analysis=stack_ranges,
                  launch_assumptions={"assumptions": assumptions},
                  memory_range_invariant_analysis=memory_range_invariants,
                  original_binary=binary,
                  machine_ir_sha256=machine_ir_sha256,
                  finite_value_budget=analysis_finite_value_budget,
                  proposal_slot_dependencies=proposal_slot_dependencies,
              )

          progress_started = time.monotonic()

          def emit_progress(phase, details):
              print(
                  json.dumps(
                      {
                          "event": "joint_interprocedural_progress_v2",
                          "phase": phase,
                          "elapsed_seconds": round(
                              time.monotonic() - progress_started, 3
                          ),
                          **details,
                      },
                      sort_keys=True,
                  ),
                  file=sys.stderr,
                  flush=True,
              )

          payload = derive_joint_fixed_point_v2(
              proposal_graph=proposal_graph,
              proposal_recoveries=proposals,
              proposal_call_frame_hypotheses=discovery_call_frames,
              proposal_slot_dependencies=proposal_slot_dependencies,
              callbacks=JointFixedPointCallbacks(
                  derive_interprocedural=derive_interprocedural,
                  derive_stack_ranges=derive_stack_ranges,
                  derive_global_slots=derive_global_slots,
                  derive_global_slot_authority=derive_global_slot_authority,
                  derive_graph=lambda interprocedural: (
                      derive_rooted_control_closure_v2(
                          rows=units,
                          base_graph=base_graph,
                          interprocedural=interprocedural,
                      )
                  ),
                  derive_inductive_interprocedural=(
                      derive_inductive_interprocedural
                  ),
                  derive_dependency_scoped_global_slots=(
                      derive_dependency_scoped_global_slots
                  ),
              ),
              progress=emit_progress,
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      interproceduralV2 = {
        derivationSuffix = "interprocedural-v2";
        kind = "interprocedural-v2";
        artifactName = "interprocedural-v2.json";
        expectedFormat = "stage-a-interprocedural-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];
        inputs = { };
        program = ''
          from spaghetti_extractor.artifact_projection_v2 import (
              project_joint_interprocedural_artifact_v2,
          )

          joint = json.loads(
              inputs["joint_interprocedural"].read_text(encoding="utf-8")
          )
          payload = project_joint_interprocedural_artifact_v2(
              joint,
              field="interprocedural",
              expected_format="stage-a-interprocedural-analysis-v2",
              allowed_statuses=("complete", "incomplete", "violated"),
          )
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      rootedClosure = {
        derivationSuffix = "rooted-closure-v2";
        kind = "rooted-closure-v2";
        artifactName = "rooted-closure-v2.json";
        expectedFormat = "stage-a-rooted-control-graph-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.control_analysis_v2" ];
        inputs = {
          machine_ir = "${machineIr}/machine-ir.jsonl";
        };
        program = ''
          from spaghetti_extractor.control_analysis_v2 import (
              derive_rooted_control_closure_v2,
          )

          rows = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          payload = derive_rooted_control_closure_v2(
              rows=rows,
              base_graph=json.loads(
                  inputs["base_graph"].read_text(encoding="utf-8")
              ),
              interprocedural=json.loads(
                  inputs["interprocedural_v2"].read_text(encoding="utf-8")
              ),
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      externalProfileAuthority = {
        derivationSuffix = "external-profile-authority-v2";
        kind = "external-profile-authority-v2";
        artifactName = "external-profile-authority-v2.json";
        expectedFormat = "spaghetti-extractor-external-profile-authority-phase-v2";
        allowedStatuses = [ "complete" ];
        pythonModules = [
          "spaghetti_extractor.external_profile_authority_v2"
          "spaghetti_extractor.hybrid_authority_v2"
        ];
        inputs = {
          selected_profiles = selectedProfileInventory;
        };
        program = ''
          from spaghetti_extractor.external_profile_authority_v2 import (
              build_external_profile_authority_v2,
          )
          from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes

          inventory = json.loads(
              inputs["selected_profiles"].read_text(encoding="utf-8")
          )
          profile_paths = []
          for field in (
              "machine_import_profiles",
              "external_interface_profiles",
              "external_operation_profiles",
              "callable_external_profiles",
          ):
              values = inventory.get(field)
              if not isinstance(values, list):
                  raise ValueError(f"selected profile field {field} is not an array")
              profile_paths.extend(values)
          authority = build_external_profile_authority_v2(profile_paths)
          payload = {
              "format": "spaghetti-extractor-external-profile-authority-phase-v2",
              "status": "complete",
              "authority": authority.payload(),
          }
          output.write_bytes(canonical_json_bytes(payload))
        '';
      };

      checkedExternalSites = {
        derivationSuffix = "external-site-proposals-v2";
        kind = "external-site-proposals-v2";
        artifactName = "external-site-proposals-v2.json";
        expectedFormat = "spaghetti-extractor-external-site-proposals-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.external_profile_authority_v2"
          "spaghetti_extractor.external_site_proposals_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        } // lib.optionalAttrs (checkedExternalSites != null) {
          checked_external_sites_proposal = checkedExternalSites;
        };
        program = ''
          import hashlib

          from spaghetti_extractor.external_profile_authority_v2 import (
              parse_external_profile_authority_v2,
          )
          from spaghetti_extractor.external_site_proposals_v2 import (
              derive_external_site_proposals_v2,
              parse_external_site_proposals_v2,
          )
          from spaghetti_extractor.hybrid_authority_v2 import (
              canonical_json_bytes,
          )

          if "checked_external_sites_proposal" in inputs:
              proposal = json.loads(
                  inputs["checked_external_sites_proposal"].read_text(
                      encoding="utf-8"
                  )
              )
              parse_external_site_proposals_v2(
                  proposal,
                  pe_sha256=hashlib.sha256(
                      inputs["original_pe"].read_bytes()
                  ).hexdigest(),
                  machine_ir_sha256=hashlib.sha256(
                      inputs["machine_ir"].read_bytes()
                  ).hexdigest(),
              )
              output.write_bytes(canonical_json_bytes(proposal))
          else:
              rows = [
                  json.loads(line)
                  for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
                  if line.strip()
              ]
              profile_phase = json.loads(
                  inputs["external_profile_authority"].read_text(
                      encoding="utf-8"
                  )
              )
              authority = parse_external_profile_authority_v2(
                  profile_phase["authority"]
              )
              payload = derive_external_site_proposals_v2(
                  machine_ir_rows=rows,
                  interprocedural=json.loads(
                      inputs["interprocedural_v2"].read_text(encoding="utf-8")
                  ),
                  profile_authority=authority,
                  pe_sha256=hashlib.sha256(
                      inputs["original_pe"].read_bytes()
                  ).hexdigest(),
                  machine_ir_sha256=hashlib.sha256(
                      inputs["machine_ir"].read_bytes()
                  ).hexdigest(),
                  reachable_unit_ids=json.loads(
                      inputs["rooted_closure"].read_text(encoding="utf-8")
                  )["reachable_units"],
              )
              output.write_bytes(canonical_json_bytes(payload))
        '';
      };

      globalSlotAnalysis = {
        derivationSuffix = "global-slot-analysis-v2";
        kind = "global-slot-analysis";
        artifactName = "global-slot-analysis.json";
        expectedFormat = "stage-a-global-slot-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];
        inputs = { };
        program = ''
          from spaghetti_extractor.artifact_projection_v2 import (
              project_joint_interprocedural_artifact_v2,
          )

          joint = json.loads(
              inputs["joint_interprocedural"].read_text(encoding="utf-8")
          )
          payload = project_joint_interprocedural_artifact_v2(
              joint,
              field="global_slot_analysis",
              expected_format="stage-a-global-slot-analysis-v2",
              allowed_statuses=("complete", "incomplete", "violated"),
          )
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      globalSlotAuthority = {
        derivationSuffix = "global-slot-authority-v2";
        kind = "global-slot-authority";
        artifactName = "global-slot-authority.json";
        expectedFormat = "spaghetti-extractor-global-slot-authority-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.control_analysis_v2"
          "spaghetti_extractor.global_slot_authority_v2"
          "spaghetti_extractor.launch_profile_v2"
          "spaghetti_extractor.stage_binary"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
        } // lib.optionalAttrs (launchProfile != null) {
          launch_profile = launchProfile;
        } // lib.optionalAttrs (launchProfileTemplate != null) {
          launch_profile_template = launchProfileTemplate;
        };
        program = ''
          import hashlib

          from spaghetti_extractor.control_analysis_v2 import (
              derive_rooted_control_closure_v2,
          )
          from spaghetti_extractor.global_slot_authority_v2 import (
              replay_global_slot_authority_v2,
          )
          from spaghetti_extractor.launch_profile_v2 import (
              parse_launch_assumption_template_v1,
              parse_launch_profile_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(
                  encoding="utf-8"
              ).splitlines()
              if line.strip()
          ]
          manifest = json.loads(
              inputs["machine_ir_manifest"].read_text(encoding="utf-8")
          )
          joint = json.loads(
              inputs["joint_interprocedural"].read_text(encoding="utf-8")
          )
          interprocedural = joint.get("interprocedural", {})
          base_graph = json.loads(
              inputs["base_graph"].read_text(encoding="utf-8")
          )
          graph = derive_rooted_control_closure_v2(
              rows=units,
              base_graph=base_graph,
              interprocedural=interprocedural,
          )
          binary = _parse_stage_a_pe(inputs["original_pe"])
          if "launch_profile" in inputs:
              launch = parse_launch_profile_v2(
                  json.loads(
                      inputs["launch_profile"].read_text(encoding="utf-8")
                  )
              )
              if launch.binary.pe_sha256 != binary.sha256:
                  raise ValueError("launch profile is bound to another PE")
              assumptions = {
                  item.kind: item.value.to_value()
                  for item in launch.assumptions
              }
          elif "launch_profile_template" in inputs:
              launch = parse_launch_assumption_template_v1(
                  json.loads(
                      inputs["launch_profile_template"].read_text(
                          encoding="utf-8"
                      )
                  )
              )
              assumptions = launch.assumption_map
          else:
              assumptions = {}
          provenance = manifest.get("control", {}).get(
              "external_interface_provenance", {}
          )
          payload = replay_global_slot_authority_v2(
              submitted_analysis=joint.get("global_slot_analysis", {}),
              provenance=provenance,
              units=units,
              graph=graph,
              interprocedural=interprocedural,
              stack_range_analysis=joint.get("stack_range_analysis", {}),
              launch_assumptions={"assumptions": assumptions},
              memory_range_invariant_analysis=json.loads(
                  inputs["memory_range_invariants"].read_text(
                      encoding="utf-8"
                  )
              ),
              original_binary=binary,
              machine_ir_sha256=hashlib.sha256(
                  inputs["machine_ir"].read_bytes()
              ).hexdigest(),
              finite_value_budget=32,
              proposal_slot_dependencies=joint.get(
                  "bootstrap_diagnostics", {}
              ).get("proposal_slot_dependencies", []),
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      callbackEntryContracts = {
        derivationSuffix = "callback-entry-contracts-v2";
        kind = "callback-entry-contracts-v2";
        artifactName = "callback-entry-contracts-v2.json";
        expectedFormat = "spaghetti-extractor-callback-entry-state-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.entry_state_analysis_v2"
          "spaghetti_extractor.global_slot_authority_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.entry_state_analysis_v2 import (
              derive_callback_entry_state_contracts_v2,
          )
          from spaghetti_extractor.global_slot_authority_v2 import (
              apply_global_slot_authority_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          interprocedural = json.loads(
              inputs["interprocedural_v2"].read_text(encoding="utf-8")
          )
          slots = json.loads(
              inputs["global_slot_authority"].read_text(encoding="utf-8")
          )
          binary = _parse_stage_a_pe(inputs["original_pe"])
          authoritative_provenance = apply_global_slot_authority_v2(
              interprocedural.get("operation_provenance", {}),
              slots,
          )
          payload = derive_callback_entry_state_contracts_v2(
              pe_sha256=binary.sha256,
              image_base=binary.image_base,
              size_of_image=binary.size_of_image,
              interface_provenance=authoritative_provenance,
              units=units,
              machine_ir_sha256=hashlib.sha256(
                  inputs["machine_ir"].read_bytes()
              ).hexdigest(),
              global_slot_invariants=slots.get(
                  "global_slot_invariants", []
              ),
          )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      finalizedLaunchProfile = {
        derivationSuffix = "finalized-launch-profile-v2";
        kind = "finalized-launch-profile-v2";
        artifactName = "finalized-launch-profile-v2.json";
        expectedFormat = "spaghetti-extractor-finalized-launch-profile-phase-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.launch_profile_v2"
          "spaghetti_extractor.stage_binary"
        ];
        inputs = {
          behavioral_roots = "${staticExport}/behavioral-roots.json";
        } // lib.optionalAttrs (launchProfile != null) {
          launch_profile = launchProfile;
        } // lib.optionalAttrs (launchProfileTemplate != null) {
          launch_profile_template = launchProfileTemplate;
          original_pe = original;
        };
        program = ''
          from spaghetti_extractor.launch_profile_v2 import (
              finalize_launch_profile_v2,
              parse_launch_assumption_template_v1,
              parse_launch_profile_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          callback = json.loads(
              inputs["callback_entry_contracts"].read_text(encoding="utf-8")
          )
          roots = json.loads(
              inputs["behavioral_roots"].read_text(encoding="utf-8")
          )
          if (
              "launch_profile" not in inputs
              and "launch_profile_template" not in inputs
          ):
              payload = {
                  "format": "spaghetti-extractor-finalized-launch-profile-phase-v2",
                  "status": "incomplete",
                  "profile": None,
                  "issues": [{
                      "status": "incomplete",
                      "code": "launch_profile_missing",
                  }],
              }
          elif "launch_profile" in inputs:
              supplied = parse_launch_profile_v2(
                  json.loads(inputs["launch_profile"].read_text(encoding="utf-8"))
              )
              assumptions = {
                  row.kind: row.value.to_value()
                  for row in supplied.assumptions
              }
              features = {
                  kind: [site.to_value() for site in sites]
                  for kind, sites in supplied.feature_inventory
              }
              finalized = finalize_launch_profile_v2(
                  pe_sha256=supplied.binary.pe_sha256,
                  image_base=supplied.binary.image_base,
                  size_of_image=supplied.binary.size_of_image,
                  behavioral_roots=roots,
                  assumptions=assumptions,
                  callback_entry_state=callback,
                  feature_inventory=features,
              )
              payload = {
                  "format": "spaghetti-extractor-finalized-launch-profile-phase-v2",
                  "status": finalized.status.value,
                  "profile": finalized.to_payload(),
                  "issues": [issue.to_payload() for issue in finalized.issues],
              }
          else:
              template = parse_launch_assumption_template_v1(
                  json.loads(
                      inputs["launch_profile_template"].read_text(encoding="utf-8")
                  )
              )
              binary = _parse_stage_a_pe(inputs["original_pe"])
              finalized = finalize_launch_profile_v2(
                  pe_sha256=binary.sha256,
                  image_base=binary.image_base,
                  size_of_image=binary.size_of_image,
                  behavioral_roots=roots,
                  assumptions=template.assumption_map,
                  callback_entry_state=callback,
                  feature_inventory=template.feature_map,
              )
              payload = {
                  "format": "spaghetti-extractor-finalized-launch-profile-phase-v2",
                  "status": finalized.status.value,
                  "profile": finalized.to_payload(),
                  "issues": [issue.to_payload() for issue in finalized.issues],
              }
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      entryRootClosure = {
        derivationSuffix = "entry-root-closure-v2";
        kind = "entry-root-closure";
        artifactName = "entry-root-closure.json";
        expectedFormat = "stage-a-entry-state-analysis-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.entry_fact_derivation_v2"
          "spaghetti_extractor.entry_state_analysis_v2"
          "spaghetti_extractor.global_slot_authority_v2"
          "spaghetti_extractor.hybrid_authority_v2"
          "spaghetti_extractor.launch_profile_v2"
          "spaghetti_extractor.stage_binary"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          behavioral_roots = "${staticExport}/behavioral-roots.json";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.entry_state_analysis_v2 import (
              construct_entry_state_analysis_v2,
          )
          from spaghetti_extractor.entry_fact_derivation_v2 import derive_iat_facts
          from spaghetti_extractor.global_slot_authority_v2 import (
              apply_global_slot_authority_v2,
          )
          from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes
          from spaghetti_extractor.launch_profile_v2 import (
              launch_invariants_for_entry_state,
              parse_launch_profile_v2,
          )
          from spaghetti_extractor.stage_binary import _parse_stage_a_pe

          units = [json.loads(line) for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines() if line.strip()]
          roots = json.loads(inputs["behavioral_roots"].read_text(encoding="utf-8"))
          slots = json.loads(inputs["global_slot_authority"].read_text(encoding="utf-8"))
          interprocedural = json.loads(inputs["interprocedural_v2"].read_text(encoding="utf-8"))
          callbacks = json.loads(inputs["callback_entry_contracts"].read_text(encoding="utf-8"))
          finalized = json.loads(inputs["finalized_launch_profile"].read_text(encoding="utf-8"))
          binary = _parse_stage_a_pe(inputs["original_pe"])
          launch = None
          if isinstance(finalized.get("profile"), dict):
              launch = launch_invariants_for_entry_state(
                  parse_launch_profile_v2(finalized["profile"])
              )
          authoritative_provenance = apply_global_slot_authority_v2(
              interprocedural.get("operation_provenance", {}),
              slots,
          )
          payload = construct_entry_state_analysis_v2(
              behavioral_roots=roots,
              interface_provenance=authoritative_provenance,
              units=units,
              machine_ir_sha256=hashlib.sha256(
                  inputs["machine_ir"].read_bytes()
              ).hexdigest(),
              global_slot_evidence=slots.get("global_slot_evidence", []),
              launch_invariants=launch,
              iat_facts=derive_iat_facts(binary),
              callback_entry_state=callbacks,
          )
          launch_issues = finalized.get("issues", [])
          if launch_issues:
              payload["issues"] = sorted(
                  [
                      *payload["issues"],
                      *launch_issues,
                  ],
                  key=lambda row: (
                      str(row.get("status")),
                      str(row.get("code")),
                      str(row.get("subject", "")),
                      str(row.get("detail", "")),
                  ),
              )
              payload["status"] = (
                  "violated"
                  if any(
                      row.get("status") == "violated"
                      for row in payload["issues"]
                  )
                  else "incomplete" if payload["issues"] else "complete"
              )
              payload["counts"]["issues"] = len(payload["issues"])
              body = dict(payload)
              body.pop("analysis_sha256", None)
              payload["analysis_sha256"] = hashlib.sha256(
                  canonical_json_bytes(body)
              ).hexdigest()
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      isaRequirements = {
        pythonSource = isaPythonSource;
        derivationSuffix = "isa-requirements-v2";
        kind = "isa-requirements";
        artifactName = "isa-requirements.json";
        expectedFormat = "spaghetti-extractor-machine-ir-isa-requirements-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.analysis.isa_requirements"
          "spaghetti_extractor.machine_ir_isa_requirements_v2"
        ];
        pythonExtraPaths = [ "spaghetti_extractor/lean/StageA" ];
        extraNativeBuildInputs = [ pkgs.lean4 ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        };
        program = ''
          import hashlib

          from spaghetti_extractor.analysis.isa_requirements import (
              extract_lean_instruction_forms_side,
          )
          from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
              build_machine_ir_isa_extraction_request_v2,
              build_machine_ir_isa_requirements_v2,
              failed_machine_ir_isa_requirements_v2,
              incomplete_machine_ir_isa_requirements_v2,
          )

          units = [
              json.loads(line)
              for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
              if line.strip()
          ]
          machine_ir_sha256 = hashlib.sha256(inputs["machine_ir"].read_bytes()).hexdigest()
          binary_sha256 = hashlib.sha256(inputs["original_pe"].read_bytes()).hexdigest()
          request = build_machine_ir_isa_extraction_request_v2(
              units=units,
              binary_sha256=binary_sha256,
          )
          try:
              lean_rows, lean_evidence = extract_lean_instruction_forms_side(
                  binary=inputs["original_pe"],
                  request=request,
                  timeout_seconds=1800.0,
                  allow_decode_gaps=True,
              )
          except Exception as exc:
              payload = incomplete_machine_ir_isa_requirements_v2(
                  request=request,
                  machine_ir_sha256=machine_ir_sha256,
                  code="lean_exact_isa_extraction_incomplete",
                  reason=str(exc),
              )
          else:
              try:
                  payload = build_machine_ir_isa_requirements_v2(
                      request=request,
                      machine_ir_sha256=machine_ir_sha256,
                      lean_rows=lean_rows,
                      lean_evidence=lean_evidence,
                      lean_gaps=lean_evidence.get("decode_gaps", []),
                  )
              except Exception as exc:
                  payload = failed_machine_ir_isa_requirements_v2(
                      request=request,
                      machine_ir_sha256=machine_ir_sha256,
                      status="violated",
                      code="lean_exact_isa_binding_contradiction",
                      reason=str(exc),
                  )
          output.write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
        '';
      };

      isaSelectionAuthority = {
        derivationSuffix = "isa-selection-authority-v2";
        kind = "isa-selection-authority";
        artifactName = "isa-selection-authority.json";
        expectedFormat = "spaghetti-extractor-isa-selection-authority-phase-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.isa_kernel_selection"
          "spaghetti_extractor.machine_ir_isa_requirements_v2"
          "spaghetti_extractor.machine_ir_isa_selection_v2"
        ];
        inputs = { } // lib.optionalAttrs (isaSelectionAuthority != null) {
          selected_authority = isaSelectionAuthority;
        };
        program = ''
          from spaghetti_extractor.isa_kernel_selection import parse_isa_kernel_selection_authority
          from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
              compare_selection_to_machine_ir_requirements_v2,
              parse_machine_ir_isa_requirements_v2,
          )
          from spaghetti_extractor.machine_ir_isa_selection_v2 import (
              build_machine_ir_isa_selection_certificate_v2,
          )

          certificate = None
          upstream_authority_sha256 = None
          issues = []
          requirements = parse_machine_ir_isa_requirements_v2(
              json.loads(inputs["isa_requirements"].read_text(encoding="utf-8"))
          )
          if requirements.status != "complete":
              issues.append({
                  "status": requirements.status,
                  "code": "isa_exact_requirements_not_complete",
                  "requirement_issues": list(requirements.issues),
              })
          if "selected_authority" not in inputs:
              issues.append({"status": "incomplete", "code": "isa_selection_authority_missing"})
          else:
              try:
                  parsed = parse_isa_kernel_selection_authority(
                      json.loads(inputs["selected_authority"].read_text(encoding="utf-8"))
                  )
                  upstream_authority_sha256 = parsed.authority_sha256
                  issues.extend(
                      compare_selection_to_machine_ir_requirements_v2(
                          requirements, parsed
                      )
                  )
                  if parsed.status.value != "qualified":
                      issues.append({"status": parsed.status.value, "code": "isa_selection_not_complete"})
                  certificate = build_machine_ir_isa_selection_certificate_v2(
                      requirements=requirements,
                      authority=parsed,
                  )
              except Exception as exc:
                  issues.append({"status": "violated", "code": "isa_selection_corrupt", "reason": str(exc)})
          status = (
              "violated" if any(row["status"] == "violated" for row in issues)
              else "incomplete" if issues else "complete"
          )
          payload = {
              "format": "spaghetti-extractor-isa-selection-authority-phase-v2",
              "status": status,
              "selection_certificate": certificate,
              "upstream_authority_sha256": upstream_authority_sha256,
              "issues": issues,
          }
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      exceptionCertificates = {
        derivationSuffix = "exception-certificates-v2";
        kind = "exception-certificates";
        artifactName = "exception-certificates.json";
        expectedFormat = "spaghetti-extractor-exception-certificates-phase-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.exception_phase_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
        } // lib.optionalAttrs (exceptionCertificates != null) {
          selected_certificates = exceptionCertificates;
        };
        program = ''
          import hashlib

          from spaghetti_extractor.exception_phase_v2 import (
              derive_checked_exception_reports_v2,
          )

          units = [json.loads(line) for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines() if line.strip()]
          graph = json.loads(inputs["rooted_closure"].read_text(encoding="utf-8"))
          binary_sha256 = hashlib.sha256(inputs["original_pe"].read_bytes()).hexdigest()
          machine_ir_sha256 = hashlib.sha256(inputs["machine_ir"].read_bytes()).hexdigest()
          submitted = []
          seh_inventories = []
          if "selected_certificates" in inputs:
              selected = json.loads(inputs["selected_certificates"].read_text(encoding="utf-8"))
              submitted = selected.get(
                  "evidence",
                  selected.get("certificates", selected.get("reports", [])),
              )
              if not isinstance(submitted, list):
                  raise ValueError("submitted exception evidence must be an array")
              seh_inventories = selected.get("seh_inventories", [])
              if not isinstance(seh_inventories, list):
                  raise ValueError("submitted SEH inventories must be an array")
          proposals, replay, reports = derive_checked_exception_reports_v2(
              units=units,
              graph=graph,
              binary_sha256=binary_sha256,
              machine_ir_sha256=machine_ir_sha256,
              submitted_evidence=submitted,
              seh_inventories=seh_inventories,
          )
          statuses = [
              str(report.get("status", "violated")) for report in reports
          ] + [
              str(row.get("status", "violated"))
              for row in replay.get("submitted_evidence", [])
          ]
          status = (
              "violated" if "violated" in statuses
              else "incomplete" if "incomplete" in statuses
              else "complete"
          )
          payload = {
              "format": "spaghetti-extractor-exception-certificates-phase-v2",
              "status": status,
              "fault_sites": [
                  fault
                  for scc in proposals.get("required_sccs", [])
                  for fault in scc.get("fault_sites", [])
              ],
              "proposals": proposals,
              "replay": replay,
              "reports": list(reports),
              "authority_records": [],
              "issues": [
                  row
                  for row in replay.get("submitted_evidence", [])
                  if row.get("status") != "complete"
              ],
          }
          output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        '';
      };

      staticAuthority = {
        derivationSuffix = "static-authority-v2";
        kind = "static-authority-v2";
        artifactName = "static-authority-v2.json";
        expectedFormat = "spaghetti-extractor-static-hybrid-authority-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.external_profile_authority_v2"
          "spaghetti_extractor.external_site_proposals_v2"
          "spaghetti_extractor.static_hybrid_authority_v2"
        ];
        inputs = {
          original_pe = original;
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
          behavioral_roots = "${staticExport}/behavioral-roots.json";
        };
        program = ''
          import hashlib
          from spaghetti_extractor.external_site_proposals_v2 import parse_external_site_proposals_v2
          from spaghetti_extractor.external_profile_authority_v2 import (
              parse_external_profile_authority_v2,
          )
          from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes
          from spaghetti_extractor.static_hybrid_authority_v2 import build_static_hybrid_authority_v2

          def load(name):
              return json.loads(inputs[name].read_text(encoding="utf-8"))
          rows = [json.loads(line) for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines() if line.strip()]
          pe_sha256 = hashlib.sha256(inputs["original_pe"].read_bytes()).hexdigest()
          machine_ir_sha256 = hashlib.sha256(inputs["machine_ir"].read_bytes()).hexdigest()
          externals = parse_external_site_proposals_v2(
              load("checked_external_sites"),
              pe_sha256=pe_sha256,
              machine_ir_sha256=machine_ir_sha256,
          )
          profile_authority = parse_external_profile_authority_v2(
              load("external_profile_authority")["authority"]
          )
          exceptions = load("exception_certificates")
          isa_requirements = load("isa_requirements")
          isa = load("isa_selection_authority")
          report = build_static_hybrid_authority_v2(
              machine_ir_rows=rows,
              machine_ir_manifest=load("machine_ir_manifest"),
              exact_unit_preparation=load("exact_unit_prep"),
              pe_sha256=pe_sha256,
              behavioral_roots=load("behavioral_roots"),
              entry_state_analysis=load("entry_root_closure"),
              interprocedural_result=load("interprocedural_v2"),
              checked_external_sites=externals,
              external_profile_authority=profile_authority,
              checked_exception_reports=exceptions.get("reports", []),
              checked_exception_records=exceptions.get("authority_records", []),
              isa_selection_authority=isa.get("selection_certificate"),
              isa_requirements=isa_requirements,
          )
          output.write_bytes(canonical_json_bytes(report))
        '';
      };

      authorityBundle = {
        derivationSuffix = "authority-bundle-v2";
        kind = "authority-bundle-v2";
        artifactName = "authority-bundle-v2.json";
        expectedFormat = "spaghetti-extractor-hybrid-authority-bundle-v2";
        allowedStatuses = [ "complete" "incomplete" "violated" ];
        pythonModules = [ "spaghetti_extractor.static_hybrid_authority_v2" ];
        inputs = { };
        program = ''
          from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes
          from spaghetti_extractor.static_hybrid_authority_v2 import (
              validate_static_hybrid_authority_v2,
          )

          report = validate_static_hybrid_authority_v2(
              json.loads(inputs["static_authority"].read_text(encoding="utf-8"))
          )
          bundle = report.get("authority_bundle")
          if not isinstance(bundle, dict):
              raise SystemExit(
                  "v2 static authority did not produce a bound authority bundle"
              )
          output.write_bytes(canonical_json_bytes(bundle))
        '';
      };

      finalAudit = {
        derivationSuffix = "final-audit-v2";
        kind = "final-audit";
        artifactName = "final-audit.json";
        expectedFormat = "spaghetti-extractor-static-hybrid-final-audit-v2";
        allowedStatuses = [ "pass" "incomplete" "violated" ];
        pythonModules = [
          "spaghetti_extractor.static_hybrid_final_audit_v2"
        ];
        inputs = {
          machine_ir = "${machineIr}/machine-ir.jsonl";
          machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
        };
        program = ''
          from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes
          from spaghetti_extractor.static_hybrid_final_audit_v2 import (
              build_static_hybrid_final_audit_v2,
          )

          payload = build_static_hybrid_final_audit_v2(
              static_authority=inputs["static_authority"],
              authority_bundle=inputs["authority_bundle"],
              machine_ir=inputs["machine_ir"],
              machine_ir_manifest=inputs["machine_ir_manifest"],
          )
          output.write_bytes(canonical_json_bytes(payload))
        '';
      };
    };
  };

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
    directPreparedMachineIr
    provisionalMachineIr
    stateMachine
    preparedMachineIr
    machineIr
    staticHybridCompleteness
    staticHybridAuthorityV2
    reconstructionPlan
    componentProposals
    ;
}
