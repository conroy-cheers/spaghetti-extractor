# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  candidateBinary =
    "${context.tools.minimalImportCall}/minimal-import-call.exe";
  nativeRealizationPhase = import ../ca-python-json-phase.nix {
    inherit pkgs;
    pythonEnv = context.pythonEnv;
    name = "spaghetti-extractor-candidate-test-fixture-native-realization";
    kind = "candidate-test-fixture-native-realization";
    artifactName = "native-realization.json";
    expectedFormat = "spaghetti-extractor-native-realization-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.native_realization.receipt_v2" ];
    phaseRole = "candidate";
    inputs.candidate_binary = candidateBinary;
    program = ''
      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.native_realization.receipt_v2 import (
          NativeRealizationV2,
      )
      from spaghetti_extractor.util import sha256_file, write_json

      candidate = inputs["candidate_binary"]
      portable_dispatch = {
          "format": "spaghetti-extractor-portable-dispatch-link-receipt-v1",
          "status": "complete",
          "activation_authorized": True,
          "bindings": {
              "implementation_selection_sha256": "2" * 64,
              "payload_sha256": "1" * 64,
              "linker_map_sha256": "2" * 64,
          },
          "registry": None,
          "entries": [],
          "policy": {
              "strong_module_registry_required_when_portable": True,
              "one_strong_implementation_symbol_per_entry": True,
              "exact_selected_object_membership_required": True,
              "contextual_bisimulation_authority_required": True,
              "weak_or_duplicate_fallback_forbidden": True,
              "source_only_authority": False,
          },
          "blockers": [],
      }
      portable_dispatch["receipt_sha256"] = canonical_sha256_v3(
          portable_dispatch
      )
      realization = {
          "format": "spaghetti-extractor-native-realization-v2",
          "status": "complete",
          "ready_for_observation": True,
          "bindings": {
              "linked_semantic_module_sha256": "1" * 64,
              "implementation_selection_sha256": "2" * 64,
              "qualified_platform_sha256": "3" * 64,
              "original_module_interface_sha256": "4" * 64,
          },
          "providers": [{
              "provider_id": "generated.fixture",
              "provider_kind": "generated_behavioral_c",
              "qualification_sha256": "5" * 64,
              "artifact_sha256": "6" * 64,
              "semantic_slice_sha256": "7" * 64,
              "tool_sha256s": ["8" * 64],
              "definition_ids": ["definition:fixture"],
              "obligation_ids": [],
          }],
          "definitions": [{
              "definition_id": "definition:fixture",
              "symbol_id": "original:function:fixture",
              "provider_id": "generated.fixture",
              "provider_kind": "generated_behavioral_c",
              "qualification_sha256": "5" * 64,
              "native_symbol": "spx_fixture",
              "address": {"kind": "linked_rva", "rva": 4096},
              "implementation_rva": 4096,
              "bridge_class_id": None,
          }],
          "obligations": [],
          "native_objects": [{
              "object_sha256": "9" * 64,
              "role": "generated_behavioral_c",
              "provider_ids": ["generated.fixture"],
              "definition_ids": ["definition:fixture"],
              "obligation_ids": [],
              "section_ids": [],
          }],
          "bridges": [],
          "runtime": {
              "qualification_sha256": "a" * 64,
              "tls_layout_sha256": "b" * 64,
              "private_stack_size": 1048576,
              "support_import_ids": [],
              "required_symbols": [{
                  "symbol": "spx_fixture",
                  "rva": 4096,
                  "role": "entry",
              }],
              "obligation_receipt_sha256s": [],
          },
          "link": {
              "payload_sha256": "1" * 64,
              "linker_map_sha256": "2" * 64,
              "relocation_inventory_sha256": "c" * 64,
              "section_table_sha256": "d" * 64,
              "entry_symbols": ["spx_fixture"],
          },
          "portable_dispatch_link_receipt": portable_dispatch,
          "loader_surface": {
              "entry_rva": 4096,
              "exports_sha256": "e" * 64,
              "imports_sha256": "f" * 64,
              "tls_sha256": "0" * 64,
              "base_relocations_sha256": "1" * 64,
              "resources_sha256": None,
              "load_config_sha256": None,
          },
          "candidate": {
              "filename": candidate.name,
              "sha256": sha256_file(candidate),
              "size": candidate.stat().st_size,
              "module_interface_sha256": "2" * 64,
          },
          "pinned_code_layout_requirements": [],
          "blockers": [],
      }
      realization["native_realization_sha256"] = canonical_sha256_v3(
          realization
      )
      NativeRealizationV2.parse(realization)
      write_json(output, realization)
    '';
  };
  nativeRealization = nativeRealizationPhase.derivation;
  staleRealizationGate = import ../ca-json-receipt-gate.nix {
    inherit pkgs;
    pythonEnv = context.pythonEnv;
    name = "spaghetti-extractor-candidate-test-stale-realization-gate";
    kind = "candidate-test-stale-realization";
    artifact = "${nativeRealization}/native-realization.json";
    artifactName = "native-realization.json";
    expectedFormat = "spaghetti-extractor-native-realization-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.native_realization.receipt_v2" ];
    phaseRole = "developer";
    inputs.native_realization = nativeRealization;
    program = ''
      import copy

      from spaghetti_extractor.native_realization.receipt_v2 import (
          NativeRealizationV2,
          NativeRealizationV2Error,
      )

      realization = NativeRealizationV2.load(artifact_path)
      stale = copy.deepcopy(realization.payload)
      stale["candidate"]["size"] += 1
      try:
          NativeRealizationV2.parse(stale)
      except NativeRealizationV2Error:
          pass
      else:
          fail("strict execution gate accepted a stale realization")
    '';
  };
  candidateTest = import ../candidate-test-suite.nix {
    inherit pkgs candidateBinary nativeRealization;
    inherit (context) pythonEnv;
    pythonSource = context.sources.fullSource;
    id = "minimal-import-call";
    configurationId = "fixture";
    namePrefix = "spaghetti-extractor-candidate-test-constructor";
    suite = ./fixtures/candidate-test-suite/candidate-suite.json;
  };
  aggregateConstructorArgs = builtins.functionArgs (
    import ../candidate-test-aggregate.nix
  );
in
assert aggregateConstructorArgs ? nativeRealization;
assert !aggregateConstructorArgs.nativeRealization;
pkgs.runCommand "spaghetti-extractor-candidate-test-suite-check" {
  nativeBuildInputs = [ pkgs.jq pkgs.ripgrep ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  receipt=${candidateTest.aggregate}/candidate-test-receipt.json
  report=${candidateTest.aggregate}/test-results/candidate-test-report.json
  for gate_source in \
      ${../candidate-test-aggregate.nix} \
      ${../candidate-test-suite.nix}; do
    rg -q 'spaghetti_extractor\.native_realization\.receipt_v2' "$gate_source"
    rg -q 'NativeRealizationV2\.load' "$gate_source"
    if rg -q 'portable_dispatch_link_receipt\.status' "$gate_source"; then
      echo "candidate execution gate regressed to shallow JSON validation" >&2
      exit 1
    fi
  done
  test -s ${staleRealizationGate.receipt}
  jq -e '
    .format == "spaghetti-extractor-candidate-test-receipt-v1" and
    .status == "pass" and
    .policy.candidate_only and
    (.policy.original_binary_executed | not) and
    .policy.native_realization_required_before_execution and
    .policy.headless_wine_required and
    .case_ids == ["writes-expected-output"]
  ' "$receipt" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-candidate-test-report-v1" and
    .status == "pass" and
    .counts == {"cases": 1, "failed": 0, "passed": 1} and
    (.oracle.original_runtime_observations | not)
  ' "$report" >/dev/null
  mkdir -p "$out"
  ln -s ${candidateTest.aggregate} "$out/candidate-test"
''
