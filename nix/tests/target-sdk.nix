# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  sdk = import ../target-sdk.nix { inherit pkgs; };
  pe32WorkflowArguments = builtins.functionArgs sdk.workflow.pe32;
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  acceptance = pkgs.writeText "minimal-sdk-acceptance-artifact" "accepted\n";
  # Reuse the discovered closure of the existing semantic-link fixture tests.
  # Importing the complete checkout here rescheduled SDK fixtures and all their
  # consumers after unrelated operator, documentation or desktop-runner edits.
  testManifest = builtins.fromJSON (builtins.unsafeDiscardStringContext
    (builtins.readFile ../generated/test-suite-manifest.json));
  semanticFixtureShard = pkgs.lib.findFirst
    (shard: builtins.elem "tests/unit/semantic_link/test_module_v2.py" shard.test_paths)
    (throw "SDK semantic fixture has no discovered test closure; run nix run .#dev -- refresh")
    testManifest.shards;
  semanticFixtureSource = pkgs.lib.fileset.toSource {
    root = ../..;
    fileset = pkgs.lib.fileset.unions (map (path: ../../. + "/${path}") semanticFixtureShard.files);
  };
  nativeRealizationPythonSource = import ../python-module-closure.nix {
    inherit pkgs;
    phaseRole = "developer";
    modules = [
      "spaghetti_extractor.artifacts.artifact_set"
      "spaghetti_extractor.native_realization.receipt_v2"
      "spaghetti_extractor.util"
    ];
  };
  semanticModuleFixture = pkgs.runCommand
    "minimal-sdk-linked-semantic-module-v2"
    { nativeBuildInputs = [ sdk.validation.pythonEnv ]; } ''
      mkdir -p "$out"
      export PYTHONPATH=${semanticFixtureSource}/src:${semanticFixtureSource}
      python3 - "$out" <<'PY'
      import sys
      from pathlib import Path

      from spaghetti_extractor.semantic_link.module_v2 import (
          build_linked_semantic_module_v2,
      )
      from spaghetti_extractor.semantic_link.may_link import (
          compile_semantic_may_link_facts_v2,
      )
      from spaghetti_extractor.util import write_json
      from tests.unit.semantic_link.fixture import SemanticLinkFixture

      root = Path(sys.argv[1])
      SemanticLinkFixture().linked_facts(root)
      semantic, facts = compile_semantic_may_link_facts_v2(
          semantic_object=root / "semantic-object.json",
      )
      payload = build_linked_semantic_module_v2(
          semantic=semantic,
          link_facts=facts,
      )
      write_json(root / "linked-semantic-module.json", payload)
      PY
    '';
  mkImplementationSelection = configurationId: mode: pkgs.runCommand
    "minimal-sdk-${configurationId}-implementation-selection-v2-${mode}"
    { nativeBuildInputs = [ pkgs.python3 ]; } ''
      mkdir -p "$out"
      python3 - \
        ${semanticModuleFixture}/linked-semantic-module.json \
        "$out/implementation-selection.json" <<'PY'
      import hashlib
      import json
      import pathlib
      import sys

      module = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
      core = {
          "format": "spaghetti-extractor-implementation-selection-v2",
          "status": "complete",
          "ready_for_realization": True,
          "mode": ${builtins.toJSON mode},
          "bindings": {
              "linked_semantic_module_sha256": module[
                  "linked_semantic_module_sha256"
              ],
          },
          "qualification_sha256s": [],
          "definition_selections": [],
          "obligation_selections": [],
          "blockers": [],
      }
      encoded = json.dumps(
          core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
      ).encode("ascii")
      payload = {**core, "selection_sha256": hashlib.sha256(encoded).hexdigest()}
      pathlib.Path(sys.argv[2]).write_text(
          json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="ascii"
      )
      PY
    '';
  defaultImplementationSelection =
    mkImplementationSelection "default" "hybrid";
  minimalImplementationSelection =
    mkImplementationSelection "minimal" "portable";
  nativeRealizationFixture = pkgs.runCommand
    "minimal-sdk-native-realization-v2"
    { nativeBuildInputs = [ sdk.validation.pythonEnv ]; } ''
      mkdir -p "$out"
      cp ${artifact} "$out/fixture.exe"
      export PYTHONPATH=${nativeRealizationPythonSource.pythonPath}
      python3 - "$out/fixture.exe" "$out/native-realization.json" <<'PY'
      import sys
      from pathlib import Path

      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.native_realization.receipt_v2 import NativeRealizationV2
      from spaghetti_extractor.util import sha256_file, write_json

      candidate = Path(sys.argv[1])
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
      portable_dispatch["receipt_sha256"] = canonical_sha256_v3(portable_dispatch)
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
      realization["native_realization_sha256"] = canonical_sha256_v3(realization)
      NativeRealizationV2.parse(realization)
      write_json(Path(sys.argv[2]), realization)
      PY
    '';
  realization = {
    derivation = nativeRealizationFixture;
    candidate = "${nativeRealizationFixture}/fixture.exe";
  };
  workflow = {
    hasComponents = true;
    originalBinary = artifact;
    binaryIdentity = "fixture.exe";
    configurationIds = [ "default" "minimal" ];
    analysis = {
      originalInventory = artifact;
      staticExport = artifact;
      launchAnalysisAssumptions = artifact;
      stateMachine = artifact;
      machineIr = artifact;
      reconstructionPlan = artifact;
      componentProposals = artifact;
    };
    authority = {
      finalAuthority = acceptance;
      finalAuthorityGate = acceptance;
      graph.metadata = artifact;
      graph.phases.example.derivation = artifact;
    };
    components = {
      authoringPaths = {
        intent = ../../tests/fixtures/minimal-target-bundle/intent/components.json;
        interface_index = toString ../../tests/fixtures/minimal-target-bundle + "/contracts/interfaces-v5/index.json";
        binding_index = toString ../../tests/fixtures/minimal-target-bundle + "/contracts/bindings-v5/index.json";
      };
      assetInventory = [ {
        path = ../../tests/fixtures/minimal-target-bundle/intent/components.json;
        role = "component_intent";
        owner = "component-workflow";
      } ];
      resolution = artifact;
      contracts.example = artifact;
      sourcePackages.example = artifact;
      v5Interfaces.example = {
        derivation = artifact;
        interface = artifact;
        schema = artifact;
      };
      bindingIntentPaths.example = artifact;
      v6SemanticSlices.example.derivation = artifact;
      v6WorkPackages.example = {
        derivation = artifact;
        semanticSlice = artifact;
        withCallerDefinition = _: { derivation = acceptance; semanticSlice = artifact; };
      };
      evidences.example = artifact;
      qualifications.example = artifact;
      compileReceipts = { };
      inductionPackages.example = artifact;
      machineBindingReceipts = { };
      serviceGraphs = { };
      ownershipReceipts = { };
      sourceBundles.default = artifact;
      sourceBundles.minimal = artifact;
      statusReports.example = artifact;
      workPackages.example = artifact;
      checkGates.example = artifact;
      configurationCheckGates.default = artifact;
      configurationCheckGates.minimal = artifact;
      liftUnitIndex.example = {
        kind = "component";
        label = "Example";
        entryRvas = [ 4096 ];
        members = [ ];
        hasSource = true;
        hasEvidence = true;
        hasQualification = true;
        hasInduction = true;
      };
      configurationIndex.default = {
        kind = "configuration";
        label = "Default";
        selections = [ ];
        selectedComponentIds = [ ];
        allSelectedProvidersEligible = true;
        mode = "hybrid";
      };
      configurationIndex.minimal = {
        kind = "configuration";
        label = "Minimal";
        selections = [ ];
        selectedComponentIds = [ ];
        allSelectedProvidersEligible = true;
        mode = "portable";
      };
      bundle = artifact;
    };
    portableSemanticProvidersByComponent.example.derivation = artifact;
    libraryCatalogConfigured = false;
    nativeRealizations.default = realization;
    nativeRealizations.minimal = realization;
    calls = {
      withComponentPackages = componentPackages: import ../boundary-workbench.nix {
        inherit pkgs componentPackages;
        pythonEnv = sdk.validation.pythonEnv;
        namePrefix = "minimal-sdk-boundaries";
        targetId = "minimal-sdk-consumer";
      };
      configured = false;
      assetInventory = [ ];
      status = artifact;
      subjects = { };
      check = artifact;
    };
    qualifiedPlatform.derivation = artifact;
    linkedSemanticModule.derivation = semanticModuleFixture;
    semanticImplementationSelections = {
      default.derivation = defaultImplementationSelection;
      minimal.derivation = minimalImplementationSelection;
    };
  };
  evidenceTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    inputs.baseline = artifact;
    workflow = workflow // {
      candidateWithProofEvidence = { configurationId, proofEvidenceByComponent }:
        assert configurationId == "default";
        assert proofEvidenceByComponent == { example = toString artifact; };
        { selection.derivation = defaultImplementationSelection; inherit realization; };
    };
  };
  evidenceRequest = { proofEvidenceByComponent.example = toString artifact; };
  changedDefaultImplementationSelection =
    mkImplementationSelection "default" "portable";
  failingConfigurationStatus = pkgs.runCommand
    "minimal-sdk-configuration-status-must-not-build" { } ''
      echo "project status incorrectly realized component status" >&2
      exit 1
    '';
  candidateTests = {
    public = {
      _type = "spaghetti-extractor-candidate-test-suite-v1";
      configurationId = "default";
      caseIds = [ "help" ];
      suite = ../../tests/fixtures/minimal-target-bundle/tests/default-status-suite.json;
      aggregate = artifact;
    };
    minimal = {
      _type = "spaghetti-extractor-candidate-test-suite-v1";
      configurationId = "minimal";
      caseIds = [ "version" ];
      suite = ../../tests/fixtures/minimal-target-bundle/tests/minimal-status-suite.json;
      aggregate = artifact;
    };
  };
  changedCandidateTests = candidateTests // {
    minimal = candidateTests.minimal // {
      caseIds = [ "version" "license" ];
    };
  };
  target = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    inherit workflow candidateTests;
    inputs.baseline = artifact;
    checks.artifact = pkgs.runCommand "minimal-sdk-consumer-check" { } ''
      grep -Fx checked ${artifact}
      touch "$out"
    '';
    acceptanceChecks.acceptance = pkgs.runCommand
      "minimal-sdk-acceptance-check" { } ''
        grep -Fx accepted ${acceptance}
        touch "$out"
      '';
  };
  changedWorkflow = workflow // {
    semanticImplementationSelections =
      workflow.semanticImplementationSelections // {
        default.derivation = changedDefaultImplementationSelection;
      };
  };
  changedTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    workflow = changedWorkflow;
    inherit candidateTests;
    inputs.baseline = artifact;
  };
  testChangedTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    inherit workflow;
    candidateTests = changedCandidateTests;
    inputs.baseline = artifact;
  };
  failingWorkflow = workflow // {
    components = workflow.components // {
      v6WorkPackages = workflow.components.v6WorkPackages // {
        example.derivation = failingConfigurationStatus;
      };
    };
  };
  failingTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    workflow = failingWorkflow;
    inherit candidateTests;
    inputs.baseline = artifact;
  };
  analysisWorkflow = workflow // {
    hasComponents = false;
    components = null;
    configurationIds = [ "faithful" ];
    nativeRealizations.faithful = realization;
    semanticImplementationSelections.faithful.derivation =
      defaultImplementationSelection;
  };
  analysisTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-analysis-target-bundle;
    workflow = analysisWorkflow;
    inputs.baseline = artifact;
  };
  registry = sdk.target.registry {
    minimal-sdk-consumer = target;
    minimal-analysis-consumer = analysisTarget;
  };
  callerArgs = {
    namePrefix = "sdk-caller";
    targetId = "minimal-sdk-consumer";
    componentId = "example";
    interfacePackage = artifact;
    sourcePackage = artifact;
  };
  # These are dependency-graph probes. Real definitions and proofs are checked
  # by the public caller fixtures; mock inputs here must never authorize them.
  composition = { definition = artifact; exactSlice = artifact; supplier = artifact; };
  preparedCaller = sdk.lifting.sourceCheck callerArgs;
  checkedCaller = sdk.lifting.sourceCheck (callerArgs // {
    localContracts = true; callerComposition = composition;
  });
  changedCaller = sdk.lifting.sourceCheck (callerArgs // {
    localContracts = true;
    callerComposition = composition // { definition = acceptance; supplier = acceptance; };
  });
  networkCaller = sdk.lifting.sourceCheck (callerArgs // {
    localContracts = true;
    callerComposition = composition // { supplier = { initialize = artifact; update = acceptance; }; };
  });
  terminalSupplier = sdk.lifting.sourceCheck (callerArgs // {
    localContracts = true;
    terminalServices = acceptance;
    originalComparison = {
      exactSlice = artifact; bindingIntent = artifact; machineDomain = artifact; serviceBindings = acceptance;
    };
  });
  callerInputs = phase: lib.splitString "\n"
    phase.derivation.SPAGHETTI_CA_DECLARED_INPUT_REFERENCES;
  lib = pkgs.lib;
  rejectsCaller = extra: !(builtins.tryEval ((sdk.lifting.sourceCheck
    (callerArgs // { localContracts = true; callerComposition = composition; } // extra))
    .derivation.drvPath)).success;
  callerTarget = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    inherit workflow;
    inputs.baseline = artifact;
    callerCompositions.example = composition;
  };
in
assert builtins.elem (toString preparedCaller.derivation) (callerInputs checkedCaller);
assert builtins.elem (toString preparedCaller.derivation) (callerInputs changedCaller);
assert builtins.elem (toString preparedCaller.derivation) (callerInputs networkCaller);
assert builtins.elem (toString artifact) (callerInputs networkCaller);
assert builtins.elem (toString acceptance) (callerInputs networkCaller);
assert networkCaller.derivation.drvPath != checkedCaller.derivation.drvPath;
assert builtins.elem (toString acceptance) (callerInputs terminalSupplier);
assert builtins.elem (toString artifact) (callerInputs terminalSupplier);
assert checkedCaller.derivation.drvPath != changedCaller.derivation.drvPath;
assert callerTarget.operator.components.units.example.sourceCheck
  == target.operator.components.units.example.sourceCheck;
assert callerTarget.operator.components.units.example.sourceContractCheck
  != target.operator.components.units.example.sourceContractCheck;
assert callerTarget.operator.components.units.example.workPackage == acceptance;
assert callerTarget.operator.boundaries.subjects."component:example".source == acceptance;
assert rejectsCaller { localContracts = false; };
assert rejectsCaller { sourceCallRegions = artifact; };
assert rejectsCaller { sourceRegionGraphs = artifact; };
assert rejectsCaller { terminalServices = artifact; };
assert rejectsCaller { localContractDependencies = [ { package = artifact; operationId = "example"; } ]; };
assert rejectsCaller { callerComposition = composition // { misspelled = true; }; };
assert rejectsCaller { callerComposition = builtins.removeAttrs composition [ "supplier" ]; };
assert !(rejectsCaller { callerComposition = composition // { supplier = { }; }; });
assert rejectsCaller { callerComposition = composition // { previous = artifact; }; previousLocalContract = artifact; };
assert sdk.format == "spaghetti-extractor-target-sdk-v5";
assert builtins.isFunction sdk.environment.pe32;
assert builtins.isFunction sdk.environment.nativeCallthroughProfile;
assert builtins.isFunction sdk.workflow.pe32Project;
assert builtins.isFunction sdk.candidate.nativeRealizationV2;
assert !(sdk.candidate ? generatedBehavioralCProvider);
assert !(sdk.candidate ? implementationSelection);
assert !(sdk.candidate ? nativeRealization);
assert pe32WorkflowArguments ? externalEnvironment;
assert pe32WorkflowArguments ? lifting;
assert pe32WorkflowArguments ? backend;
assert pe32WorkflowArguments ? analysisLimits;
assert pe32WorkflowArguments ? proofSmtSolver;
assert pe32WorkflowArguments ? proofEvidenceByComponent;
assert (evidenceTarget.operator.candidate.configurations.default.selectionFor evidenceRequest).drvPath ==
  target.operator.candidate.configurations.default.selection.drvPath;
assert (evidenceTarget.operator.candidate.configurations.default.realizationFor evidenceRequest).drvPath ==
  target.operator.candidate.configurations.default.realization.drvPath;
assert evidenceTarget.operatorIndex.candidate.configurations.default.products ==
  [ "realization" "realizationFor" "selection" "selectionFor" ];
assert !(pe32WorkflowArguments ? externalProfile);
assert !(pe32WorkflowArguments ? machineImportProfiles);
assert !(pe32WorkflowArguments ? callProtocols);
assert !(pe32WorkflowArguments ? componentReviewRoot);
assert !(pe32WorkflowArguments ? componentBindingRoot);
assert !(pe32WorkflowArguments ? componentInductionRoot);
assert !(pe32WorkflowArguments ? componentRelationRoot);
assert !(pe32WorkflowArguments ? behavioralCExactRuntime);
assert !(pe32WorkflowArguments ? nativeProcessTermination);
assert registry.minimal-sdk-consumer.metadata.id == "minimal-sdk-consumer";
assert registry.minimal-sdk-consumer.defaultConfiguration == "default";
assert registry.minimal-sdk-consumer.artifacts.input.baseline == artifact;
assert registry.minimal-sdk-consumer.artifacts.components.interfaces-v5.example == artifact;
assert registry.minimal-sdk-consumer.artifacts.components.semantic-slices-v2.example == artifact;
assert registry.minimal-sdk-consumer.artifacts.candidate.native-realizations.default ==
  nativeRealizationFixture;
assert registry.minimal-sdk-consumer.operator.components.units.example.workPackage == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.interface == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.bindingIntent == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.qualification == artifact;
assert !(registry.minimal-sdk-consumer.operator.components ? configurations);
assert registry.minimal-sdk-consumer.operator.project.semanticModule == semanticModuleFixture;
assert registry.minimal-sdk-consumer.operator.candidate.configurations.default.selection ==
  defaultImplementationSelection;
assert registry.minimal-sdk-consumer.operatorIndex.format ==
  "spaghetti-extractor-operator-index-v1";
assert registry.minimal-sdk-consumer.operatorIndex.components.units.example.entryRvas ==
  [ 4096 ];
assert registry.minimal-sdk-consumer.operatorIndex.components.authoringPaths == {
  intent = "intent/components.json";
  interface_index = "contracts/interfaces-v5/index.json";
  binding_index = "contracts/bindings-v5/index.json";
};
assert registry.minimal-sdk-consumer.operatorIndex.libraries == null;
assert !(registry.minimal-sdk-consumer.operator ? libraries);
assert !(registry.minimal-sdk-consumer.artifacts ? libraries);
assert builtins.attrNames registry.minimal-sdk-consumer.operator == [
  "boundaries"
  "candidate"
  "components"
  "project"
];
assert builtins.attrNames registry.minimal-sdk-consumer.operator.components == [
  "proposals"
  "units"
];
assert registry.minimal-sdk-consumer.operatorIndex.candidate.configurations.default.products == [
  "realization"
  "selection"
];
assert target.operator.project.status.drvPath == changedTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == failingTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == testChangedTarget.operator.project.status.drvPath;
assert target.operator.candidate.configurations.default.selection.drvPath !=
  changedTarget.operator.candidate.configurations.default.selection.drvPath;
assert target.operator.candidate.configurations.default.selection.drvPath ==
  testChangedTarget.operator.candidate.configurations.default.selection.drvPath;
assert target.operator.candidate.configurations.minimal.selection.drvPath ==
  testChangedTarget.operator.candidate.configurations.minimal.selection.drvPath;
assert target.operator.candidate.configurations.default.selection.drvPath ==
  failingTarget.operator.candidate.configurations.default.selection.drvPath;
assert registry.minimal-sdk-consumer.acceptanceChecks.acceptance != null;
assert registry.minimal-analysis-consumer.defaultConfiguration == null;
assert registry.minimal-analysis-consumer.operator.components.units == { };
assert registry.minimal-analysis-consumer.operator.components.proposals ==
  workflow.analysis.componentProposals;
assert registry.minimal-analysis-consumer.operatorIndex.defaultConfiguration ==
  "faithful";
assert registry.minimal-analysis-consumer.operatorIndex.components.units == { };
assert registry.minimal-analysis-consumer.operatorIndex.components.authoringPaths == null;
assert registry.minimal-analysis-consumer.operatorIndex.libraries == null;
assert !(registry.minimal-analysis-consumer.artifacts ? libraries);
assert registry.minimal-analysis-consumer.default.implementationSelection == null;
assert registry.minimal-analysis-consumer.acceptanceChecks.component-intent != null;
pkgs.linkFarm "spaghetti-extractor-target-sdk-check" [
  { name = "regression"; path = registry.minimal-sdk-consumer.defaultCheck; }
  { name = "acceptance"; path = registry.minimal-sdk-consumer.acceptanceCheck; }
  { name = "progress"; path = registry.minimal-sdk-consumer.operator.project.status; }
  {
    name = "analysis-only-progress";
    path = registry.minimal-analysis-consumer.operator.project.status;
  }
  {
    name = "component-mutation-project-status";
    path = changedTarget.operator.project.status;
  }
  {
    name = "failing-component-project-status";
    path = failingTarget.operator.project.status;
  }
  {
    name = "changed-candidate-selection";
    path = changedTarget.operator.candidate.configurations.default.selection;
  }
  {
    name = "test-metadata-changed-candidate-selection";
    path = testChangedTarget.operator.candidate.configurations.minimal.selection;
  }
]
