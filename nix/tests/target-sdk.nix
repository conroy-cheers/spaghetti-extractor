# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  sdk = import ../target-sdk.nix { inherit pkgs; };
  pe32WorkflowArguments = builtins.functionArgs sdk.workflow.pe32;
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  acceptance = pkgs.writeText "minimal-sdk-acceptance-artifact" "accepted\n";
  semanticModuleFixture = pkgs.runCommand
    "minimal-sdk-linked-semantic-module-v2"
    { nativeBuildInputs = [ sdk.validation.pythonEnv ]; } ''
      mkdir -p "$out"
      export PYTHONPATH=${../../.}/src:${../../.}
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
    { nativeBuildInputs = [ pkgs.coreutils ]; } ''
      mkdir -p "$out"
      cp ${artifact} "$out/fixture.exe"
      candidate_sha256="$(sha256sum "$out/fixture.exe" | cut -d ' ' -f 1)"
      cat > "$out/native-realization.json" <<JSON
      {
        "format": "spaghetti-extractor-native-realization-v2",
        "status": "complete",
        "ready_for_observation": true,
        "blockers": [],
        "candidate": {
          "filename": "fixture.exe",
          "sha256": "$candidate_sha256"
        }
      }
      JSON
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
    nativeRealizations.default = realization;
    nativeRealizations.minimal = realization;
    calls = {
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
    configurationIds = [ ];
    nativeRealizations = { };
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
in
assert sdk.format == "spaghetti-extractor-target-sdk-v4";
assert builtins.isFunction sdk.environment.pe32;
assert builtins.isFunction sdk.workflow.pe32Project;
assert builtins.isFunction sdk.candidate.nativeRealizationV2;
assert !(sdk.candidate ? generatedBehavioralCProvider);
assert !(sdk.candidate ? implementationSelection);
assert !(sdk.candidate ? nativeRealization);
assert pe32WorkflowArguments ? externalEnvironment;
assert pe32WorkflowArguments ? lifting;
assert pe32WorkflowArguments ? backend;
assert pe32WorkflowArguments ? analysisLimits;
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
assert registry.minimal-sdk-consumer.operator.components.units.example.status == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.interface == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.bindingIntent == artifact;
assert registry.minimal-sdk-consumer.operator.components.configurations.default.selection == defaultImplementationSelection;
assert registry.minimal-sdk-consumer.operator.project.semanticModule == semanticModuleFixture;
assert registry.minimal-sdk-consumer.operator.candidate.statuses.default != null;
assert registry.minimal-sdk-consumer.operator.candidate.materializedStatus ==
  registry.minimal-sdk-consumer.operator.candidate.statuses.default;
assert registry.minimal-sdk-consumer.artifacts.diagnostics.candidate-status ==
  registry.minimal-sdk-consumer.operator.candidate.materializedStatus;
assert registry.minimal-sdk-consumer.checks.candidate-status ==
  registry.minimal-sdk-consumer.operator.candidate.materializedStatus;
assert target.operator.project.status.drvPath == changedTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == failingTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == testChangedTarget.operator.project.status.drvPath;
assert target.operator.candidate.statuses.default.drvPath !=
  changedTarget.operator.candidate.statuses.default.drvPath;
assert target.operator.candidate.statuses.default.drvPath ==
  testChangedTarget.operator.candidate.statuses.default.drvPath;
assert target.operator.candidate.statuses.minimal.drvPath ==
  testChangedTarget.operator.candidate.statuses.minimal.drvPath;
assert target.operator.candidate.statuses.default.drvPath ==
  failingTarget.operator.candidate.statuses.default.drvPath;
assert registry.minimal-sdk-consumer.acceptanceChecks.acceptance != null;
assert registry.minimal-analysis-consumer.defaultConfiguration == null;
assert registry.minimal-analysis-consumer.operatorIndex.hasComponents == false;
assert registry.minimal-analysis-consumer.operator.components.units == { };
assert registry.minimal-analysis-consumer.operator.components.proposals ==
  workflow.analysis.componentProposals;
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
    name = "changed-candidate-status";
    path = changedTarget.operator.candidate.statuses.default;
  }
  {
    name = "test-metadata-changed-candidate-status";
    path = testChangedTarget.operator.candidate.statuses.minimal;
  }
]
