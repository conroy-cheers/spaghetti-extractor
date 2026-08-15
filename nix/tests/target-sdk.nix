{ pkgs }:

let
  sdk = import ../target-sdk.nix { inherit pkgs; };
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  acceptance = pkgs.writeText "minimal-sdk-acceptance-artifact" "accepted\n";
  authorityDiagnostics = pkgs.writeText "minimal-sdk-authority-diagnostics.json"
    (builtins.toJSON {
      format = "spaghetti-extractor-authority-diagnostics-v3";
      status = "complete";
      authorizing = true;
      counts = {
        primary_frontiers = 0;
        dependent_occurrences = 0;
      };
      primary_frontiers = [ ];
    });
  configurationStatus = pkgs.writeText "minimal-sdk-configuration-status.json"
    (builtins.toJSON {
      format = "spaghetti-extractor-component-configuration-status-v1";
      configuration_id = "default";
      status = "ready";
      counts.blocked = 0;
      blockers = [ ];
    });
  candidate = {
    interpreter = artifact;
    componentRuntime = artifact;
    machineImportProfileBundle = artifact;
    fallbackCoverageReceipt = artifact;
    candidateAuthorityReport = artifact;
    candidateAuthorityGate = artifact;
    nativeEngine = artifact;
    nativeRuntime = artifact;
    nativeObjects.package = artifact;
    candidate = artifact;
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
      diagnostics = pkgs.runCommand "minimal-sdk-authority-diagnostics" { } ''
        mkdir -p "$out"
        cp ${authorityDiagnostics} "$out/authority-diagnostics-v3.json"
      '';
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
      evidences.example = artifact;
      qualifications.example = artifact;
      activationPlans.default = artifact;
      activationPlans.minimal = artifact;
      sourceBundles.default = artifact;
      sourceBundles.minimal = artifact;
      statusReports.example = artifact;
      workPackages.example = artifact;
      checkGates.example = artifact;
      configurationStatusReports.default = pkgs.runCommand
        "minimal-sdk-configuration-status" { } ''
          mkdir -p "$out"
          cp ${configurationStatus} "$out/status.json"
        '';
      configurationStatusReports.minimal = pkgs.runCommand
        "minimal-sdk-configuration-status-minimal" { } ''
          mkdir -p "$out"
          ${pkgs.jq}/bin/jq '.configuration_id = "minimal"' \
            ${configurationStatus} > "$out/status.json"
        '';
      configurationCheckGates.default = artifact;
      configurationCheckGates.minimal = artifact;
      liftUnitIndex.example = {
        kind = "component";
        label = "Example";
        members = [ ];
        hasSource = true;
        hasEvidence = true;
        hasQualification = true;
      };
      configurationIndex.default = {
        kind = "configuration";
        label = "Default";
        selections = [ ];
        hasRuntime = true;
      };
      configurationIndex.minimal = {
        kind = "configuration";
        label = "Minimal";
        selections = [ ];
        hasRuntime = true;
      };
      bundle = artifact;
    };
    componentRuntimes.default = artifact;
    componentRuntimes.minimal = artifact;
    staticCandidates.default = candidate;
    staticCandidates.minimal = candidate;
    structuralDiagnostic = artifact;
  };
  changedConfigurationStatus = pkgs.runCommand
    "minimal-sdk-configuration-status-changed" { } ''
      mkdir -p "$out"
      ${pkgs.jq}/bin/jq '.counts.revision = 2' \
        ${configurationStatus} > "$out/status.json"
    '';
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
    components = workflow.components // {
      configurationStatusReports =
        workflow.components.configurationStatusReports // {
          default = changedConfigurationStatus;
        };
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
      configurationStatusReports =
        workflow.components.configurationStatusReports // {
          default = failingConfigurationStatus;
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
    componentRuntimeFor = null;
    componentRuntimes = { };
    staticCandidates = { };
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
assert sdk.format == "spaghetti-extractor-target-sdk-v3";
assert registry.minimal-sdk-consumer.metadata.id == "minimal-sdk-consumer";
assert registry.minimal-sdk-consumer.defaultConfiguration == "default";
assert registry.minimal-sdk-consumer.artifacts.input.baseline == artifact;
assert registry.minimal-sdk-consumer.artifacts.components.runtimes.default == artifact;
assert registry.minimal-sdk-consumer.artifacts.candidate.static.default.candidate == artifact;
assert registry.minimal-sdk-consumer.operator.components.units.example.workPackage == artifact;
assert registry.minimal-sdk-consumer.operator.components.configurations.default.runtime == artifact;
assert registry.minimal-sdk-consumer.operator.project.authorityDiagnostics == workflow.authority.diagnostics;
assert registry.minimal-sdk-consumer.operator.candidate.statuses.default != null;
assert target.operator.project.status.drvPath == changedTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == failingTarget.operator.project.status.drvPath;
assert target.operator.project.status.drvPath == testChangedTarget.operator.project.status.drvPath;
assert target.operator.candidate.statuses.default.drvPath !=
  changedTarget.operator.candidate.statuses.default.drvPath;
assert target.operator.candidate.statuses.default.drvPath ==
  testChangedTarget.operator.candidate.statuses.default.drvPath;
assert target.operator.candidate.statuses.minimal.drvPath !=
  testChangedTarget.operator.candidate.statuses.minimal.drvPath;
assert registry.minimal-sdk-consumer.acceptanceChecks.acceptance != null;
assert registry.minimal-analysis-consumer.defaultConfiguration == null;
assert registry.minimal-analysis-consumer.operatorIndex.hasComponents == false;
assert registry.minimal-analysis-consumer.operator.components.units == { };
assert registry.minimal-analysis-consumer.operator.components.proposals ==
  workflow.analysis.componentProposals;
assert registry.minimal-analysis-consumer.default.componentRuntime == null;
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
