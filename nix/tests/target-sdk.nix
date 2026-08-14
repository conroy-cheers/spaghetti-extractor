{ pkgs }:

let
  sdk = import ../target-sdk.nix { inherit pkgs; };
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  acceptance = pkgs.writeText "minimal-sdk-acceptance-artifact" "accepted\n";
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
    configurationIds = [ "default" ];
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
      diagnostics = artifact;
      graph.metadata = artifact;
      graph.phases.example.derivation = artifact;
    };
    components = {
      assetInventory = [ ];
      resolution = artifact;
      contracts.example = artifact;
      sourcePackages.example = artifact;
      evidences.example = artifact;
      qualifications.example = artifact;
      activationPlans.default = artifact;
      sourceBundles.default = artifact;
      statusReports.example = artifact;
      workPackages.example = artifact;
      checkGates.example = artifact;
      configurationStatusReports.default = artifact;
      configurationCheckGates.default = artifact;
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
      bundle = artifact;
    };
    componentRuntimes.default = artifact;
    staticCandidates.default = candidate;
    structuralDiagnostic = artifact;
  };
  target = sdk.target.pe32Bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    inherit workflow;
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
  registry = sdk.target.registry {
    minimal-sdk-consumer = target;
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
assert registry.minimal-sdk-consumer.operator.project.status == artifact;
assert registry.minimal-sdk-consumer.acceptanceChecks.acceptance != null;
pkgs.linkFarm "spaghetti-extractor-target-sdk-check" [
  { name = "regression"; path = registry.minimal-sdk-consumer.defaultCheck; }
  { name = "acceptance"; path = registry.minimal-sdk-consumer.acceptanceCheck; }
]
