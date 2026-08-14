{ pkgs }:

let
  context = import ./toolkit-context.nix { inherit pkgs; };
  lib = pkgs.lib;
  callWith = path: common: args: import path (args // common);
  analysisCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.staticSource;
  };
  authorityCommon = analysisCommon // {
    isaPythonSource = context.sources.isaSource;
    isaKernelCache = context.kernels.isaConformanceKernel;
    isaSemanticKernel = context.kernels.isaSemanticKernel;
    bochsRunner = context.tools.bochsRunner;
  };
  candidateCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.fullSource;
  };
  analysisComponent = callWith ./stage-b-component-analysis.nix analysisCommon;
  authorityWorkflow = callWith ./authority-workflow.nix authorityCommon;
  componentWorkflow = callWith ./stage-b-components.nix analysisCommon;
  hybridCandidate = callWith ./stage-b-hybrid-candidate.nix candidateCommon;
  mkBundleRecord = {
    targetRoot,
    artifacts,
    checks ? { },
    acceptanceChecks ? { },
    apps ? { },
  }:
    let
      metadata = builtins.fromJSON (builtins.readFile (targetRoot + "/target.json"));
      targetId = metadata.id or null;
      metadataFile = pkgs.writeText
        "spaghetti-extractor-${targetId}-metadata.json"
        (builtins.toJSON metadata);
      contractCheck = pkgs.runCommand
        "spaghetti-extractor-${targetId}-bundle-contract-v2"
        { __contentAddressed = true; }
        ''
          mkdir -p "$out"
          cp ${metadataFile} "$out/target.json"
          printf '%s\n' ${lib.escapeShellArg (builtins.toJSON (builtins.attrNames artifacts))} \
            > "$out/artifact-families.json"
        '';
      regressionChecks = checks // { bundle-contract = contractCheck; };
      completeAcceptanceChecks = regressionChecks // acceptanceChecks;
      defaultCheck = pkgs.linkFarm
        "spaghetti-extractor-${targetId}-target-regression-checks"
        (lib.mapAttrsToList (name: path: { inherit name path; }) regressionChecks);
      acceptanceCheck = pkgs.linkFarm
        "spaghetti-extractor-${targetId}-target-acceptance-checks"
        (lib.mapAttrsToList
          (name: path: { inherit name path; }) completeAcceptanceChecks);
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v2";
      assert builtins.isString targetId && targetId != "";
      assert builtins.isAttrs artifacts && builtins.isAttrs checks
        && builtins.isAttrs acceptanceChecks && builtins.isAttrs apps;
      {
        _type = "spaghetti-extractor-target-definition-v4";
        inherit metadata artifacts apps defaultCheck acceptanceCheck;
        checks = regressionChecks;
        inherit acceptanceChecks;
      };
  validateRegistry = registry:
    assert lib.all
      (id:
        let bundle = registry.${id};
        in bundle._type or null == "spaghetti-extractor-target-definition-v4"
          && bundle.metadata.id == id)
      (builtins.attrNames registry);
    registry;
  mkPe32Workflow = {
    original,
    binaryIdentity,
    externalProfile,
    machineImportProfiles ? [ externalProfile ],
    launchProfileTemplate,
    namePrefix,
    componentIntent,
    componentReviewRoot ? null,
    componentSourceRoot ? null,
    externalInterfaceProfiles ? [ ],
    candidateMachineImportProfiles ? [ ],
    maxUnits ? 512,
    maxCandidatesPerSeed ? 12,
  }:
    let
      analysis = analysisComponent {
        inherit original externalProfile externalInterfaceProfiles namePrefix;
        additionalMachineImportProfiles = builtins.tail machineImportProfiles;
        inherit launchProfileTemplate maxUnits maxCandidatesPerSeed;
      };
      authority = authorityWorkflow {
        name = "${namePrefix}-authority-v3";
        machineIr = "${analysis.machineIr}/machine-ir.jsonl";
        binary = original;
        inherit binaryIdentity machineImportProfiles launchProfileTemplate;
      };
      interpreter = assert lib.assertMsg (authority.fallbackInterpreter != null)
        "PE32 workflows require the standard machine-IR interpreter";
        authority.fallbackInterpreter;
      components = componentWorkflow {
        machineIr = analysis.machineIr;
        reconstructionPlan = analysis.reconstructionPlan;
        componentProposals = analysis.componentProposals;
        intent = componentIntent;
        reviewRoot = componentReviewRoot;
        sourceRoot = componentSourceRoot;
        inherit namePrefix;
        interpreterPackage = interpreter;
      };
      candidateFor = {
        configurationId,
        extraMachineImportProfiles ? [ ],
        compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
      }: hybridCandidate {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        staticAuthority = authority;
        machineImportProfiles = machineImportProfiles
          ++ candidateMachineImportProfiles
          ++ extraMachineImportProfiles;
        namePrefix = "${namePrefix}-${configurationId}";
        inherit compiler;
        interpreterPackage = interpreter;
        componentRuntimePackage = components.mkRuntime {
          inherit configurationId;
          runtimeCompiler = compiler;
        };
        allowDeferredPotentialTransfers = false;
      };
      diagnosticFor = {
        configurationId ? null,
        extraMachineImportProfiles ? [ ],
        compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
      }: hybridCandidate {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        machineImportProfiles = machineImportProfiles
          ++ candidateMachineImportProfiles
          ++ extraMachineImportProfiles;
        namePrefix = "${namePrefix}-${if configurationId == null then "fallback" else configurationId}-diagnostic";
        inherit compiler;
        interpreterPackage = interpreter;
        candidateMode = "structural-diagnostic";
        allowDeferredPotentialTransfers = true;
        diagnosticFailureTrap = true;
        componentRuntimePackage =
          if configurationId == null then null
          else components.mkRuntime {
            inherit configurationId;
            runtimeCompiler = compiler;
          };
      };
      configurationIds = builtins.attrNames components.runtimeConfigurations;
      staticCandidates = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = candidateFor { inherit configurationId; };
      }) configurationIds);
      diagnosticCandidates = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = diagnosticFor { inherit configurationId; };
      }) configurationIds);
    in {
      inherit analysis authority components interpreter candidateFor diagnosticFor
        configurationIds staticCandidates diagnosticCandidates;
      componentRuntimeFor = components.runtimeFor;
      componentRuntimes = components.runtimePackages;
      candidates = {
        static = staticCandidates;
        diagnostic = diagnosticCandidates;
      };
    };
  projectCandidate = candidate: lib.filterAttrs (_name: value: value != null) {
    inherit (candidate) interpreter componentRuntime machineImportProfileBundle
      fallbackCoverageReceipt candidateAuthorityReport candidateAuthorityGate
      nativeEngine nativeRuntime candidate;
    nativeObjects = candidate.nativeObjects.package;
  };
  mkPe32Bundle = {
    targetRoot,
    workflow,
    inputs,
    profiles ? { },
    extraArtifacts ? { },
    checks ? { },
    acceptanceChecks ? { },
    apps ? { },
  }:
    let
      metadata = builtins.fromJSON (builtins.readFile (targetRoot + "/target.json"));
      defaultConfiguration = metadata.workflow.default_configuration or null;
      configurationIds = workflow.configurationIds;
      standardArtifacts = {
        input = inputs;
        inherit profiles;
        analysis = {
          inventory = workflow.analysis.originalInventory;
          static-export = workflow.analysis.staticExport;
          launch-assumptions = workflow.analysis.launchAnalysisAssumptions;
          state-machine = workflow.analysis.stateMachine;
          machine-ir = workflow.analysis.machineIr;
          reconstruction-plan = workflow.analysis.reconstructionPlan;
          component-proposals = workflow.analysis.componentProposals;
        };
        authority = {
          final = workflow.authority.finalAuthority;
          gate = workflow.authority.finalAuthorityGate;
          diagnostics = workflow.authority.diagnostics;
          graph-metadata = workflow.authority.graph.metadata;
          phases = lib.mapAttrs (_: phase: phase.derivation)
            workflow.authority.graph.phases;
        };
        components = {
          resolution = workflow.components.resolution;
          contracts = workflow.components.contracts;
          source-packages = workflow.components.sourcePackages;
          evidence = workflow.components.evidences;
          qualifications = workflow.components.qualifications;
          configurations = workflow.components.activationPlans;
          source-bundles = workflow.components.sourceBundles;
          runtimes = workflow.componentRuntimes;
          bundle = workflow.components.bundle;
        };
        candidate = {
          static = lib.mapAttrs (_: candidate: projectCandidate candidate)
            workflow.staticCandidates;
          diagnostic = lib.mapAttrs (_: candidate: projectCandidate candidate)
            workflow.diagnosticCandidates;
        };
      } // lib.optionalAttrs (builtins.attrNames extraArtifacts != [ ]) {
        target = extraArtifacts;
      };
      standardChecks = {
        component-resolution = workflow.components.resolution;
        default-component-configuration =
          workflow.components.activationPlans.${defaultConfiguration};
      };
      standardAcceptanceChecks = {
        final-authority = workflow.authority.finalAuthorityGate;
        default-static-candidate =
          workflow.staticCandidates.${defaultConfiguration}.candidate;
      };
      bundle = mkBundleRecord {
        inherit targetRoot apps;
        artifacts = standardArtifacts;
        checks = standardChecks // checks;
        acceptanceChecks = standardAcceptanceChecks // acceptanceChecks;
      };
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v2";
      assert builtins.isString defaultConfiguration
        && builtins.elem defaultConfiguration configurationIds;
      bundle // {
        inherit defaultConfiguration;
        default = {
          componentRuntime = workflow.componentRuntimes.${defaultConfiguration};
          staticCandidate = workflow.staticCandidates.${defaultConfiguration};
          diagnosticCandidate = workflow.diagnosticCandidates.${defaultConfiguration};
        };
      };
in
{
  format = "spaghetti-extractor-target-sdk-v3";
  inherit (context) package fixtures;
  inherit (context) sources kernels tools;
  profiles = context.sources.profileSource;

  workflow.pe32 = mkPe32Workflow;
  analysis = {
    component = analysisComponent;
    authority = authorityWorkflow;
    externalInterfaceProfile = callWith
      ./stage-a-external-interface-profile.nix analysisCommon;
  };
  candidate = {
    hybrid = hybridCandidate;
    headlessDiagnostic = callWith
      ./stage-b-headless-diagnostic-run.nix candidateCommon;
  };
  lifting = {
    linkedLibraries = callWith ./stage-b-linked-libraries.nix analysisCommon;
    functionalSuite = callWith ./stage-b-functional-suite.nix analysisCommon;
    components = componentWorkflow;
  };
  validation = {
    testRunner = context.packages.testkitTestRunner;
    testSuite = callWith ./test-suite.nix {
      inherit pkgs;
      inherit (context) pythonEnv fixtures;
    };
    upstreamShellSuite = import ./stage-b-upstream-shell-suite.nix { inherit pkgs; };
  };
  target = {
    pe32Bundle = mkPe32Bundle;
    registry = validateRegistry;
  };
}
