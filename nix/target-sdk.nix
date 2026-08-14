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
  structuralDiagnostics = callWith ./structural-diagnostics.nix candidateCommon;
  candidateTestSuite = callWith ./candidate-test-suite.nix candidateCommon;
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
      };
      structuralDiagnostic = structuralDiagnostics {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        machineImportProfiles = machineImportProfiles
          ++ candidateMachineImportProfiles;
        namePrefix = "${namePrefix}-structural";
      };
      configurationIds = builtins.attrNames components.runtimeConfigurations;
      staticCandidates = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = candidateFor { inherit configurationId; };
      }) configurationIds);
      candidateTestFor = {
        id,
        configurationId,
        suite,
        timeoutSeconds ? 30,
        stripStderrLineRegexes ? [ ],
      }: candidateTestSuite {
        inherit id configurationId suite timeoutSeconds stripStderrLineRegexes;
        namePrefix = "${namePrefix}-${configurationId}";
        candidateBinary = "${staticCandidates.${configurationId}.candidate}/candidate.exe";
        authorityGate = authority.finalAuthorityGate;
      };
    in {
      inherit analysis authority components interpreter candidateFor
        candidateTestFor configurationIds staticCandidates structuralDiagnostic;
      componentRuntimeFor = components.runtimeFor;
      componentRuntimes = components.runtimePackages;
      candidates = {
        static = staticCandidates;
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
    candidateTests ? { },
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
          statuses = workflow.components.statusReports;
          work-packages = workflow.components.workPackages;
          configurations = workflow.components.activationPlans;
          configuration-statuses =
            workflow.components.configurationStatusReports;
          source-bundles = workflow.components.sourceBundles;
          runtimes = workflow.componentRuntimes;
          bundle = workflow.components.bundle;
        };
        diagnostics.structural = workflow.structuralDiagnostic;
        candidate = {
          static = lib.mapAttrs (_: candidate: projectCandidate candidate)
            workflow.staticCandidates;
          tests = lib.mapAttrs (_: test: test.aggregate) candidateTests;
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
      } // lib.mapAttrs' (id: test:
        lib.nameValuePair "candidate-test-${id}" test.aggregate) candidateTests;
      bundle = mkBundleRecord {
        inherit targetRoot apps;
        artifacts = standardArtifacts;
        checks = standardChecks // checks;
        acceptanceChecks = standardAcceptanceChecks // acceptanceChecks;
      };
      projectAnalysis = pkgs.linkFarm
        "spaghetti-extractor-${metadata.id}-project-analysis"
        (lib.mapAttrsToList (name: path: { inherit name path; })
          standardArtifacts.analysis);
      componentUnits = lib.mapAttrs (id: _index: {
        workPackage = workflow.components.workPackages.${id};
        status = workflow.components.statusReports.${id};
        check = workflow.components.checkGates.${id};
      }) workflow.components.liftUnitIndex;
      componentConfigurations = lib.mapAttrs (id: _index: {
        runtime = workflow.componentRuntimes.${id};
        status = workflow.components.configurationStatusReports.${id};
        check = workflow.components.configurationCheckGates.${id};
      }) workflow.components.configurationIndex;
      candidateTestAggregate =
        if candidateTests == { } then null else
        pkgs.linkFarm "spaghetti-extractor-${metadata.id}-candidate-tests"
          (lib.mapAttrsToList (name: test: {
            inherit name;
            path = test.aggregate;
          }) candidateTests);
      operatorIndex = {
        targetId = metadata.id;
        inherit defaultConfiguration;
        components = {
          units = workflow.components.liftUnitIndex;
          configurations = workflow.components.configurationIndex;
        };
        candidate = {
          configurations = configurationIds;
          testSuites = lib.mapAttrs (_: test: {
            configurationId = test.configurationId;
            caseIds = test.caseIds;
          }) candidateTests;
        };
      };
      operator = {
        index = operatorIndex;
        project = {
          analysis = projectAnalysis;
          status = workflow.authority.diagnostics;
          regressionCheck = bundle.defaultCheck;
          acceptanceCheck = bundle.acceptanceCheck;
          structuralDiagnostics = workflow.structuralDiagnostic;
        };
        components = {
          units = componentUnits;
          configurations = componentConfigurations;
        };
        candidate = {
          builds = lib.mapAttrs (_: candidate: candidate.candidate)
            workflow.staticCandidates;
          tests = lib.mapAttrs (_: test: test.aggregate) candidateTests;
          allTests = candidateTestAggregate;
        };
      };
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v2";
      assert builtins.isString defaultConfiguration
        && builtins.elem defaultConfiguration configurationIds;
      assert builtins.all
        (test:
          test._type or null == "spaghetti-extractor-candidate-test-suite-v1"
          && builtins.elem test.configurationId configurationIds)
        (builtins.attrValues candidateTests);
      bundle // {
        inherit defaultConfiguration candidateTests operator operatorIndex;
        default = {
          componentRuntime = workflow.componentRuntimes.${defaultConfiguration};
          staticCandidate = workflow.staticCandidates.${defaultConfiguration};
          structuralDiagnostic = workflow.structuralDiagnostic;
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
    structuralDiagnostics = structuralDiagnostics;
    testSuite = candidateTestSuite;
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
