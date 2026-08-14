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
  mkBundle = {
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
        "spaghetti-extractor-${targetId}-bundle-contract-v1"
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
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v1";
      assert builtins.isString targetId && targetId != "";
      assert builtins.isAttrs artifacts && builtins.isAttrs checks
        && builtins.isAttrs acceptanceChecks && builtins.isAttrs apps;
      {
        _type = "spaghetti-extractor-target-definition-v3";
        inherit metadata artifacts apps defaultCheck acceptanceCheck;
        checks = regressionChecks;
        inherit acceptanceChecks;
      };
  validateRegistry = registry:
    assert lib.all
      (id:
        let bundle = registry.${id};
        in bundle._type or null == "spaghetti-extractor-target-definition-v3"
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
      components = componentWorkflow {
        machineIr = analysis.machineIr;
        reconstructionPlan = analysis.reconstructionPlan;
        componentProposals = analysis.componentProposals;
        intent = componentIntent;
        reviewRoot = componentReviewRoot;
        sourceRoot = componentSourceRoot;
        inherit namePrefix;
      };
      candidateFor = {
        configurationId,
        extraMachineImportProfiles ? [ ],
        compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
      }: hybridCandidate {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        staticAuthority = authority;
        machineImportProfiles = machineImportProfiles ++ extraMachineImportProfiles;
        namePrefix = "${namePrefix}-${configurationId}";
        inherit compiler;
        componentConfiguration = components.runtimeConfigurations.${configurationId};
        allowDeferredPotentialTransfers = false;
      };
      diagnosticFor = {
        configurationId ? null,
        extraMachineImportProfiles ? [ ],
        compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
      }: hybridCandidate {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        machineImportProfiles = machineImportProfiles ++ extraMachineImportProfiles;
        namePrefix = "${namePrefix}-diagnostic";
        inherit compiler;
        candidateMode = "structural-diagnostic";
        allowDeferredPotentialTransfers = true;
        diagnosticFailureTrap = true;
        componentConfiguration =
          if configurationId == null then null
          else components.runtimeConfigurations.${configurationId};
      };
    in {
      inherit analysis authority components candidateFor diagnosticFor;
      componentRuntimeFor = configurationId:
        (diagnosticFor { inherit configurationId; }).componentRuntime;
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
    bundle = mkBundle;
    registry = validateRegistry;
  };
}
