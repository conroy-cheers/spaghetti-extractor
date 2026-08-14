{ pkgs }:

let
  context = import ./toolkit-context.nix { inherit pkgs; };
  lib = pkgs.lib;
  callWith = path: common: args: import path (args // common);
  analysisCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.analysisSource;
  };
  authorityCommon = analysisCommon // {
    isaPythonSource = context.sources.isaAnalysisSource;
    spaghettiExtractor = context.package;
    isaKernelCache = context.kernels.isaConformanceKernel;
    isaSemanticKernel = context.kernels.isaSemanticKernel;
    bochsRunner = context.tools.bochsRunner;
  };
  candidateCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.candidateSource;
  };
  mkBundle = {
    targetRoot,
    artifacts,
    checks ? { },
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
      allChecks = checks // { bundle-contract = contractCheck; };
      defaultCheck = pkgs.linkFarm
        "spaghetti-extractor-${targetId}-target-checks"
        (lib.mapAttrsToList (name: path: { inherit name path; }) allChecks);
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v1";
      assert builtins.isString targetId && targetId != "";
      assert builtins.isAttrs artifacts && builtins.isAttrs checks && builtins.isAttrs apps;
      {
        _type = "spaghetti-extractor-target-definition-v2";
        inherit metadata artifacts apps defaultCheck;
        checks = allChecks;
      };
  validateRegistry = registry:
    assert lib.all
      (id:
        let bundle = registry.${id};
        in bundle._type or null == "spaghetti-extractor-target-definition-v2"
          && bundle.metadata.id == id)
      (builtins.attrNames registry);
    registry;
in
{
  format = "spaghetti-extractor-target-sdk-v2";
  inherit (context) package fixtures;
  inherit (context) sources kernels tools;
  profiles = context.sources.profileSource;

  analysis = {
    component = callWith ./stage-b-component-analysis.nix analysisCommon;
    authorityV3 = callWith ./analysis-v3-authority.nix authorityCommon;
    targetIntent = callWith ./stage-b-target-intent.nix analysisCommon;
    externalInterfaceProfile = callWith
      ./stage-a-external-interface-profile.nix analysisCommon;
  };
  candidate = {
    hybrid = callWith ./stage-b-hybrid-candidate.nix candidateCommon;
    headlessDiagnostic = callWith
      ./stage-b-headless-diagnostic-run.nix candidateCommon;
    validation = callWith ./stage-b-candidate-validation.nix analysisCommon;
  };
  lifting = {
    linkedLibraries = callWith ./stage-b-linked-libraries.nix analysisCommon;
    runtimeLock = callWith ./stage-b-runtime-lock.nix analysisCommon;
    sourceProject = callWith ./stage-b-source-project.nix analysisCommon;
    portableCProject = callWith ./stage-b-portable-c-project.nix { inherit pkgs; };
    functionalSuite = callWith ./stage-b-functional-suite.nix analysisCommon;
    sourceIterationAudit = callWith
      ./stage-b-source-iteration-audit.nix analysisCommon;
    sourceLiftAudit = callWith ./stage-b-source-lift-audit.nix analysisCommon;
    clangAstBundle = callWith ./stage-b-clang-ast-bundle.nix { inherit pkgs; };
    sourceCallSubstitutions = callWith
      ./stage-b-source-call-substitutions.nix analysisCommon;
    sourceComponentAssurance = callWith
      ./stage-b-source-component-assurance.nix analysisCommon;
    sourceQualification = callWith
      ./stage-b-source-qualification.nix analysisCommon;
    runtimeQualification = callWith
      ./stage-b-runtime-qualification.nix analysisCommon;
    componentContractsV2 = callWith ./stage-b-components-v2.nix analysisCommon;
    implementationLedger = callWith
      ./stage-b-implementation-ledger.nix analysisCommon;
    completionReceipt = callWith
      ./stage-b-lift-completion-receipt.nix analysisCommon;
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
