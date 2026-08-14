# spaghetti-extractor-python-role: operator
{ pkgs }:

let
  context = import ./toolkit-context.nix { inherit pkgs; };
  lib = pkgs.lib;
  callWith = path: common: args:
    let
      function = import path;
      accepted = builtins.functionArgs function;
      unknown = builtins.attrNames (
        builtins.removeAttrs args (builtins.attrNames accepted)
      );
      selectedCommon = lib.filterAttrs
        (name: _: builtins.hasAttr name accepted) common;
    in
      assert unknown == [ ];
      function (args // selectedCommon);
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
  targetBundleLint = callWith ./target-bundle-lint.nix analysisCommon;
  progressPythonSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.progress" ];
    name = "spaghetti-extractor-target-progress-python-closure";
  };
  exactAttrs = value: names:
    builtins.isAttrs value
    && builtins.attrNames value == builtins.sort builtins.lessThan names;
  parseTargetMetadata = targetRoot:
    let
      metadata = builtins.fromJSON (builtins.readFile (targetRoot + "/target.json"));
      input = metadata.input or null;
      paths = metadata.paths or null;
      workflow = metadata.workflow or null;
      identifier = value:
        builtins.isString value && value != ""
        && builtins.match "[a-z0-9]([a-z0-9._-]*[a-z0-9])?" value != null;
      relativePath = value:
        builtins.isString value && value != ""
        && builtins.substring 0 1 value != "/"
        && lib.all (part: part != "" && part != "." && part != "..")
          (lib.splitString "/" value);
    in
      assert exactAttrs metadata [ "display_name" "format" "id" "input" "paths" "workflow" ];
      assert metadata.format == "spaghetti-extractor-target-bundle-v2";
      assert identifier metadata.id;
      assert builtins.isString metadata.display_name && metadata.display_name != "";
      assert exactAttrs input [ "expected_sha256" "kind" ];
      assert input.kind == "pe32";
      assert builtins.isString input.expected_sha256
        && builtins.stringLength input.expected_sha256 == 64
        && builtins.match "[0-9a-f]*" input.expected_sha256 != null;
      assert exactAttrs paths [ "components" "nix" ];
      assert lib.all (name: relativePath paths.${name})
        (builtins.attrNames paths);
      assert exactAttrs workflow [ "default_configuration" ];
      assert identifier workflow.default_configuration;
      metadata;
  mkBundleRecord = {
    targetRoot,
    artifacts,
    checks ? { },
    acceptanceChecks ? { },
    apps ? { },
  }:
    let
      metadata = parseTargetMetadata targetRoot;
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
      originalBinary = original;
      inherit binaryIdentity;
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
    targetAssets ? { },
    apps ? { },
  }:
    let
      metadata = parseTargetMetadata targetRoot;
      targetRootString = toString targetRoot;
      relativeTargetPath = path:
        let
          value = toString path;
          prefix = "${targetRootString}/";
        in assert lib.assertMsg (lib.hasPrefix prefix value)
          "target asset ${value} is outside ${targetRootString}";
          lib.removePrefix prefix value;
      metadataAssets = [ {
        path = "target.json";
        role = "metadata";
        owner = "target-sdk";
      } ] ++ lib.optional (metadata.paths ? nix) {
        path = metadata.paths.nix;
        role = "module";
        owner = "target-sdk";
      };
      componentAssets = map (asset: asset // {
        path = relativeTargetPath asset.path;
      }) workflow.components.assetInventory;
      candidateTestAssets = lib.mapAttrsToList (id: test: {
        path = relativeTargetPath test.suite;
        role = "candidate_test";
        owner = id;
      }) candidateTests;
      manualAssetRoles = [ "runtime" "documentation" "license" ];
      invalidManualRoles = lib.subtractLists manualAssetRoles
        (builtins.attrNames targetAssets);
      manualAssets = lib.concatMap (role: map (path: {
        inherit path role;
        owner = "target-bundle";
      }) (targetAssets.${role} or [ ])) manualAssetRoles;
      declaredAssets = metadataAssets ++ componentAssets
        ++ candidateTestAssets ++ manualAssets;
      ownership = targetBundleLint {
        inherit targetRoot declaredAssets;
        targetId = metadata.id;
        namePrefix = "spaghetti-extractor-${metadata.id}";
      };
      defaultConfiguration = metadata.workflow.default_configuration or null;
      configurationIds = workflow.configurationIds;
      targetInputIdentity = pkgs.runCommand
        "spaghetti-extractor-${metadata.id}-target-input-identity-v1"
        {
          nativeBuildInputs = [ pkgs.coreutils pkgs.jq ];
          preferLocalBuild = false;
          allowSubstitutes = true;
          __contentAddressed = true;
        }
        ''
          set -euo pipefail
          actual="$(sha256sum ${lib.escapeShellArg workflow.originalBinary} | cut -d ' ' -f 1)"
          expected=${lib.escapeShellArg metadata.input.expected_sha256}
          if [ "$actual" != "$expected" ]; then
            echo "target ${metadata.id} primary PE hash mismatch" >&2
            echo "expected: $expected" >&2
            echo "observed: $actual" >&2
            exit 1
          fi
          mkdir -p "$out"
          jq -n --arg target ${lib.escapeShellArg metadata.id} \
            --arg binary ${lib.escapeShellArg workflow.binaryIdentity} \
            --arg sha256 "$actual" '{
              format: "spaghetti-extractor-target-input-identity-v1",
              status: "checked",
              target_id: $target,
              binary_identity: $binary,
              sha256: $sha256
            }' > "$out/target-input-identity.json"
        '';
      standardArtifacts = {
        identity = targetInputIdentity;
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
        diagnostics = {
          structural = workflow.structuralDiagnostic;
          target-ownership = ownership;
        };
        candidate = {
          static = lib.mapAttrs (_: candidate: projectCandidate candidate)
            workflow.staticCandidates;
          tests = lib.mapAttrs (_: test: test.aggregate) candidateTests;
        };
      } // lib.optionalAttrs (builtins.attrNames extraArtifacts != [ ]) {
        target = extraArtifacts;
      };
      standardChecks = {
        target-bundle-assets = ownership;
        target-input-identity = targetInputIdentity;
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
        ([ {
          name = "target-input-identity";
          path = targetInputIdentity;
        } ] ++ lib.mapAttrsToList
          (name: path: { inherit name path; }) standardArtifacts.analysis);
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
          ([ {
            name = "target-input-identity";
            path = targetInputIdentity;
          } ] ++ lib.mapAttrsToList (name: test: {
            inherit name;
            path = test.aggregate;
          }) candidateTests);
      candidateTestIndex = lib.mapAttrs (_: test: {
        configurationId = test.configurationId;
        caseIds = test.caseIds;
      }) candidateTests;
      mkProgress = configurationId:
        pkgs.runCommand
          "spaghetti-extractor-${metadata.id}-${configurationId}-project-progress-v1"
          {
            nativeBuildInputs = [ context.pythonEnv pkgs.jq ];
            preferLocalBuild = false;
            allowSubstitutes = true;
            __contentAddressed = true;
          }
          ''
            set -euo pipefail
            test -s ${targetInputIdentity}/target-input-identity.json
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export PYTHONPATH=${progressPythonSource}/src
            mkdir -p "$out"
            ${context.pythonEnv}/bin/python3 - \
              ${workflow.authority.diagnostics}/authority-diagnostics-v3.json \
              ${workflow.components.configurationStatusReports.${configurationId}}/status.json \
              ${lib.escapeShellArg metadata.id} \
              ${lib.escapeShellArg configurationId} \
              ${lib.escapeShellArg (builtins.toJSON candidateTestIndex)} \
              "$out/project-progress.json" <<'PY'
            import json
            import pathlib
            import sys
            from spaghetti_extractor.target_bundles.progress import build_project_progress

            build_project_progress(
                authority_diagnostics=pathlib.Path(sys.argv[1]),
                configuration_status=pathlib.Path(sys.argv[2]),
                target_id=sys.argv[3],
                configuration_id=sys.argv[4],
                candidate_test_suites=json.loads(sys.argv[5]),
                out=pathlib.Path(sys.argv[6]),
            )
            PY
            jq -e '
              .format == "spaghetti-extractor-project-progress-v1" and
              (.status == "ready" or .status == "incomplete" or .status == "violated") and
              (.authorizing | not) and
              .policy.diagnostic_only and
              (.policy.candidate_gate_bypassed | not) and
              (.policy.original_binary_executed | not)
            ' "$out/project-progress.json" >/dev/null
          '';
      progressReports = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = mkProgress configurationId;
      }) configurationIds);
      checkedCandidateBuilds = lib.mapAttrs (configurationId: candidate:
        pkgs.runCommand
          "spaghetti-extractor-${metadata.id}-${configurationId}-checked-candidate"
          { __contentAddressed = true; } ''
            set -euo pipefail
            test -s ${targetInputIdentity}/target-input-identity.json
            mkdir -p "$out"
            cp -rs ${candidate.candidate}/. "$out/"
            ln -s ${targetInputIdentity}/target-input-identity.json \
              "$out/target-input-identity.json"
          '') workflow.staticCandidates;
      checkedCandidateTests = lib.mapAttrs (id: test:
        pkgs.linkFarm
          "spaghetti-extractor-${metadata.id}-${id}-checked-candidate-test" [
            { name = "target-input-identity"; path = targetInputIdentity; }
            { name = "candidate-test"; path = test.aggregate; }
          ]) candidateTests;
      operatorIndex = {
        targetId = metadata.id;
        inherit defaultConfiguration;
        components = {
          units = workflow.components.liftUnitIndex;
          configurations = workflow.components.configurationIndex;
        };
        candidate = {
          configurations = configurationIds;
          testSuites = candidateTestIndex;
        };
      };
      operator = {
        index = operatorIndex;
        project = {
          analysis = projectAnalysis;
          status = progressReports.${defaultConfiguration};
          authorityStatus = workflow.authority.diagnostics;
          regressionCheck = bundle.defaultCheck;
          acceptanceCheck = bundle.acceptanceCheck;
          structuralDiagnostics = workflow.structuralDiagnostic;
        };
        components = {
          units = componentUnits;
          configurations = componentConfigurations;
        };
        candidate = {
          builds = checkedCandidateBuilds;
          statuses = progressReports;
          tests = checkedCandidateTests;
          allTests = candidateTestAggregate;
        };
      };
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v2";
      assert builtins.isString defaultConfiguration
        && builtins.elem defaultConfiguration configurationIds;
      assert lib.assertMsg (invalidManualRoles == [ ])
        "targetAssets contains unsupported roles: ${builtins.toJSON invalidManualRoles}";
      assert lib.assertMsg
        (!(metadata.paths ? components) ||
          (workflow.components.assetInventory != [ ] &&
            metadata.paths.components == relativeTargetPath
              (builtins.head workflow.components.assetInventory).path))
        "target metadata component intent does not match the workflow intent";
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
