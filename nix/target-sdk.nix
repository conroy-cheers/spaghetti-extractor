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
    relationKernel = context.kernels.relationKernel;
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
  analysisComponent = callWith ./component-analysis.nix analysisCommon;
  authorityWorkflow = callWith ./authority-workflow.nix authorityCommon;
  componentWorkflow = callWith ./component-workflow.nix analysisCommon;
  callProtocolWorkflow = callWith ./call-protocol-workflow.nix analysisCommon;
  hybridCandidate = callWith ./candidate-hybrid.nix candidateCommon;
  runtimeFrontierReport = callWith ./runtime-frontier-report.nix analysisCommon;
  candidateTestSuite = callWith ./candidate-test-suite.nix candidateCommon;
  targetBundleLint = callWith ./target-bundle-lint.nix analysisCommon;
  projectStatusPythonSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.project_status" ];
    name = "spaghetti-extractor-project-status-python-closure";
  };
  candidateStatusPythonSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.candidate_status" ];
    name = "spaghetti-extractor-candidate-status-python-closure";
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
      assert metadata.format == "spaghetti-extractor-target-bundle-v3";
      assert identifier metadata.id;
      assert builtins.isString metadata.display_name && metadata.display_name != "";
      assert exactAttrs input [ "expected_sha256" "kind" ];
      assert input.kind == "pe32";
      assert builtins.isString input.expected_sha256
        && builtins.stringLength input.expected_sha256 == 64
        && builtins.match "[0-9a-f]*" input.expected_sha256 != null;
      assert exactAttrs paths [ "components" "nix" ]
        || exactAttrs paths [ "components" "libraries" "nix" ];
      assert relativePath paths.nix;
      assert paths.components == null || relativePath paths.components;
      assert !(paths ? libraries) || paths.libraries == null
        || relativePath paths.libraries;
      assert exactAttrs workflow [ "default_configuration" ];
      assert workflow.default_configuration == null
        || identifier workflow.default_configuration;
      assert (paths.components == null)
        == (workflow.default_configuration == null);
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
        "spaghetti-extractor-${targetId}-bundle-contract-v3"
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
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v3";
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
    targetId ? binaryIdentity,
    externalProfile,
    machineImportProfiles ? [ externalProfile ],
    launchProfileTemplate,
    namePrefix,
    componentIntent ? null,
    componentReviewRoot ? null,
    componentSourceRoot ? null,
    componentBindingRoot ? null,
    componentInductionRoot ? null,
    componentRelationRoot ? null,
    callProtocols ? { },
    externalInterfaceProfiles ? [ ],
    candidateMachineImportProfiles ? [ ],
    libraryCatalogPacks ? [ ],
    libraryCatalogIndexes ? [ ],
    libraryAbiCatalogs ? [ ],
    libraryCatalogLock ? null,
    libraryImplementations ? { },
    libraryAdoptionIntentRoot ? null,
    maxUnits ? 512,
    maxCandidatesPerSeed ? 12,
  }:
    let
      hasComponents = componentIntent != null;
      effectiveLibraryCatalogIndexes = libraryCatalogIndexes
        ++ map (pack: pack.artifactIndex) libraryCatalogPacks;
      effectivePhysicalAbiCatalogs =
        map (pack: pack.physicalAbiCatalog) libraryCatalogPacks;
      effectiveLibraryImplementations = lib.foldl'
        (result: pack: result // (pack.implementationPaths or { }))
        libraryImplementations
        libraryCatalogPacks;
      libraryCatalogConfigured =
        effectiveLibraryCatalogIndexes != [ ] || libraryAbiCatalogs != [ ]
        || libraryCatalogLock != null;
      libraryAdoptionIntents =
        if libraryAdoptionIntentRoot == null then { } else
        let
          entries = builtins.readDir libraryAdoptionIntentRoot;
          filenames = builtins.filter
            (name: entries.${name} == "regular" && lib.hasSuffix ".json" name)
            (builtins.attrNames entries);
        in builtins.listToAttrs (map (filename: {
          name = lib.removeSuffix ".json" filename;
          value = libraryAdoptionIntentRoot + "/${filename}";
        }) filenames);
      analysis = analysisComponent {
        inherit original externalProfile externalInterfaceProfiles namePrefix;
        additionalMachineImportProfiles = builtins.tail machineImportProfiles;
        inherit launchProfileTemplate maxUnits maxCandidatesPerSeed;
      };
      libraryRecognition = callWith ./library-recognition.nix analysisCommon {
        inherit original namePrefix targetId binaryIdentity;
        machineIr = analysis.machineIr;
        catalogIndexes = effectiveLibraryCatalogIndexes;
        physicalAbiCatalogs = effectivePhysicalAbiCatalogs;
        abiCatalogs = libraryAbiCatalogs;
        catalogLock = libraryCatalogLock;
        implementations = effectiveLibraryImplementations;
      };
      authority = authorityWorkflow {
        name = "${namePrefix}-authority-v3";
        machineIr = "${analysis.machineIr}/machine-ir.jsonl";
        binary = original;
        inherit binaryIdentity machineImportProfiles launchProfileTemplate;
        normalCallAbiPremise =
          "${context.sources.profileSource}/pe32-normal-return-nonvolatile-v1.json";
        externalArtifacts = lib.optionalAttrs
          (libraryRecognition.catalogCallContracts != null) {
            catalog_call_contracts = {
              artifact = "${libraryRecognition.catalogCallContracts}/artifact";
              expectedKind = "catalog-call-contracts-v3";
              expectedRecordIds = (builtins.fromJSON (builtins.readFile
                "${libraryRecognition.catalogCallContracts}/metadata.json")).record_ids;
            };
          };
      };
      rootedBehavioralProjection = import ./rooted-behavioral-projection.nix {
        inherit pkgs;
        pythonEnv = context.pythonEnv;
        inherit namePrefix;
        rootClosure =
          authority.graph.phases."launch-root-closure-v3".artifact;
        semanticIndex = authority.graph.phases."semantic-index-v3".artifact;
      };
      linkedLibraries = callWith ./linked-libraries.nix analysisCommon {
        inherit original namePrefix targetId binaryIdentity;
        machineIr = analysis.machineIr;
        parametricSummaries =
          authority.graph.phases."parametric-scc-summaries-v3".artifact;
        catalogIndexes = effectiveLibraryCatalogIndexes;
        physicalAbiCatalogs = effectivePhysicalAbiCatalogs;
        abiCatalogs = libraryAbiCatalogs;
        catalogLock = libraryCatalogLock;
        implementations = effectiveLibraryImplementations;
        adoptionIntents = libraryAdoptionIntents;
        canonicalExternalSites =
          authority.graph.phases."canonical-external-sites-v3".artifact;
        targetCertificates =
          authority.graph.phases."indirect-target-certificates-v3".artifact;
      };
      libraryOperator = import ./library-status.nix {
        inherit pkgs;
        pythonEnv = context.pythonEnv;
        pythonSource = context.sources.fullSource;
        targetId = binaryIdentity;
        namePrefix = "${namePrefix}-libraries";
        releaseHypotheses = linkedLibraries.releaseHypotheses;
        catalogSearchIndex = linkedLibraries.catalogSearchIndex;
        abiMatchResolution = linkedLibraries.abiMatchResolution;
        adoptionIntents = linkedLibraries.adoptionIntents;
        checkedIslands = linkedLibraries.checkedIslands;
        generatedComponents = linkedLibraries.generatedComponents;
        implementations = linkedLibraries.implementations;
      };
      calls = callProtocolWorkflow {
        protocols = callProtocols;
        namePrefix = "${namePrefix}-calls";
      };
      interpreterSupport = assert lib.assertMsg (authority.fallbackSupport != null)
        "PE32 workflows require reusable machine-IR support";
        authority.fallbackSupport;
      components = if !hasComponents then null else componentWorkflow {
          machineIr = analysis.machineIr;
          reconstructionPlan = analysis.reconstructionPlan;
          componentProposals = analysis.componentProposals;
          canonicalExternalSites = authority.componentExternalSites;
          callbackAuthority =
            authority.graph.phases."callback-authority-v4".artifact;
          callBoundaryContracts =
            authority.graph.phases."call-boundary-contracts-v3".artifact;
          intent = componentIntent;
          reviewRoot = componentReviewRoot;
          sourceRoot = componentSourceRoot;
          bindingRoot = componentBindingRoot;
          inductionRoot = componentInductionRoot;
          relationRoot = componentRelationRoot;
          inherit namePrefix;
          interpreterPackage = interpreterSupport;
          generatedLibraryComponents = linkedLibraries.generatedComponents;
          inherit rootedBehavioralProjection;
        };
      configurationIds = if hasComponents
        then builtins.attrNames components.runtimeConfigurations else [ ];
      structuralArtifacts = {
        callbacks = authority.graph.phases."callback-authority-v4".artifact;
        exceptional_transitions =
          authority.graph.phases."exceptional-transitions-v3".artifact;
        external_sites =
          authority.graph.phases."canonical-external-sites-v3".artifact;
        inductive_authority =
          authority.graph.phases."inductive-authority-v3".artifact;
        parametric_summaries =
          authority.graph.phases."parametric-scc-summaries-v3".artifact;
        root_closure = authority.graph.phases."launch-root-closure-v3".artifact;
        semantic_index = authority.graph.phases."semantic-index-v3".artifact;
        target_certificates =
          authority.graph.phases."indirect-target-certificates-v3".artifact;
      };
      structuralReceipts = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = import ./candidate-policy-receipt.nix {
          inherit pkgs structuralArtifacts;
          pythonEnv = context.pythonEnv;
          namePrefix = "${namePrefix}-${configurationId}";
          machineIr = "${analysis.machineIr}/machine-ir.jsonl";
          machineIrManifest = "${analysis.machineIr}/machine-ir-manifest.json";
          fallbackCapabilityAnalysis = authority.fallbackCapabilityAnalysis;
          activationPlan = components.activationPlans.${configurationId};
          inherit rootedBehavioralProjection;
        };
      }) configurationIds);
      structuralGates = lib.mapAttrs (configurationId: receipt:
        import ./candidate-policy-gate.nix {
          inherit pkgs receipt;
          namePrefix = "${namePrefix}-${configurationId}";
        }) structuralReceipts;
      interpreters = lib.mapAttrs (configurationId: executionGate:
        import ./candidate-interpreter-package.nix {
          inherit pkgs executionGate;
          supportPackage = interpreterSupport;
          namePrefix = "${namePrefix}-${configurationId}-standard-fallback";
        }) structuralGates;
      candidateFor = {
        configurationId,
        extraMachineImportProfiles ? [ ],
        compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
      }: assert lib.assertMsg hasComponents
        "candidate construction requires authored component intent";
      hybridCandidate {
        machineIr = analysis.machineIr;
        staticExport = analysis.staticExport;
        staticAuthority = authority;
        machineImportProfiles = machineImportProfiles
          ++ candidateMachineImportProfiles
          ++ extraMachineImportProfiles;
        namePrefix = "${namePrefix}-${configurationId}";
        inherit compiler;
        structuralExecutionGate = structuralGates.${configurationId};
        interpreterPackage = interpreters.${configurationId};
        componentRuntimePackage = components.mkRuntime {
          inherit configurationId;
          runtimeCompiler = compiler;
        };
      };
      runtimeFrontiers = runtimeFrontierReport {
        authorityDiagnostics = authority.diagnostics;
        namePrefix = "${namePrefix}-runtime";
      };
      staticCandidates = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = candidateFor { inherit configurationId; };
      }) configurationIds);
      releaseFor = { configurationId }:
        let
          receipt = import ./candidate-release-receipt.nix {
            inherit pkgs;
            pythonEnv = context.pythonEnv;
            namePrefix = "${namePrefix}-${configurationId}";
            structuralReceipt = structuralReceipts.${configurationId};
            isaQualification = authority.graph.phases."isa-qualification-v3".artifact;
            candidateBinary =
              "${staticCandidates.${configurationId}.candidate}/candidate.exe";
            componentReleaseGate = components.hybridGates.${configurationId};
          };
          gate = import ./candidate-release-gate.nix {
            inherit pkgs receipt;
            namePrefix = "${namePrefix}-${configurationId}";
          };
        in { inherit receipt gate; };
      staticReleasePolicies = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = releaseFor { inherit configurationId; };
      }) configurationIds);
      candidateTestFor = {
        id,
        configurationId,
        suite,
        runtimeData ? null,
        timeoutSeconds ? 30,
        stripStderrLineRegexes ? [ ],
      }: candidateTestSuite {
        inherit id configurationId suite runtimeData timeoutSeconds
          stripStderrLineRegexes;
        namePrefix = "${namePrefix}-${configurationId}";
        candidateBinary = "${staticCandidates.${configurationId}.candidate}/candidate.exe";
        releaseGate = staticReleasePolicies.${configurationId}.gate;
      };
    in {
      inherit analysis authority rootedBehavioralProjection libraryRecognition linkedLibraries libraryOperator libraryCatalogConfigured calls components interpreterSupport interpreters
        structuralArtifacts structuralReceipts structuralGates candidateFor
        candidateTestFor releaseFor staticReleasePolicies configurationIds staticCandidates runtimeFrontiers
        hasComponents;
      originalBinary = original;
      inherit binaryIdentity;
      componentRuntimeFor = if hasComponents then components.runtimeFor else null;
      componentRuntimes = if hasComponents then components.runtimePackages else { };
      candidates = {
        static = staticCandidates;
      };
    };
  projectCandidate = candidate: lib.filterAttrs (_name: value: value != null) {
    inherit (candidate) interpreter componentRuntime machineImportProfileBundle
      structuralExecutionGate nativeEngine nativeRuntime candidate;
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
      hasComponents = workflow.hasComponents or false;
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
      componentAssets = if !hasComponents then [ ] else map (asset: asset // {
        path = relativeTargetPath asset.path;
      }) workflow.components.assetInventory;
      callAssets = map (asset: asset // {
        path = relativeTargetPath asset.path;
      }) workflow.calls.assetInventory;
      libraryIntentAssets =
        if !(metadata.paths ? libraries) then [ ] else
        let
          root = targetRoot + "/${metadata.paths.libraries}";
          entries = if builtins.pathExists root then builtins.readDir root else { };
          filenames = builtins.filter
            (name: entries.${name} == "regular" && lib.hasSuffix ".json" name)
            (builtins.attrNames entries);
        in map (filename: {
          path = "${metadata.paths.libraries}/${filename}";
          role = "library_adoption_intent";
          owner = "linked-libraries";
        }) filenames;
      candidateTestAssets = lib.mapAttrsToList (id: test: {
        path = relativeTargetPath test.suite;
        role = "candidate_test";
        owner = id;
      }) candidateTests;
      manualAssetRoles = [
        "runtime" "documentation" "license" "boundary_schema" "boundary_source"
      ];
      invalidManualRoles = lib.subtractLists manualAssetRoles
        (builtins.attrNames targetAssets);
      manualAssets = lib.concatMap (role: map (path: {
        inherit path role;
        owner = "target-bundle";
      }) (targetAssets.${role} or [ ])) manualAssetRoles;
      declaredAssets = metadataAssets ++ componentAssets ++ callAssets ++ libraryIntentAssets
        ++ candidateTestAssets ++ manualAssets;
      ownership = targetBundleLint {
        inherit targetRoot declaredAssets;
        targetId = metadata.id;
        namePrefix = "spaghetti-extractor-${metadata.id}";
      };
      defaultConfiguration = metadata.workflow.default_configuration;
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
          rooted-behavioral-projection = workflow.rootedBehavioralProjection;
          phases = lib.mapAttrs (_: phase: phase.derivation)
            workflow.authority.graph.phases;
        };
        libraries = lib.filterAttrs (_: value: value != null) {
          artifact-index = workflow.linkedLibraries.artifactIndex;
          catalog-lock = workflow.linkedLibraries.generatedCatalogLock;
          catalog-search-index = workflow.linkedLibraries.catalogSearchIndex;
          target-signature-graph = workflow.linkedLibraries.targetSignatureGraph;
          release-hypotheses = workflow.linkedLibraries.releaseHypotheses;
          catalog-call-contracts =
            workflow.libraryRecognition.catalogCallContracts;
          target-abi-evidence = workflow.linkedLibraries.targetAbiEvidence;
          abi-match-resolution = workflow.linkedLibraries.abiMatchResolution;
          checked-islands = workflow.linkedLibraries.checkedIslands;
          generated-components = workflow.linkedLibraries.generatedComponents;
          status = workflow.libraryOperator.status;
        };
        calls = {
          status = workflow.calls.status;
          subjects = workflow.calls.subjects;
        };
        components = {
          proposals = workflow.analysis.componentProposals;
        } // lib.optionalAttrs hasComponents {
          resolution = workflow.components.resolution;
          contracts = workflow.components.contracts;
          source-packages = workflow.components.sourcePackages;
          evidence = workflow.components.evidences;
          qualifications = workflow.components.qualifications;
          compile-receipts = workflow.components.compileReceipts or { };
          source-profiles = workflow.components.sourceProfiles or { };
          machine-bindings = workflow.components.machineBindingReceipts or { };
          semantic-contracts = workflow.components.semanticContracts or { };
          universal-contracts = workflow.components.universalContracts or { };
          relations = workflow.components.relationArtifacts or { };
          universal-machine-bindings =
            workflow.components.universalMachineBindings or { };
          machine-implementations =
            workflow.components.machineImplementations or { };
          dependency-graphs = workflow.components.dependencyGraphs or { };
          hybrid-gates = workflow.components.hybridGates or { };
          portable-gates = workflow.components.portableGates or { };
          retirement-reports = workflow.components.retirementReports or { };
          induction-packages = workflow.components.inductionPackages or { };
          induction-draft-certificates =
            workflow.components.inductionDraftCertificates or { };
          induction-source-receipts =
            workflow.components.inductionSourceReceipts or { };
          semantic-refinements = workflow.components.refinementReceipts or { };
          service-graphs = workflow.components.serviceGraphs or { };
          ownership-receipts = workflow.components.ownershipReceipts or { };
          activation-receipts = workflow.components.activationReceipts or { };
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
          runtime-frontiers = workflow.runtimeFrontiers;
          target-ownership = ownership;
        };
        candidate = {
          static = lib.mapAttrs (_: candidate: projectCandidate candidate)
            workflow.staticCandidates;
          tests = lib.mapAttrs (_: test: test.aggregate) candidateTests;
          release-receipts = releaseReceipts;
          release-gates = releaseGates;
        };
      } // lib.optionalAttrs (builtins.attrNames extraArtifacts != [ ]) {
        target = extraArtifacts;
      };
      standardChecks = {
        target-bundle-assets = ownership;
        target-input-identity = targetInputIdentity;
        call-protocols = workflow.calls.check;
      } // lib.optionalAttrs hasComponents {
        component-resolution = workflow.components.resolution;
        default-component-configuration =
          workflow.components.activationPlans.${defaultConfiguration};
      };
      componentIntentRequired = pkgs.runCommand
        "spaghetti-extractor-${metadata.id}-component-intent-required"
        { __contentAddressed = true; } ''
          echo "target ${metadata.id} has no authored component intent" >&2
          echo "run project analyze, inspect component proposals, then configure a default component configuration" >&2
          exit 1
        '';
      releasePolicies = if !hasComponents then { } else workflow.staticReleasePolicies;
      releaseReceipts = lib.mapAttrs (_: policy: policy.receipt) releasePolicies;
      releaseGates = lib.mapAttrs (_: policy: policy.gate) releasePolicies;
      standardAcceptanceChecks = if hasComponents then {
        release-acceptance = releaseGates.${defaultConfiguration};
        default-static-candidate =
          workflow.staticCandidates.${defaultConfiguration}.candidate;
      } else {
        component-intent = componentIntentRequired;
      };
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
      componentUnits = if !hasComponents then { } else lib.mapAttrs (id: _index: {
        build = workflow.components.workPackages.${id};
        workPackage = workflow.components.workPackages.${id};
        status = workflow.components.statusReports.${id};
        check = workflow.components.checkGates.${id};
        developmentStatus = workflow.components.statusReports.${id};
        developmentCheck = workflow.components.checkGates.${id};
      } // lib.optionalAttrs (builtins.hasAttr id (workflow.components.compileReceipts or { })) {
        build = (workflow.components.compileReceipts or { }).${id};
        compileReceipt = (workflow.components.compileReceipts or { }).${id};
      } // lib.optionalAttrs (builtins.hasAttr id (workflow.components.activationReceipts or { })) {
        status = (workflow.components.activationStatusReports or { }).${id};
        check = (workflow.components.activationCheckGates or { }).${id};
        activationStatus = (workflow.components.activationStatusReports or { }).${id};
        activationReceipt = (workflow.components.activationReceipts or { }).${id};
        activationCheck = (workflow.components.activationCheckGates or { }).${id};
      } // lib.optionalAttrs (builtins.hasAttr id (workflow.components.machineBindingReceipts or { })) {
        machineBinding = (workflow.components.machineBindingReceipts or { }).${id};
        contract = (workflow.components.universalContracts or { }).${id};
        universalMachineBinding =
          (workflow.components.universalMachineBindings or { }).${id};
        machineImplementation =
          (workflow.components.machineImplementations or { }).${id};
      } // lib.optionalAttrs (builtins.hasAttr id (workflow.components.relationArtifacts or { })) {
        relation = (workflow.components.relationArtifacts or { }).${id};
        relationCheck = (workflow.components.relationCheckGates or { }).${id};
      } // lib.optionalAttrs (builtins.hasAttr id (workflow.components.inductionPackages or { })) {
        inductionPackage = (workflow.components.inductionPackages or { }).${id};
        inductionDraftCertificate =
          (workflow.components.inductionDraftCertificates or { }).${id};
        inductionSourceReceipt =
          (workflow.components.inductionSourceReceipts or { }).${id};
        inductiveRefinement =
          (workflow.components.inductionRefinementArtifacts or { }).${id};
      }) workflow.components.liftUnitIndex;
      componentConfigurations = if !hasComponents then { } else lib.mapAttrs (id: _index: {
        runtime = workflow.componentRuntimes.${id};
        status = workflow.components.configurationStatusReports.${id};
        check = workflow.components.configurationCheckGates.${id};
        dependencies = workflow.components.dependencyGraphs.${id};
        retirement = workflow.components.retirementReports.${id};
        portableCheck = workflow.components.portableCheckGates.${id};
        hybridCheck = workflow.components.hybridCheckGates.${id};
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
      projectStatus = pkgs.runCommand
        "spaghetti-extractor-${metadata.id}-project-status-v2"
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
          export PYTHONPATH=${projectStatusPythonSource}/src
          mkdir -p "$out"
          ${context.pythonEnv}/bin/python3 - \
            ${workflow.authority.diagnostics}/authority-diagnostics-v3.json \
            ${lib.escapeShellArg metadata.id} \
            "$out/project-status.json" <<'PY'
          import pathlib
          import sys
          from spaghetti_extractor.target_bundles.project_status import build_project_status

          build_project_status(
              authority_diagnostics=pathlib.Path(sys.argv[1]),
              target_id=sys.argv[2],
              out=pathlib.Path(sys.argv[3]),
          )
          PY
          jq -e '
            .format == "spaghetti-extractor-project-status-v2" and
            (.status == "ready" or .status == "incomplete" or .status == "violated") and
            (.authorizing | not) and
            .policy.diagnostic_only and
            (.policy.candidate_gate_bypassed | not) and
            (.policy.original_binary_executed | not) and
            (.configuration_id == null) and
            (.component_configuration == null) and
            (.candidate == null)
          ' "$out/project-status.json" >/dev/null
        '';
      candidateTestIndexFor = configurationId:
        lib.filterAttrs (_: test: test.configurationId == configurationId)
          candidateTestIndex;
      mkCandidateStatus = configurationId:
        let
          configurationStatus =
            toString workflow.components.configurationStatusReports.${configurationId};
          configurationTestIndex = candidateTestIndexFor configurationId;
        in
        pkgs.runCommand
          "spaghetti-extractor-${metadata.id}-${configurationId}-candidate-status-v2"
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
            export PYTHONPATH=${candidateStatusPythonSource}/src
            mkdir -p "$out"
            ${context.pythonEnv}/bin/python3 - \
              ${workflow.structuralReceipts.${configurationId}}/structural-executable.json \
              ${configurationStatus}/status.json \
              ${lib.escapeShellArg metadata.id} \
              ${lib.escapeShellArg configurationId} \
              ${lib.escapeShellArg (builtins.toJSON configurationTestIndex)} \
              "$out/candidate-status.json" <<'PY'
            import json
            import pathlib
            import sys
            from spaghetti_extractor.target_bundles.candidate_status import build_candidate_status

            build_candidate_status(
                structural_receipt=pathlib.Path(sys.argv[1]),
                configuration_status=pathlib.Path(sys.argv[2]),
                target_id=sys.argv[3],
                configuration_id=sys.argv[4],
                candidate_test_suites=json.loads(sys.argv[5]),
                out=pathlib.Path(sys.argv[6]),
            )
            PY
            jq -e '
              .format == "spaghetti-extractor-candidate-status-v2" and
              (.status == "ready" or .status == "incomplete" or .status == "violated") and
              (.authorizing | not) and
              .policy.diagnostic_only and
              (.policy.candidate_gate_bypassed | not) and
              (.policy.candidate_tests_authorize | not) and
              (.policy.original_binary_executed | not)
            ' "$out/candidate-status.json" >/dev/null
          '';
      candidateStatusReports = builtins.listToAttrs (map (configurationId: {
        name = configurationId;
        value = mkCandidateStatus configurationId;
      }) configurationIds);
      checkedCandidateBuilds = lib.mapAttrs (configurationId: candidate:
        pkgs.runCommand
          "spaghetti-extractor-${metadata.id}-${configurationId}-checked-candidate"
          {
            nativeBuildInputs = [ pkgs.jq ];
            __contentAddressed = true;
          } ''
            set -euo pipefail
            test -s ${targetInputIdentity}/target-input-identity.json
            jq -e '.ready and .status == "ready" and .mode == "hybrid"' \
              ${workflow.components.hybridCheckGates.${configurationId}}/component-hybrid-release-gate-v1.json \
              >/dev/null
            test -s ${releaseGates.${configurationId}}/release-acceptance.json
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
        inherit defaultConfiguration hasComponents;
        components = {
          units = if hasComponents then workflow.components.liftUnitIndex else { };
          configurations = if hasComponents
            then workflow.components.configurationIndex else { };
        };
        candidate = {
          configurations = configurationIds;
          testSuites = candidateTestIndex;
        };
        libraries = {
          configured = workflow.libraryCatalogConfigured;
          selections = builtins.attrNames workflow.linkedLibraries.checks;
        };
        calls = {
          configured = workflow.calls.configured;
          subjects = lib.mapAttrs (_: _: { }) workflow.calls.subjects;
        };
      };
      operator = {
        index = operatorIndex;
        project = {
          analysis = projectAnalysis;
          status = projectStatus;
          authorityDiagnostics = workflow.authority.diagnostics;
          regressionCheck = bundle.defaultCheck;
          acceptanceCheck = bundle.acceptanceCheck;
          runtimeFrontierReport = workflow.runtimeFrontiers;
        };
        components = {
          proposals = workflow.analysis.componentProposals;
          units = componentUnits;
          configurations = componentConfigurations;
        };
        libraries = {
          status = workflow.libraryOperator.status;
          check = workflow.libraryOperator.check;
          checks = workflow.linkedLibraries.checks;
          catalogSearchIndex = workflow.linkedLibraries.catalogSearchIndex;
          targetSignatureGraph = workflow.linkedLibraries.targetSignatureGraph;
          releaseHypotheses = workflow.linkedLibraries.releaseHypotheses;
          targetAbiEvidence = workflow.linkedLibraries.targetAbiEvidence;
          abiMatchResolution = workflow.linkedLibraries.abiMatchResolution;
          checkedIslands = workflow.linkedLibraries.checkedIslands;
          generatedComponents = workflow.linkedLibraries.generatedComponents;
        };
        calls = {
          inherit (workflow.calls) status subjects check;
        };
        candidate = {
          builds = checkedCandidateBuilds;
          checks = lib.mapAttrs (configurationId: _configuration: {
            hybrid = workflow.components.hybridCheckGates.${configurationId};
            portable = workflow.components.portableCheckGates.${configurationId};
          }) workflow.components.configurationIndex;
          statuses = candidateStatusReports;
          tests = checkedCandidateTests;
          allTests = candidateTestAggregate;
          releaseReceipts = releaseReceipts;
          releaseChecks = releaseGates;
          structuralReceipts = workflow.structuralReceipts;
          structuralChecks = workflow.structuralGates;
        };
      };
    in
      assert metadata.format or null == "spaghetti-extractor-target-bundle-v3";
      assert hasComponents == (defaultConfiguration != null);
      assert !hasComponents || (builtins.isString defaultConfiguration
        && builtins.elem defaultConfiguration configurationIds);
      assert lib.assertMsg (invalidManualRoles == [ ])
        "targetAssets contains unsupported roles: ${builtins.toJSON invalidManualRoles}";
      assert lib.assertMsg
        ((metadata.paths.components == null && !hasComponents) ||
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
          componentRuntime = if hasComponents
            then workflow.componentRuntimes.${defaultConfiguration} else null;
          staticCandidate = if hasComponents
            then workflow.staticCandidates.${defaultConfiguration} else null;
          releaseReceipt = if hasComponents
            then releaseReceipts.${defaultConfiguration} else null;
          releaseCheck = if hasComponents
            then releaseGates.${defaultConfiguration} else null;
          runtimeFrontiers = workflow.runtimeFrontiers;
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
      ./external-interface-profile.nix analysisCommon;
  };
  candidate = {
    hybrid = hybridCandidate;
    runtimeFrontierReport = runtimeFrontierReport;
    testSuite = candidateTestSuite;
  };
  lifting = {
    behaviorPack = callWith ./library-behavior-pack.nix candidateCommon;
    catalogPack = callWith ./library-catalog-pack.nix analysisCommon;
    linkedLibraries = callWith ./linked-libraries.nix analysisCommon;
    components = componentWorkflow;
    boundarySchema = callWith ./boundary-schema-workflow.nix analysisCommon;
  };
  validation = {
    testRunner = context.packages.testkitTestRunner;
    testSuite = callWith ./test-suite.nix {
      inherit pkgs;
      inherit (context) pythonEnv fixtures;
    };
  };
  target = {
    pe32Bundle = mkPe32Bundle;
    registry = validateRegistry;
  };
}
