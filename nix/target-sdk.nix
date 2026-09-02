# spaghetti-extractor-python-role: operator
{ pkgs }:

let
  context = import ./toolkit-context.nix { inherit pkgs; };
  lib = pkgs.lib;
  callWith =
    path: common: args:
    let
      function = import path;
      accepted = builtins.functionArgs function;
      unknown = builtins.attrNames (builtins.removeAttrs args (builtins.attrNames accepted));
      selectedCommon = lib.filterAttrs (name: _: builtins.hasAttr name accepted) common;
    in
    assert unknown == [ ];
    function (args // selectedCommon);
  analysisCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.staticSource;
    relationKernel = context.kernels.relationKernel;
  };
  candidateCommon = {
    inherit pkgs;
    inherit (context) pythonEnv;
    pythonSource = context.sources.fullSource;
  };
  componentCommon = analysisCommon // {
    inherit (context) transferPythonEnv;
  };
  analysisComponent = callWith ./component-analysis.nix analysisCommon;
  componentWorkflow = callWith ./component-workflow.nix componentCommon;
  callProtocolWorkflow = callWith ./call-protocol-workflow.nix analysisCommon;
  boundaryWorkbench = callWith ./boundary-workbench.nix analysisCommon;
  executableTransferPlan = callWith ./executable-transfer-plan.nix candidateCommon;
  semanticISARequirements = callWith ./semantic-isa-requirements.nix {
    inherit pkgs;
    inherit (context) pythonEnv;
  };
  behavioralCPackage = callWith ./behavioral-c-package.nix candidateCommon;
  generatedBehavioralCProviderV2 = callWith ./generated-behavioral-c-provider-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  externalEnvironmentProviderV2 = callWith ./external-environment-provider-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  qualifiedRuntimeProviderV2 = callWith ./qualified-runtime-provider-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  portableCWorkPackageProviderV2 = callWith
    ./portable-c-work-package-provider-v2.nix {
      inherit pkgs;
      pythonEnv = context.transferPythonEnv;
    };
  implementationSelectionV2 = callWith ./semantic-provider-selection-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  nativeRealizationV2 = callWith ./native-realization-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  semanticObjectPackage = callWith ./semantic-object.nix candidateCommon;
  linkedSemanticModulePackage = callWith ./linked-semantic-module.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
  };
  pe32ModuleInterface = callWith ./pe32-module-interface.nix candidateCommon;
  pe32SingleModuleProjectIntent = callWith ./pe32-single-module-project-intent.nix candidateCommon;
  candidateTestSuite = callWith ./candidate-test-suite.nix candidateCommon;
  targetBundleLint = callWith ./target-bundle-lint.nix analysisCommon;
  externalEnvironmentIntent = callWith ./external-environment-intent.nix analysisCommon;
  resolvedExternalEnvironment = callWith ./resolved-external-environment.nix analysisCommon;
  projectStatusPythonSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.artifacts.build_manifest"
      "spaghetti_extractor.target_bundles.project_status"
      "spaghetti_extractor.util"
    ];
    name = "spaghetti-extractor-project-status-python-closure";
  };
  exactAttrs =
    value: names:
    builtins.isAttrs value && builtins.attrNames value == builtins.sort builtins.lessThan names;
  parseTargetMetadata =
    targetRoot:
    let
      metadata = builtins.fromJSON (builtins.readFile (targetRoot + "/target.json"));
      input = metadata.input or null;
      paths = metadata.paths or null;
      workflow = metadata.workflow or null;
      identifier =
        value:
        builtins.isString value
        && value != ""
        && builtins.match "[a-z0-9]([a-z0-9._-]*[a-z0-9])?" value != null;
      relativePath =
        value:
        builtins.isString value
        && value != ""
        && builtins.substring 0 1 value != "/"
        && lib.all (part: part != "" && part != "." && part != "..") (lib.splitString "/" value);
    in
    assert exactAttrs metadata [
      "display_name"
      "format"
      "id"
      "input"
      "paths"
      "workflow"
    ];
    assert metadata.format == "spaghetti-extractor-target-bundle-v3";
    assert identifier metadata.id;
    assert builtins.isString metadata.display_name && metadata.display_name != "";
    assert exactAttrs input [
      "expected_sha256"
      "kind"
    ];
    assert input.kind == "pe32";
    assert
      builtins.isString input.expected_sha256
      && builtins.stringLength input.expected_sha256 == 64
      && builtins.match "[0-9a-f]*" input.expected_sha256 != null;
    assert
      exactAttrs paths [
        "components"
        "nix"
      ]
      || exactAttrs paths [
        "components"
        "libraries"
        "nix"
      ];
    assert relativePath paths.nix;
    assert paths.components == null || relativePath paths.components;
    assert !(paths ? libraries) || paths.libraries == null || relativePath paths.libraries;
    assert exactAttrs workflow [ "default_configuration" ];
    assert workflow.default_configuration == null || identifier workflow.default_configuration;
    assert (paths.components == null) == (workflow.default_configuration == null);
    metadata;
  mkBundleRecord =
    {
      targetRoot,
      artifacts,
      checks ? { },
      acceptanceChecks ? { },
      apps ? { },
    }:
    let
      metadata = parseTargetMetadata targetRoot;
      targetId = metadata.id or null;
      metadataFile = pkgs.writeText "spaghetti-extractor-${targetId}-metadata.json" (
        builtins.toJSON metadata
      );
      contractCheck =
        pkgs.runCommand "spaghetti-extractor-${targetId}-bundle-contract-v3" { __contentAddressed = true; }
          ''
            mkdir -p "$out"
            cp ${metadataFile} "$out/target.json"
            printf '%s\n' ${lib.escapeShellArg (builtins.toJSON (builtins.attrNames artifacts))} \
              > "$out/artifact-families.json"
          '';
      regressionChecks = checks // {
        bundle-contract = contractCheck;
      };
      completeAcceptanceChecks = regressionChecks // acceptanceChecks;
      defaultCheck = pkgs.linkFarm "spaghetti-extractor-${targetId}-target-regression-checks" (
        lib.mapAttrsToList (name: path: { inherit name path; }) regressionChecks
      );
      acceptanceCheck = pkgs.linkFarm "spaghetti-extractor-${targetId}-target-acceptance-checks" (
        lib.mapAttrsToList (name: path: { inherit name path; }) completeAcceptanceChecks
      );
    in
    assert metadata.format or null == "spaghetti-extractor-target-bundle-v3";
    assert builtins.isString targetId && targetId != "";
    assert
      builtins.isAttrs artifacts
      && builtins.isAttrs checks
      && builtins.isAttrs acceptanceChecks
      && builtins.isAttrs apps;
    {
      _type = "spaghetti-extractor-target-definition-v4";
      inherit
        metadata
        artifacts
        apps
        defaultCheck
        acceptanceCheck
        ;
      checks = regressionChecks;
      inherit acceptanceChecks;
    };
  validateRegistry =
    registry:
    assert lib.all (
      id:
      let
        bundle = registry.${id};
      in
      bundle._type or null == "spaghetti-extractor-target-definition-v4" && bundle.metadata.id == id
    ) (builtins.attrNames registry);
    registry;
  mkPe32Environment =
    {
      id,
      profilePacks,
      interfacePacks ? [ ],
      launchProfile,
      boundaryIntents ? { },
      support ? {
        processTermination = null;
      },
      targetAbi ? "pe32-i686-mingw32",
      targetDataLayout ? "pe32-ilp32-v1",
    }:
    let
      namePrefix = "spaghetti-extractor-${id}";
      stableBoundarySubject =
        subject:
        builtins.isString subject
        &&
          builtins.match "(call|callback|export|component_operation|service):[a-z0-9]([a-z0-9._-]*[a-z0-9])?" subject
          != null;
      _supportFields =
        assert builtins.attrNames support == [ "processTermination" ];
        true;
      _boundarySubjects =
        assert builtins.all stableBoundarySubject (builtins.attrNames boundaryIntents);
        true;
      compiled = externalEnvironmentIntent {
        inherit
          namePrefix
          profilePacks
          interfacePacks
          launchProfile
          boundaryIntents
          targetAbi
          targetDataLayout
          ;
        environmentId = id;
        processTermination = support.processTermination or null;
      };
    in
    assert _supportFields && _boundarySubjects;
    assert builtins.isString id && id != "";
    assert builtins.isList profilePacks && profilePacks != [ ];
    assert builtins.isList interfacePacks;
    assert builtins.isAttrs boundaryIntents;
    assert builtins.isAttrs support;
    assert builtins.elem targetAbi [
      "pe32-i686-mingw32"
      "pe32-i686-msvc"
    ];
    assert targetDataLayout == "pe32-ilp32-v1";
    {
      _type = "spaghetti-extractor-external-environment-v1";
      inherit
        id
        profilePacks
        interfacePacks
        launchProfile
        boundaryIntents
        support
        targetAbi
        targetDataLayout
        ;
      inherit (compiled)
        intent
        analysisProjection
        manifest
        derivation
        ;
    };
  mkPe32Workflow =
    {
      original,
      binaryIdentity,
      targetId ? binaryIdentity,
      externalEnvironment,
      lifting ? {
        boundaries = [ ];
        components = null;
        libraries = { };
      },
      backend ? {
        kind = "behavioral-c";
        sourcePresentation = null;
      },
      analysisLimits ? {
        maxUnits = 512;
        maxCandidatesPerSeed = 12;
      },
      namePrefix ? "spaghetti-extractor-${targetId}",
    }:
    let
      _environmentType =
        assert externalEnvironment._type == "spaghetti-extractor-external-environment-v1";
        true;
      _backendKind =
        assert backend.kind or null == "behavioral-c";
        true;
      _backendFields =
        assert
          builtins.attrNames backend == [
            "kind"
            "sourcePresentation"
          ];
        true;
      _liftingFields =
        assert
          builtins.attrNames lifting == [
            "boundaries"
            "components"
            "libraries"
          ];
        true;
      _analysisLimitFields =
        assert
          builtins.attrNames analysisLimits == [
            "maxCandidatesPerSeed"
            "maxUnits"
          ];
        true;
      machineImportProfiles = externalEnvironment.profilePacks;
      externalProfile = builtins.head machineImportProfiles;
      externalInterfaceProfiles = externalEnvironment.interfacePacks;
      candidateMachineImportProfiles = externalEnvironment.interfacePacks;
      launchProfileTemplate = externalEnvironment.launchProfile;
      boundaryDefinitions = lifting.boundaries;
      protocolBoundaryDefinitions = builtins.filter (row: row ? protocol) boundaryDefinitions;
      packageBoundaryDefinitions = builtins.filter (row: row ? package) boundaryDefinitions;
      _boundaryDefinitions =
        assert builtins.all (
          row:
          builtins.isAttrs row
          && builtins.isString (row.subject or null)
          && builtins.hasAttr row.subject externalEnvironment.boundaryIntents
          && (
            if row ? protocol then
              builtins.attrNames row == [
                "protocol"
                "subject"
              ]
              && builtins.isAttrs row.protocol
              && builtins.attrNames row.protocol == [ "layouts" ]
            else
              row ? package
              &&
                builtins.attrNames row == [
                  "package"
                  "subject"
                ]
          )
        ) boundaryDefinitions;
        true;
      callProtocols = builtins.listToAttrs (
        map (row: {
          name = row.subject;
          value =
            row.protocol
            // {
              intent = externalEnvironment.boundaryIntents.${row.subject};
              transferPlan = transferPlan.plan;
            }
            // lib.optionalAttrs (lib.hasPrefix "callback:" row.subject) {
              runtimeProfiles = machineImportProfiles;
            };
        }) protocolBoundaryDefinitions
      );
      componentConfiguration = lifting.components;
      componentIntent = if componentConfiguration == null then null else componentConfiguration.intent;
      componentOperatorRoot =
        if componentConfiguration == null then null else componentConfiguration.operatorRoot;
      componentSourceRoot =
        if componentConfiguration == null then null else componentConfiguration.sourceRoot;
      componentSubroot =
        name:
        if componentOperatorRoot == null then
          null
        else
          let
            path = componentOperatorRoot + "/${name}";
          in
          if builtins.pathExists path then path else null;
      componentInterfaceRoot = componentSubroot "interfaces-v5";
      componentBindingIntentRoot = componentSubroot "bindings-v5";
      componentInductionRoot = componentSubroot "induction";
      componentRelationRoot = componentSubroot "relations";
      libraryConfiguration = lifting.libraries;
      libraryCatalogPacks = libraryConfiguration.packs or [ ];
      libraryAdoptionIntentRoot = libraryConfiguration.adoptionRoot or null;
      libraryCatalogIndexes = [ ];
      libraryAbiCatalogs = [ ];
      libraryCatalogLock = null;
      libraryImplementations = { };
      behavioralCLayoutIntent = backend.sourcePresentation;
      maxUnits = analysisLimits.maxUnits;
      maxCandidatesPerSeed = analysisLimits.maxCandidatesPerSeed;
      hasComponents =
        assert
          _environmentType
          && _backendKind
          && _backendFields
          && _liftingFields
          && _analysisLimitFields
          && _boundaryDefinitions;
        componentIntent != null;
      effectiveLibraryCatalogIndexes =
        libraryCatalogIndexes ++ map (pack: pack.artifactIndex) libraryCatalogPacks;
      effectiveLibraryImplementations = lib.foldl' (
        result: pack: result // (pack.implementationPaths or { })
      ) libraryImplementations libraryCatalogPacks;
      libraryCatalogConfigured =
        effectiveLibraryCatalogIndexes != [ ] || libraryAbiCatalogs != [ ] || libraryCatalogLock != null;
      libraryAdoptionIntents =
        if libraryAdoptionIntentRoot == null then
          { }
        else
          let
            entries = builtins.readDir libraryAdoptionIntentRoot;
            filenames = builtins.filter (name: entries.${name} == "regular" && lib.hasSuffix ".json" name) (
              builtins.attrNames entries
            );
          in
          builtins.listToAttrs (
            map (filename: {
              name = lib.removeSuffix ".json" filename;
              value = libraryAdoptionIntentRoot + "/${filename}";
            }) filenames
          );
      analysis = analysisComponent {
        inherit
          original
          externalProfile
          externalInterfaceProfiles
          namePrefix
          ;
        additionalMachineImportProfiles = builtins.tail machineImportProfiles;
        inherit launchProfileTemplate maxUnits maxCandidatesPerSeed;
      };
      transferPlan = executableTransferPlan {
        machineIr = analysis.machineIr;
        inherit namePrefix;
      };
      isaRequirements = semanticISARequirements {
        kernelCache = context.kernels.isaConformanceKernel;
        binary = original;
        machineIr = "${analysis.machineIr}/machine-ir.jsonl";
        inherit namePrefix;
      };
      libraryRecognition = callWith ./library-recognition.nix analysisCommon {
        inherit
          original
          namePrefix
          targetId
          binaryIdentity
          ;
        machineIr = analysis.machineIr;
        catalogIndexes = effectiveLibraryCatalogIndexes;
        abiCatalogs = libraryAbiCatalogs;
        catalogLock = libraryCatalogLock;
        implementations = effectiveLibraryImplementations;
      };
      linkedLibraries = callWith ./linked-libraries.nix analysisCommon {
        inherit
          original
          namePrefix
          targetId
          binaryIdentity
          ;
        machineIr = analysis.machineIr;
        linkedSemanticModule = linkedSemanticModule.derivation;
        catalogIndexes = effectiveLibraryCatalogIndexes;
        abiCatalogs = libraryAbiCatalogs;
        catalogLock = libraryCatalogLock;
        implementations = effectiveLibraryImplementations;
        adoptionIntents = libraryAdoptionIntents;
      };
      libraryOperator = import ./library-status.nix {
        inherit pkgs;
        pythonEnv = context.pythonEnv;
        pythonSource = context.sources.fullSource;
        targetId = binaryIdentity;
        namePrefix = "${namePrefix}-libraries";
        releaseHypotheses = linkedLibraries.releaseHypotheses;
        catalogSearchIndex = linkedLibraries.catalogSearchIndex;
        adoptionIntents = linkedLibraries.adoptionIntents;
        checkedIslands = linkedLibraries.checkedIslands;
        providerQualifications = lib.mapAttrs
          (_: provider: provider.qualification)
          portableSemanticProvidersByLibrary;
        implementations = linkedLibraries.implementations;
      };
      rawCalls = callProtocolWorkflow {
        protocols = callProtocols;
        namePrefix = "${namePrefix}-calls";
      };
      suppliedBoundaryPackages = builtins.listToAttrs (
        map (row: {
          name = row.subject;
          value = row.package;
        }) packageBoundaryDefinitions
      );
      calls = boundaryWorkbench {
        namePrefix = "${namePrefix}-boundaries";
        checkedProtocols = rawCalls.subjects;
        suppliedPackages = suppliedBoundaryPackages;
        boundaryIntents = externalEnvironment.boundaryIntents;
        rawAssetInventory = rawCalls.assetInventory;
        componentPackages = if hasComponents
          then components.boundarySubjects else { };
      };
      moduleInterface = pe32ModuleInterface {
        inherit original namePrefix;
        imageId = binaryIdentity;
        staticExport = analysis.staticExport;
      };
      qualifiedPlatform = context.platforms.qualifiedPlatform;
      semanticObject = semanticObjectPackage (
        {
          inherit namePrefix;
          transferPlan = transferPlan.plan;
          moduleInterface = "${moduleInterface}/module-interface.json";
          resolvedExternalEnvironment = resolvedEnvironment.derivation;
        }
        // {
          isaRequirements = isaRequirements.artifact;
          qualifiedPlatform = qualifiedPlatform.qualifiedPlatform;
        }
      );
      moduleObjectAuthority = semanticObject.derivation;
      checkedBoundaryPackages = builtins.listToAttrs (
        map (row: {
          name = row.subject;
          value = rawCalls.checked.${row.subject};
        }) protocolBoundaryDefinitions
      );
      allBoundaryPackages =
        assert
          lib.intersectLists (builtins.attrNames checkedBoundaryPackages) (
            builtins.attrNames suppliedBoundaryPackages
          ) == [ ];
        checkedBoundaryPackages // suppliedBoundaryPackages;
      resolvedEnvironment = resolvedExternalEnvironment {
        inherit namePrefix moduleInterface;
        intent = externalEnvironment.intent;
        profilePacks = machineImportProfiles;
        interfacePacks = externalInterfaceProfiles;
        boundaryIntents = externalEnvironment.boundaryIntents;
        boundaryPackages = allBoundaryPackages;
        staticAuthority = {
          executable_transfer_plan = transferPlan.plan;
        };
      };
      linkedSemanticModule = linkedSemanticModulePackage {
        inherit namePrefix;
        semanticObject = semanticObject.artifact;
      };
      behavioralCSource = behavioralCPackage {
        semanticObject = semanticObject.artifact;
        inherit namePrefix;
        layoutIntent = behavioralCLayoutIntent;
      };
      components =
        if !hasComponents then
          null
        else
          componentWorkflow {
            intent = componentIntent;
            interfaceRoot = componentInterfaceRoot;
            sourceRoot = componentSourceRoot;
            bindingIntentRoot = componentBindingIntentRoot;
            inductionRoot = componentInductionRoot;
            relationRoot = componentRelationRoot;
            inherit namePrefix;
            behavioralCPackage = behavioralCSource;
            linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
          };
      componentConfigurationIds =
        if hasComponents then builtins.attrNames components.configurationIndex else [ ];
      configurationIds = [ "faithful" ] ++ componentConfigurationIds;
      generatedSemanticProviderId = "${targetId}.generated-c";
      generatedSemanticProvider = generatedBehavioralCProviderV2 {
        linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
        behavioralCPackage = behavioralCSource;
        providerId = generatedSemanticProviderId;
        namePrefix = "${namePrefix}-semantic";
      };
      externalSemanticProviderId = "${targetId}.external-environment";
      externalSemanticProvider = externalEnvironmentProviderV2 {
        linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
        providerId = externalSemanticProviderId;
        namePrefix = "${namePrefix}-semantic";
      };
      runtimeSemanticProviderId = "${targetId}.qualified-runtime";
      runtimeSemanticProvider = qualifiedRuntimeProviderV2 {
        linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
        behavioralCPackage = behavioralCSource;
        recoveredExecutableData =
          "${analysis.machineIr}/recovered-executable-data.json";
        providerId = runtimeSemanticProviderId;
        namePrefix = "${namePrefix}-semantic";
      };
      portableSemanticProvidersByComponent = builtins.listToAttrs (map (
        componentId: {
          name = componentId;
          value = portableCWorkPackageProviderV2 ({
            semanticSlice = components.v6SemanticSlices.${componentId}.semanticSlice;
            bindingIntent = components.bindingIntentPaths.${componentId};
            interfacePackage = components.v5Interfaces.${componentId}.derivation;
            sourcePackage = components.sourcePackages.${componentId};
            transferPlan = transferPlan.plan;
            resolvedExternalEnvironment =
              "${resolvedEnvironment.derivation}/resolved-external-environment.json";
            semanticObject = semanticObject.derivation;
            providerEntryUnits = components.providerEntryUnits;
            providerComponents =
              components.directProviderComponentsByConsumer.${componentId};
            relationIntent = components.relationIntents.${componentId} or null;
            inductionIntent = components.inductionIntents.${componentId} or null;
            interactionContractCatalog =
              "${context.sources.profileSource}/interaction-contracts-v1.json";
            providerId = "${targetId}.${componentId}.portable-c";
            proofClassification = components.proofClassifications.${componentId};
            namePrefix = "${namePrefix}-${componentId}";
          } // lib.optionalAttrs
            components.directProviderNeedsLinkedModule.${componentId} {
              linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
            });
        }
      ) components.directV6ProviderIds);
      portableSemanticProvidersByLibrary = lib.mapAttrs (
        selectionId: providerInput:
        portableCWorkPackageProviderV2 {
          semanticSlice = providerInput.semanticSlice;
          bindingIntent = providerInput.bindingIntent;
          interfacePackage = providerInput.interfacePackage;
          sourcePackage = providerInput.sourcePackage;
          transferPlan = transferPlan.plan;
          resolvedExternalEnvironment =
            "${resolvedEnvironment.derivation}/resolved-external-environment.json";
          semanticObject = semanticObject.derivation;
          provenanceArtifacts = {
            "library-behavior-pack" =
              "${providerInput.behaviorPack}/behavior-pack.json";
            "library-source-qualification" =
              "${providerInput.behaviorPack}/source-qualification-v1.json";
            "checked-library-island" = providerInput.checkedIsland;
          };
          providerId = "${targetId}.library.${selectionId}.portable-c";
          proofClassification = "machine_overlay";
          namePrefix = "${namePrefix}-library-${selectionId}";
        }
      ) linkedLibraries.providerInputs;
      portableSemanticProviderSets = lib.genAttrs configurationIds (
        configurationId:
        let
          selectedIds =
            if configurationId == "faithful" then [ ]
            else components.selectedComponentIdsByConfiguration.${configurationId};
          allDirect = builtins.all
            (id: builtins.hasAttr id portableSemanticProvidersByComponent)
            selectedIds;
          directIds = assert lib.assertMsg allDirect
            "configuration ${configurationId} selects an unqualified V6 provider";
            selectedIds;
          directProviders = map
            (id: portableSemanticProvidersByComponent.${id}) directIds;
          libraryProviders = if configurationId == "faithful" then [ ]
            else builtins.attrValues portableSemanticProvidersByLibrary;
        in {
          inherit directIds directProviders;
          providers = directProviders ++ libraryProviders;
        }
      );
      semanticImplementationSelections = lib.genAttrs configurationIds (
        configurationId:
        let
          portableSet = portableSemanticProviderSets.${configurationId};
          portableQualifications = builtins.listToAttrs (map (provider: {
            name = provider.providerId;
            value = provider.qualification;
          }) portableSet.providers);
          qualifications = {
            "${generatedSemanticProviderId}" =
              "${generatedSemanticProvider}/semantic-provider-qualification.json";
            "${externalSemanticProviderId}" =
              "${externalSemanticProvider}/semantic-provider-qualification.json";
            "${runtimeSemanticProviderId}" =
              "${runtimeSemanticProvider}/semantic-provider-qualification.json";
          } // portableQualifications;
        in
        implementationSelectionV2 {
          linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
          qualificationsById = qualifications;
          choiceFiles = [
            "${generatedSemanticProvider}/definition-choices.json"
          ] ++ map (provider: provider.definitionChoices)
            portableSet.providers ++ [
            "${externalSemanticProvider}/definition-choices.json"
            "${runtimeSemanticProvider}/implementation-choices.json"
          ];
          selectedProviderIds = builtins.attrNames qualifications;
          mode =
            if configurationId == "faithful" then "faithful"
            else components.configurationIndex.${configurationId}.mode or "hybrid";
          namePrefix = "${namePrefix}-${configurationId}-semantic";
        }
      );
      nativeRealizations = lib.mapAttrs (
        configurationId: selection:
        let
          portableSet = portableSemanticProviderSets.${configurationId};
        in
        nativeRealizationV2 {
          linkedSemanticModule = linkedSemanticModule.linkedSemanticModule;
          implementationSelection = selection.artifact;
          providerQualifications = [
            "${generatedSemanticProvider}/semantic-provider-qualification.json"
            "${externalSemanticProvider}/semantic-provider-qualification.json"
            "${runtimeSemanticProvider}/semantic-provider-qualification.json"
          ]
          ++ map (provider: provider.qualification) portableSet.providers;
          loadImageContract = "${analysis.staticExport}/load-image-contract.json";
          recoveredExecutableData = "${analysis.machineIr}/recovered-executable-data.json";
          candidateFilename = binaryIdentity;
          namePrefix = "${namePrefix}-${configurationId}";
        }
      ) semanticImplementationSelections;
      behavioralC = behavioralCSource;
      singleModuleProjectIntent = pe32SingleModuleProjectIntent {
        inherit namePrefix moduleInterface;
        resolvedExternalEnvironment = resolvedEnvironment.derivation;
      };
      singleModuleProjectLoadPlan = import ./pe32-project-load-plan.nix {
        inherit pkgs;
        pythonEnv = context.pythonEnv;
        intent = "${singleModuleProjectIntent}/project-intent.json";
        linkedSemanticModules = {
          "${binaryIdentity}" = linkedSemanticModule.linkedSemanticModule;
        };
        namePrefix = "${namePrefix}-single-module";
      };
      singleModuleProjects = lib.mapAttrs (configurationId: realization: {
        projectId = "single-module:${binaryIdentity}";
        rootImageId = binaryIdentity;
        intent = singleModuleProjectIntent;
        loadPlan = singleModuleProjectLoadPlan;
        nativeRealizations = {
          "${binaryIdentity}" = realization.derivation;
        };
        observedLoadGraph = null;
        completion = null;
        observationRequired = true;
        inherit configurationId;
      }) nativeRealizations;
      candidateTestFor =
        {
          id,
          configurationId,
          suite,
          runtimeData ? null,
          timeoutSeconds ? 30,
          stripStderrLineRegexes ? [ ],
        }:
        candidateTestSuite {
          inherit
            id
            configurationId
            suite
            runtimeData
            timeoutSeconds
            stripStderrLineRegexes
            ;
          namePrefix = "${namePrefix}-${configurationId}";
          candidateBinary = nativeRealizations.${configurationId}.candidate;
          nativeRealization = nativeRealizations.${configurationId}.derivation;
        };
    in
    {
      inherit
        analysis
        libraryRecognition
        linkedLibraries
        libraryOperator
        libraryCatalogConfigured
        calls
        moduleInterface
        qualifiedPlatform
        semanticObject
        linkedSemanticModule
        moduleObjectAuthority
        components
        transferPlan
        behavioralC
        behavioralCSource
        generatedSemanticProvider
        externalSemanticProvider
        runtimeSemanticProvider
        portableSemanticProvidersByComponent
        portableSemanticProvidersByLibrary
        portableSemanticProviderSets
        semanticImplementationSelections
        nativeRealizations
        singleModuleProjectIntent
        singleModuleProjectLoadPlan
        singleModuleProjects
        resolvedEnvironment
        candidateTestFor
        configurationIds
        componentConfigurationIds
        hasComponents
        ;
      originalBinary = original;
      inherit binaryIdentity;
      externalEnvironmentIntent = externalEnvironment.intent;
      externalEnvironmentAnalysisProjection = externalEnvironment.analysisProjection;
      candidates.native = nativeRealizations;
    };
  mkPe32ProjectWorkflow =
    {
      projectId,
      rootImageId,
      images,
      hostEnvironment,
      targetDistributionRoots ? [ ],
      loadObservation ? null,
      observedLoadGraph ? null,
      nativeRealizations ? null,
      namePrefix ? "spaghetti-extractor-${projectId}",
    }:
    let
      imageIds = builtins.attrNames images;
      imageWorkflows = lib.mapAttrs (
        imageId: image:
        mkPe32Workflow (
          image.workflowArgs
          // {
            targetId = image.workflowArgs.targetId or "${projectId}:${imageId}";
            binaryIdentity = image.workflowArgs.binaryIdentity or imageId;
            namePrefix = image.workflowArgs.namePrefix or "${namePrefix}-${imageId}";
          }
        )
      ) (lib.filterAttrs (_imageId: image: image.ownership == "target") images);
      projectIntent = pkgs.writeText "${namePrefix}-project-intent-v1.json" (
        builtins.toJSON {
          format = "spaghetti-extractor-pe32-project-intent-v1";
          project_id = projectId;
          root_image_id = rootImageId;
          target_distribution_roots = targetDistributionRoots;
          host_environment = {
            id = hostEnvironment.id;
            sha256 = hostEnvironment.sha256;
          };
          images = map (imageId: {
            image_id = imageId;
            filename = images.${imageId}.filename;
            aliases = images.${imageId}.aliases or [ ];
            ownership = images.${imageId}.ownership;
            implementation = images.${imageId}.implementation;
          }) imageIds;
        }
      );
      linkedSemanticModules = lib.mapAttrs (
        _imageId: workflow:
          workflow.linkedSemanticModule.linkedSemanticModule
      ) imageWorkflows;
      generatedNativeRealizations = lib.mapAttrs (
        imageId: workflow:
        let
          available = builtins.attrNames workflow.nativeRealizations;
          selected =
            images.${imageId}.configuration_id
              or (if builtins.length available == 1 then builtins.head available else null);
        in
        assert lib.assertMsg (
          selected != null
        ) "project image ${imageId} must select a native-realization configuration";
        assert lib.assertMsg (builtins.hasAttr selected workflow.nativeRealizations)
          "project image ${imageId} selected an unknown native-realization configuration";
        workflow.nativeRealizations.${selected}.derivation
      ) imageWorkflows;
      effectiveNativeRealizations =
        if nativeRealizations != null then
          nativeRealizations
        else if lib.all (
          workflow: workflow.nativeRealizations != { }
        ) (builtins.attrValues imageWorkflows)
        then
          generatedNativeRealizations
        else
          null;
      loadPlan = import ./pe32-project-load-plan.nix {
        inherit pkgs linkedSemanticModules;
        pythonEnv = context.pythonEnv;
        intent = projectIntent;
        namePrefix = namePrefix;
      };
      observedLoadGraphPackage =
        if loadObservation == null then
          null
        else
          import ./pe32-observed-load-graph.nix {
            inherit pkgs loadPlan;
            pythonEnv = context.pythonEnv;
            observation = loadObservation;
            namePrefix = namePrefix;
          };
      checkedObservedLoadGraph =
        if observedLoadGraphPackage == null then
          observedLoadGraph
        else
          "${observedLoadGraphPackage}/observed-load-graph.json";
      completion =
        if effectiveNativeRealizations == null || checkedObservedLoadGraph == null then
          null
        else
          import ./pe32-project-completion.nix {
            inherit pkgs loadPlan;
            nativeRealizations = effectiveNativeRealizations;
            pythonEnv = context.pythonEnv;
            observedLoadGraph = checkedObservedLoadGraph;
            namePrefix = namePrefix;
          };
    in
    assert lib.assertMsg (images != { }) "PE32 project requires at least one image";
    assert lib.assertMsg (builtins.hasAttr rootImageId images)
      "PE32 project root image is not declared";
    assert lib.assertMsg (
      images.${rootImageId}.ownership == "target"
    ) "PE32 project root image must be target-owned";
    assert lib.assertMsg (
      loadObservation == null || observedLoadGraph == null
    ) "provide a raw load observation or an already checked graph, not both";
    assert lib.assertMsg (lib.all (
      imageId:
      let
        image = images.${imageId};
      in
      builtins.isString image.filename
      && builtins.elem image.ownership [
        "target"
        "runtime"
      ]
      && builtins.elem image.implementation [
        "behavioral_c"
        "native_host"
      ]
      && (image.ownership != "runtime" || image.implementation == "native_host")
      && ((image.ownership == "target") == (image ? workflowArgs))
    ) imageIds) "PE32 project image declarations are malformed";
    {
      _type = "spaghetti-extractor-pe32-project-workflow-v1";
      inherit
        projectId
        rootImageId
        imageWorkflows
        linkedSemanticModules
        loadPlan
        completion
        projectIntent
        hostEnvironment
        targetDistributionRoots
        loadObservation
        ;
      nativeRealizations = effectiveNativeRealizations;
      observedLoadGraph = checkedObservedLoadGraph;
      inherit observedLoadGraphPackage;
      root = imageWorkflows.${rootImageId};
    };
  mkPe32Bundle =
    {
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
      project ? null,
    }:
    let
      metadata = parseTargetMetadata targetRoot;
      hasComponents = workflow.hasComponents or false;
      hasProject = project != null;
      targetRootString = toString targetRoot;
      relativeTargetPath =
        path:
        let
          value = toString path;
          prefix = "${targetRootString}/";
        in
        assert lib.assertMsg (lib.hasPrefix prefix value)
          "target asset ${value} is outside ${targetRootString}";
        lib.removePrefix prefix value;
      metadataAssets = [
        {
          path = "target.json";
          role = "metadata";
          owner = "target-sdk";
        }
      ]
      ++ lib.optional (metadata.paths ? nix) {
        path = metadata.paths.nix;
        role = "module";
        owner = "target-sdk";
      };
      componentAssets =
        if !hasComponents then
          [ ]
        else
          map (
            asset:
            asset
            // {
              path = relativeTargetPath asset.path;
            }
          ) workflow.components.assetInventory;
      callAssets = map (
        asset:
        asset
        // {
          path = relativeTargetPath asset.path;
        }
      ) workflow.calls.assetInventory;
      libraryIntentAssets =
        if !(metadata.paths ? libraries) then
          [ ]
        else
          let
            root = targetRoot + "/${metadata.paths.libraries}";
            entries = if builtins.pathExists root then builtins.readDir root else { };
            filenames = builtins.filter (name: entries.${name} == "regular" && lib.hasSuffix ".json" name) (
              builtins.attrNames entries
            );
          in
          map (filename: {
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
        "runtime"
        "documentation"
        "license"
        "boundary_schema"
        "boundary_source"
        "library_provider"
      ];
      invalidManualRoles = lib.subtractLists manualAssetRoles (builtins.attrNames targetAssets);
      manualAssets = lib.concatMap (
        role:
        map (path: {
          inherit path role;
          owner = "target-bundle";
        }) (targetAssets.${role} or [ ])
      ) manualAssetRoles;
      declaredAssets =
        metadataAssets
        ++ componentAssets
        ++ callAssets
        ++ libraryIntentAssets
        ++ candidateTestAssets
        ++ manualAssets;
      ownership = targetBundleLint {
        inherit targetRoot declaredAssets;
        targetId = metadata.id;
        namePrefix = "spaghetti-extractor-${metadata.id}";
      };
      defaultConfiguration = metadata.workflow.default_configuration;
      configurationIds = workflow.configurationIds;
      targetInputIdentity =
        pkgs.runCommand "spaghetti-extractor-${metadata.id}-target-input-identity-v1"
          {
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.jq
            ];
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
        libraries = lib.filterAttrs (_: value: value != null) {
          artifact-index = workflow.linkedLibraries.artifactIndex;
          catalog-lock = workflow.linkedLibraries.generatedCatalogLock;
          catalog-search-index = workflow.linkedLibraries.catalogSearchIndex;
          target-signature-graph = workflow.linkedLibraries.targetSignatureGraph;
          release-hypotheses = workflow.linkedLibraries.releaseHypotheses;
          checked-islands = workflow.linkedLibraries.checkedIslands;
          provider-bindings = workflow.linkedLibraries.providerBindings;
          semantic-slices = workflow.linkedLibraries.providerSemanticSlices;
          semantic-providers = workflow.portableSemanticProvidersByLibrary;
          status = workflow.libraryOperator.status;
        };
        boundaries = {
          status = workflow.calls.status;
          subjects = workflow.calls.subjects;
        };
        platform = {
          qualified-v1 = workflow.qualifiedPlatform.derivation;
        };
        components = {
          proposals = workflow.analysis.componentProposals;
        }
        // lib.optionalAttrs hasComponents {
          interfaces-v5 = lib.mapAttrs (_: value: value.derivation) workflow.components.v5Interfaces;
          binding-intents-v1 = workflow.components.bindingIntentPaths;
          source-packages-v3 = workflow.components.sourcePackages;
          semantic-slices-v2 = lib.mapAttrs (
            _: value: value.derivation
          ) workflow.components.v6SemanticSlices;
          work-packages-v6 = lib.mapAttrs (_: value: value.derivation) workflow.components.v6WorkPackages;
        };
        diagnostics = {
          target-ownership = ownership;
        }
        // lib.optionalAttrs hasComponents {
          candidate-status = defaultCandidateStatusReport;
        };
        candidate = {
          module-interface = workflow.moduleInterface;
          semantic-object = workflow.semanticObject.derivation;
          linked-semantic-module = workflow.linkedSemanticModule.derivation;
          object-authority = workflow.moduleObjectAuthority;
          semantic-provider-generated = workflow.generatedSemanticProvider;
          semantic-provider-portable-by-component =
            workflow.portableSemanticProvidersByComponent;
          semantic-provider-sets = workflow.portableSemanticProviderSets;
          semantic-provider-external = workflow.externalSemanticProvider;
          semantic-provider-runtime = workflow.runtimeSemanticProvider;
          semantic-implementation-selections = lib.mapAttrs (
            _: value: value.derivation
          ) workflow.semanticImplementationSelections;
          native-realizations = lib.mapAttrs (_: value: value.derivation) (
            workflow.nativeRealizations or { }
          );
          single-module-project-intent = workflow.singleModuleProjectIntent;
          single-module-project-load-plan = workflow.singleModuleProjectLoadPlan;
          tests = lib.mapAttrs (_: test: test.aggregate) candidateTests;
        }
        // lib.optionalAttrs hasProject {
          project = {
            intent = project.projectIntent;
            load-plan = project.loadPlan;
            linked-semantic-modules = lib.mapAttrs (
              _imageId: imageWorkflow:
                imageWorkflow.linkedSemanticModule.derivation
            ) project.imageWorkflows;
            native-realizations = project.nativeRealizations;
            observed-load-graph = project.observedLoadGraph;
            completion = project.completion;
          };
        }
        // lib.optionalAttrs (workflow ? transferPlan) {
          executable-transfer-plan = workflow.transferPlan.derivation;
        }
        // lib.optionalAttrs (workflow ? behavioralC) {
          behavioral-c = workflow.behavioralC;
        };
      }
      // lib.optionalAttrs (workflow ? resolvedEnvironment) {
        environment = {
          intent = workflow.externalEnvironmentIntent;
          analysis-projection = workflow.externalEnvironmentAnalysisProjection;
          resolved = workflow.resolvedEnvironment.derivation;
        };
      }
      // lib.optionalAttrs (builtins.attrNames extraArtifacts != [ ]) {
        target = extraArtifacts;
      };
      standardChecks = {
        target-bundle-assets = ownership;
        target-input-identity = targetInputIdentity;
        boundaries = workflow.calls.check;
        qualified-platform = workflow.qualifiedPlatform.derivation;
      }
      // lib.optionalAttrs (workflow ? transferPlan) {
        executable-transfer-plan = workflow.transferPlan.derivation;
        semantic-object = workflow.semanticObject.derivation;
        linked-semantic-module = workflow.linkedSemanticModule.derivation;
      }
      // lib.optionalAttrs (workflow ? resolvedEnvironment) {
        external-environment-intent = workflow.externalEnvironmentIntent;
        resolved-external-environment = workflow.resolvedEnvironment.derivation;
      }
      // lib.optionalAttrs (workflow ? behavioralCSource) {
        # Regression checks validate that behavioral C can be emitted.  Exact
        # runtime qualification and completion remain acceptance authority and
        # must not turn an incomplete root closure into a regression failure.
        behavioral-c = workflow.behavioralCSource;
      }
      // lib.optionalAttrs hasProject {
        project-load-plan = project.loadPlan;
      }
      // lib.optionalAttrs hasComponents {
        component-work-packages-v6 = pkgs.linkFarm
          "spaghetti-extractor-${metadata.id}-component-work-packages-v6"
          (lib.mapAttrsToList (name: value: {
            inherit name;
            path = value.derivation;
          }) workflow.components.v6WorkPackages);
        default-semantic-implementation-selection =
          workflow.semanticImplementationSelections.${defaultConfiguration}.derivation;
        # Status is a non-authorizing projection, but the ordinary default
        # view must be materialized by the regression workflow.  Otherwise a
        # read-only operator command has to evaluate and realize the full
        # structural/component graph merely to discover blockers that the
        # regression already checked.  Explicit non-default configurations
        # remain on-demand operator work.
        candidate-status = defaultCandidateStatusReport;
      };
      componentIntentRequired =
        pkgs.runCommand "spaghetti-extractor-${metadata.id}-component-intent-required"
          { __contentAddressed = true; }
          ''
            echo "target ${metadata.id} has no authored component intent" >&2
            echo "run project analyze, inspect component proposals, then configure a default component configuration" >&2
            exit 1
          '';
      standardAcceptanceChecks =
        if hasComponents then
          {
            default-native-realization =
              checkedCandidateBuilds.${defaultConfiguration};
          }
        else
          {
            component-intent = componentIntentRequired;
          };
      bundle = mkBundleRecord {
        inherit targetRoot apps;
        artifacts = standardArtifacts;
        checks = standardChecks // checks;
        acceptanceChecks = standardAcceptanceChecks // acceptanceChecks;
      };
      projectAnalysis = pkgs.linkFarm "spaghetti-extractor-${metadata.id}-project-analysis" (
        [
          {
            name = "target-input-identity";
            path = targetInputIdentity;
          }
        ]
        ++ lib.mapAttrsToList (name: path: { inherit name path; }) standardArtifacts.analysis
      );
      componentUnits =
        if !hasComponents then
          { }
        else
          lib.mapAttrs (
            id: interface:
            {
              build = interface.derivation;
              interface = interface.derivation;
            }
            // lib.optionalAttrs (builtins.hasAttr id workflow.components.bindingIntentPaths) {
              bindingIntent = workflow.components.bindingIntentPaths.${id};
            }
            // lib.optionalAttrs (builtins.hasAttr id workflow.components.v6WorkPackages) {
              workPackage = workflow.components.v6WorkPackages.${id}.derivation;
              semanticSlice = workflow.components.v6SemanticSlices.${id}.derivation;
              status = workflow.components.v6WorkPackages.${id}.derivation;
            }
          ) workflow.components.v5Interfaces;
      componentConfigurations =
        if !hasComponents then
          { }
        else
          lib.mapAttrs (id: _index: {
            selection = workflow.semanticImplementationSelections.${id}.derivation;
            status = candidateStatusReports.${id};
            check = checkedCandidateBuilds.${id};
          }) workflow.components.configurationIndex;
      candidateTestAggregate =
        if candidateTests == { } then
          null
        else
          pkgs.linkFarm "spaghetti-extractor-${metadata.id}-candidate-tests" (
            [
              {
                name = "target-input-identity";
                path = targetInputIdentity;
              }
            ]
            ++ lib.mapAttrsToList (name: test: {
              inherit name;
              path = test.aggregate;
            }) candidateTests
          );
      candidateTestIndex = lib.mapAttrs (_: test: {
        configurationId = test.configurationId;
        caseIds = test.caseIds;
      }) candidateTests;
      projectStatusPhase = import ./ca-python-json-phase.nix {
        inherit pkgs;
        pythonEnv = context.pythonEnv;
        name = "spaghetti-extractor-${metadata.id}-semantic-module-work-status-v1";
        kind = "semantic-module-work-status";
        artifactName = "project-status.json";
        expectedFormat = "spaghetti-extractor-operator-work-status-v1";
        allowedStatuses = [
          "complete"
          "incomplete"
          "violated"
        ];
        pythonModules = [ "spaghetti_extractor.target_bundles.project_status" ];
        phaseRole = "operator";
        pythonSource = projectStatusPythonSource;
        inputs.linked_semantic_module =
          "${workflow.linkedSemanticModule.derivation}/linked-semantic-module.json";
        program = ''
          from spaghetti_extractor.target_bundles.project_status import (
              build_project_status,
          )

          build_project_status(
              linked_semantic_module=inputs["linked_semantic_module"],
              target_id=${builtins.toJSON metadata.id},
              out=output,
          )
        '';
      };
      projectStatus = projectStatusPhase.derivation;
      mkCandidateStatus =
        configurationId:
        (import ./ca-python-json-phase.nix {
          inherit pkgs;
          pythonEnv = context.pythonEnv;
          name = "spaghetti-extractor-${metadata.id}-${configurationId}-semantic-module-work-status-v1";
          kind = "semantic-module-work-status";
          artifactName = "project-status.json";
          expectedFormat = "spaghetti-extractor-operator-work-status-v1";
          allowedStatuses = [
            "complete"
            "incomplete"
            "violated"
          ];
          pythonModules = [ "spaghetti_extractor.target_bundles.project_status" ];
          phaseRole = "operator";
          pythonSource = projectStatusPythonSource;
          inputs = {
            linked_semantic_module =
              "${workflow.linkedSemanticModule.derivation}/linked-semantic-module.json";
            implementation_selection = "${
              workflow.semanticImplementationSelections.${configurationId}.derivation
            }/implementation-selection.json";
          };
          program = ''
            from spaghetti_extractor.target_bundles.project_status import (
                build_project_status,
            )

            build_project_status(
                linked_semantic_module=inputs["linked_semantic_module"],
                implementation_selection=inputs["implementation_selection"],
                target_id=${builtins.toJSON metadata.id},
                configuration_id=${builtins.toJSON configurationId},
                out=output,
            )
          '';
        }).derivation;
      candidateStatusReports = builtins.listToAttrs (
        map (configurationId: {
          name = configurationId;
          value = mkCandidateStatus configurationId;
        }) configurationIds
      );
      defaultCandidateStatusReport =
        if !hasComponents then null else candidateStatusReports.${defaultConfiguration};
      checkedCandidateBuilds = lib.mapAttrs (
        configurationId: realization:
        pkgs.runCommand "spaghetti-extractor-${metadata.id}-${configurationId}-checked-candidate"
          {
            nativeBuildInputs = [ pkgs.jq ];
            __contentAddressed = true;
          }
          ''
            set -euo pipefail
            test -s ${targetInputIdentity}/target-input-identity.json
            jq -e '
              .format == "spaghetti-extractor-native-realization-v2" and
              .status == "complete" and .ready_for_observation and
              (.blockers | length) == 0
            ' ${realization.derivation}/native-realization.json >/dev/null
            expected_candidate_sha256="$(jq -r \
              '.candidate.sha256' \
              ${realization.derivation}/native-realization.json)"
            actual_candidate_sha256="$(sha256sum \
              ${realization.candidate} | cut -d ' ' -f 1)"
            test "$expected_candidate_sha256" = "$actual_candidate_sha256"
            mkdir -p "$out"
            cp -rs ${realization.derivation}/. "$out/"
            ln -s ${targetInputIdentity}/target-input-identity.json \
              "$out/target-input-identity.json"
          ''
      ) workflow.nativeRealizations;
      componentModeChecks = lib.mapAttrs (configurationId: _configuration: {
        selected = checkedCandidateBuilds.${configurationId};
      }) workflow.components.configurationIndex;
      checkedCandidateTests = lib.mapAttrs (
        id: test:
        pkgs.linkFarm "spaghetti-extractor-${metadata.id}-${id}-checked-candidate-test" [
          {
            name = "target-input-identity";
            path = targetInputIdentity;
          }
          {
            name = "candidate-test";
            path = test.aggregate;
          }
        ]
      ) candidateTests;
      operatorIndex = {
        targetId = metadata.id;
        inherit defaultConfiguration hasComponents;
        components = {
          units =
            if hasComponents then
              builtins.mapAttrs (_: value: {
                interface = value.interface;
                schema = value.schema;
              }) workflow.components.v5Interfaces
            else
              { };
          v5Interfaces =
            if hasComponents then
              builtins.mapAttrs (_: value: {
                interface = value.interface;
                schema = value.schema;
              }) workflow.components.v5Interfaces
            else
              { };
          configurations = if hasComponents then workflow.components.configurationIndex else { };
        };
        candidate = {
          configurations = configurationIds;
          testSuites = candidateTestIndex;
        };
        libraries = {
          configured = workflow.libraryCatalogConfigured;
          selections = builtins.attrNames workflow.linkedLibraries.checks;
        };
        boundaries = {
          configured = workflow.calls.configured;
          subjects = lib.mapAttrs (_: value: {
            kind = value.kind or "call";
            inspectionArtifact = value.inspectionArtifact or "call-inspection.json";
            intentArtifact = value.intentArtifact or "call-intent.json";
            checkArtifact = value.checkArtifact or null;
          }) workflow.calls.subjects;
        };
      };
      operator = {
        index = operatorIndex;
        project = {
          analysis = projectAnalysis;
          status = projectStatus;
          semanticModule = workflow.linkedSemanticModule.derivation;
          regressionCheck = bundle.defaultCheck;
          acceptanceCheck = bundle.acceptanceCheck;
        }
        // lib.optionalAttrs hasProject {
          workflow = project;
          intent = project.projectIntent;
          loadPlan = project.loadPlan;
          imageWorkflows = project.imageWorkflows;
          nativeRealizations = project.nativeRealizations;
          observedLoadGraph = project.observedLoadGraph;
          completion = project.completion;
        };
        components = {
          proposals = workflow.analysis.componentProposals;
          units = componentUnits;
          configurations = componentConfigurations;
          interfacesV5 = if hasComponents then workflow.components.v5Interfaces else { };
          bindingIntentsV1 = if hasComponents then workflow.components.bindingIntentPaths else { };
          semanticSlicesV2 = if hasComponents then workflow.components.v6SemanticSlices else { };
          workPackagesV6 = if hasComponents then workflow.components.v6WorkPackages else { };
        };
        libraries = {
          status = workflow.libraryOperator.status;
          check = workflow.libraryOperator.check;
          checks = workflow.linkedLibraries.checks;
          catalogSearchIndex = workflow.linkedLibraries.catalogSearchIndex;
          targetSignatureGraph = workflow.linkedLibraries.targetSignatureGraph;
          releaseHypotheses = workflow.linkedLibraries.releaseHypotheses;
          checkedIslands = workflow.linkedLibraries.checkedIslands;
          providerBindings = workflow.linkedLibraries.providerBindings;
          semanticSlices = workflow.linkedLibraries.providerSemanticSlices;
          semanticProviders = workflow.portableSemanticProvidersByLibrary;
        };
        boundaries = {
          inherit (workflow.calls) status subjects check;
        };
        candidate = {
          builds = checkedCandidateBuilds;
          checks = componentModeChecks;
          statuses = candidateStatusReports;
          materializedStatus = defaultCandidateStatusReport;
          tests = checkedCandidateTests;
          allTests = candidateTestAggregate;
          selections = workflow.semanticImplementationSelections or { };
          nativeRealizations = workflow.nativeRealizations or { };
        };
      };
    in
    assert metadata.format or null == "spaghetti-extractor-target-bundle-v3";
    assert lib.assertMsg (
      !hasProject
      || project._type == "spaghetti-extractor-pe32-project-workflow-v1"
    ) "target bundle project must be an SDK PE32 project workflow";
    assert lib.assertMsg (
      !hasProject
      || project.root.linkedSemanticModule.linkedSemanticModule
        == workflow.linkedSemanticModule.linkedSemanticModule
    ) "target bundle workflow must be the selected project root workflow";
    assert hasComponents == (defaultConfiguration != null);
    assert
      !hasComponents
      || (builtins.isString defaultConfiguration && builtins.elem defaultConfiguration configurationIds);
    assert lib.assertMsg (
      invalidManualRoles == [ ]
    ) "targetAssets contains unsupported roles: ${builtins.toJSON invalidManualRoles}";
    assert lib.assertMsg (
      (metadata.paths.components == null && !hasComponents)
      || (
        workflow.components.assetInventory != [ ]
        &&
          metadata.paths.components
          == relativeTargetPath (builtins.head workflow.components.assetInventory).path
      )
    ) "target metadata component intent does not match the workflow intent";
    assert builtins.all (
      test:
      test._type or null == "spaghetti-extractor-candidate-test-suite-v1"
      && builtins.elem test.configurationId configurationIds
    ) (builtins.attrValues candidateTests);
    bundle
    // {
      inherit
        defaultConfiguration
        candidateTests
        operator
        operatorIndex
        ;
      default = {
        behavioralC = workflow.behavioralC or null;
        implementationSelection =
          if hasComponents then workflow.semanticImplementationSelections.${defaultConfiguration} else null;
        nativeRealization =
          if hasComponents then workflow.nativeRealizations.${defaultConfiguration} else null;
      };
    };
in
{
  format = "spaghetti-extractor-target-sdk-v4";
  inherit (context) package fixtures;
  inherit (context) sources kernels tools;
  profiles = context.sources.profileSource;

  # Stable consumers enter through workflow.pe32 or workflow.pe32Project.
  workflow = {
    pe32 = mkPe32Workflow;
    pe32Project = mkPe32ProjectWorkflow;
  };
  environment.pe32 = mkPe32Environment;
  transfer.executablePlan = executableTransferPlan;
  analysis = {
    component = analysisComponent;
    externalInterfaceProfile = callWith ./external-interface-profile.nix analysisCommon;
    headerMachineAbiProfile = callWith ./header-machine-abi-profile.nix analysisCommon;
  };
  candidate = {
    behavioralC = behavioralCPackage;
    inherit
      generatedBehavioralCProviderV2
      externalEnvironmentProviderV2
      qualifiedRuntimeProviderV2
      portableCWorkPackageProviderV2
      implementationSelectionV2
      nativeRealizationV2
      ;
    moduleInterface = pe32ModuleInterface;
    testSuite = candidateTestSuite;
  };
  lifting = {
    behaviorPack = callWith ./library-behavior-pack-v3.nix analysisCommon;
    catalogPack = callWith ./library-catalog-pack.nix analysisCommon;
    linkedLibraries = callWith ./linked-libraries.nix analysisCommon;
    components = componentWorkflow;
    boundarySchema = callWith ./boundary-schema-workflow.nix analysisCommon;
  };
  validation = {
    pythonEnv = context.transferPythonEnv;
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
