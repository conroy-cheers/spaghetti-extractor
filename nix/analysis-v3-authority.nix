{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource ? null,
  spaghettiExtractor ? null,
  isaKernelCache ? null,
  isaSemanticKernel ? null,
  bochsRunner ? null,
  name,
  machineIr,
  binary,
  binaryIdentity,
  machineImportProfiles ? [ ],
  launchProfileTemplate ? null,
  externalArtifacts ? { },
  outputs ? [ "final-authority-v3" ],
  scheduleBucketCount ? 4,
  resourceClasses ? import ./authority-resource-classes-v3.nix,
  contentAddressed ? true,
  diagnosticEmptyEvidence ? false,
}:

let
  lib = pkgs.lib;
  artifactSeedPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.artifact_set_v3" ];
    name = "${name}-artifact-seed-python-closure";
  };
  machineInput = import ./analysis-v3-machine-ir-input.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      machineIr
      binary
      binaryIdentity
      resourceClasses
      contentAddressed
      ;
    name = "${name}-machine-input";
    shardBucketCount = scheduleBucketCount;
  };
  externalInputs = import ./analysis-v3-external-inputs.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      binary
      machineIr
      binaryIdentity
      machineImportProfiles
      launchProfileTemplate
      contentAddressed
      ;
    name = "${name}-external-inputs-v3";
  };
  standardEvidence = import ./analysis-v3-standard-evidence.nix {
    inherit pkgs pythonEnv pythonSource contentAddressed;
    name = "${name}-standard-evidence-v3";
    machineIrManifest = "${builtins.dirOf (toString machineIr)}/machine-ir-manifest.json";
    launchRoots = externalInputs.launchRoots.artifact;
  };
  manifestDerivation = import ./analysis-v3-graph-manifest.nix {
    inherit pkgs pythonEnv pythonSource outputs contentAddressed;
    name = "${name}-graph-manifest";
    graphId = name;
  };
  manifest = builtins.fromJSON (builtins.readFile "${manifestDerivation}/graph.json");
  machineIrPackage = builtins.dirOf (toString machineIr);
  externalKinds = removeAttrs manifest.external_artifact_kinds [ "machine_ir" ];
  unknownOverrides = lib.subtractLists (builtins.attrNames externalKinds) (
    builtins.attrNames externalArtifacts
  );
  emptyArtifacts = lib.mapAttrs (
    inputName: artifactKind:
    let
      artifact = import ./artifact-seed-v3.nix {
        inherit pkgs pythonEnv artifactKind contentAddressed;
        pythonSource = artifactSeedPythonSource;
        name = "${name}-${inputName}-empty-v3";
        bindings = machineInput.bindings;
        inputFormat = "empty";
      };
    in
    {
      inherit artifact;
      expectedKind = artifactKind;
      expectedRecordIds = [ ];
    }
  ) externalKinds;
  nativeExternalArtifacts = {
    external_profiles = externalInputs.externalProfiles;
    launch_roots = externalInputs.launchRoots;
  };
  earlyStandardExternalArtifacts = {
    inductive_inputs = standardEvidence.inductiveInputs;
    target_hints = standardEvidence.targetHints;
  };
  bootstrapExternalArtifacts = emptyArtifacts // nativeExternalArtifacts // (
    if diagnosticEmptyEvidence then { } else earlyStandardExternalArtifacts
  ) // externalArtifacts // {
    machine_ir = machineInput.externalArtifact;
  };
  mkGraph = graphExternalArtifacts: import ./authority-graph-v3.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      manifest
      contentAddressed
      scheduleBucketCount
      resourceClasses
      ;
    structuralInventory = machineInput.structuralInventory;
    recordEdges = machineInput.recordEdges;
    externalArtifacts = graphExternalArtifacts;
    bindings = machineInput.bindings;
    preplannedBoundaries = machineInput.preplannedBoundaries;
  };
  # Evidence for late authority phases depends on earlier checked graph
  # outputs.  Build that root-independent prefix first, then reinstantiate the
  # graph with the checked providers.  Identical upstream CA derivations are
  # shared; this does not recompute extraction, semantics, or target closure.
  bootstrapGraph = mkGraph bootstrapExternalArtifacts;
  generatedExceptionEvidence =
    if
      diagnosticEmptyEvidence
      || builtins.hasAttr "exception_evidence" externalArtifacts
      || launchProfileTemplate == null
    then
      null
    else
      import ./analysis-v3-exception-evidence.nix {
        inherit pkgs pythonEnv pythonSource machineIr contentAddressed;
        name = "${name}-exception-evidence-v3";
        semanticIndex = bootstrapGraph.phases."semantic-index-v3".artifact;
        launchProfile = launchProfileTemplate;
      };
  generatedExceptionEvidenceMetadata =
    if generatedExceptionEvidence == null then null else
    builtins.fromJSON (
      builtins.readFile "${generatedExceptionEvidence}/metadata.json"
    );
  generatedExceptionEvidenceArtifact =
    lib.optionalAttrs (generatedExceptionEvidence != null) {
      exception_evidence = {
        artifact = "${generatedExceptionEvidence}/artifact";
        expectedKind = externalKinds.exception_evidence;
        expectedRecordIds =
          generatedExceptionEvidenceMetadata.record_ids;
      };
    };
  isaEvidenceEnabled =
    isaPythonSource != null
    && spaghettiExtractor != null
    && isaKernelCache != null
    && isaSemanticKernel != null
    && bochsRunner != null;
  generatedISAEvidence =
    if
      diagnosticEmptyEvidence
      || builtins.hasAttr "isa_evidence" externalArtifacts
      || !isaEvidenceEnabled
    then
      null
    else
      import ./analysis-v3-isa-evidence.nix {
        inherit
          pkgs
          pythonEnv
          pythonSource
          isaPythonSource
          spaghettiExtractor
          bochsRunner
          binary
          contentAddressed
          ;
        kernelCache = isaKernelCache;
        semanticKernel = "${isaSemanticKernel}/semantic-kernel.json";
        name = "${name}-isa-evidence-v3";
        machineIr = machineIr;
        semanticIndex = bootstrapGraph.phases."semantic-index-v3".artifact;
      };
  generatedISAEvidenceArtifact =
    lib.optionalAttrs (generatedISAEvidence != null) {
      isa_evidence = {
        artifact = generatedISAEvidence.artifact;
        expectedKind = externalKinds.isa_evidence;
        expectedRecordIds = generatedISAEvidence.metadata.record_ids;
      };
    };
  generatedIndexedTargetEvidence =
    if
      diagnosticEmptyEvidence
      || builtins.hasAttr "target_evidence" externalArtifacts
    then
      null
    else
      import ./analysis-v3-indexed-target-evidence.nix {
        inherit pkgs pythonEnv pythonSource binary machineIr contentAddressed;
        name = "${name}-indexed-target-evidence-v3";
        machineIrManifest =
          "${builtins.dirOf (toString machineIr)}/machine-ir-manifest.json";
        semanticIndex = bootstrapGraph.phases."semantic-index-v3".artifact;
        transitionSummaries =
          bootstrapGraph.phases."transition-summaries-v3".artifact;
        structuralTargets =
          bootstrapGraph.phases."structural-target-proposals-v3".artifact;
        targetHints = standardEvidence.targetHints.artifact;
      };
  generatedIndexedTargetEvidenceMetadata =
    if generatedIndexedTargetEvidence == null then null else
    builtins.fromJSON (
      builtins.readFile "${generatedIndexedTargetEvidence}/metadata.json"
    );
  generatedTargetEvidenceArtifact =
    lib.optionalAttrs (generatedIndexedTargetEvidence != null) {
      target_evidence = {
        artifact = "${generatedIndexedTargetEvidence}/artifact";
        expectedKind = externalKinds.target_evidence;
        expectedRecordIds =
          generatedIndexedTargetEvidenceMetadata.record_ids;
      };
    };
  targetEvidenceExternalArtifacts =
    bootstrapExternalArtifacts
    // generatedTargetEvidenceArtifact
    // generatedISAEvidenceArtifact;
  targetEvidenceGraph =
    if generatedIndexedTargetEvidence == null && generatedISAEvidence == null then
      bootstrapGraph
    else
      mkGraph targetEvidenceExternalArtifacts;
  generatedExternalSiteEvidence =
    if
      diagnosticEmptyEvidence
      || builtins.hasAttr "external_site_evidence" externalArtifacts
    then
      null
    else
      import ./analysis-v3-external-site-evidence.nix {
        inherit pkgs pythonEnv pythonSource contentAddressed;
        name = "${name}-external-site-evidence-v3";
        semanticIndex = targetEvidenceGraph.phases."semantic-index-v3".artifact;
        transitionSummaries =
          targetEvidenceGraph.phases."transition-summaries-v3".artifact;
        targetCertificates =
          targetEvidenceGraph.phases."indirect-target-certificates-v3".artifact;
        externalProfiles = externalInputs.externalProfiles.artifact;
      };
  generatedExternalSiteEvidenceMetadata =
    if generatedExternalSiteEvidence == null then null else
    builtins.fromJSON (
      builtins.readFile "${generatedExternalSiteEvidence}/metadata.json"
    );
  fallbackInterpreter =
    if
      diagnosticEmptyEvidence
      || builtins.hasAttr "implementation_capabilities" externalArtifacts
    then
      null
    else
      import ./stage-b-interpreter-package.nix {
        inherit pkgs pythonEnv pythonSource;
        machineIr = machineIrPackage;
        namePrefix = "${name}-standard-fallback";
        # The package remains useful evidence while target closure is
        # incomplete.  It fails closed on a deferred transfer if executed.
        allowDeferredPotentialTransfers = true;
      };
  fallbackInterpreterMetadata =
    if fallbackInterpreter == null then null else
    builtins.fromJSON (
      builtins.readFile
        "${fallbackInterpreter}/state-machine-interpreter-package.json"
    );
  fallbackCoverageReceipt =
    if
      fallbackInterpreterMetadata == null
      || fallbackInterpreterMetadata.semantic_coverage.status != "complete"
    then
      null
    else
      import ./stage-b-fallback-coverage-receipt.nix {
        inherit pkgs pythonEnv pythonSource;
        machineIr = machineIrPackage;
        interpreterPackage = fallbackInterpreter;
        namePrefix = "${name}-standard-fallback";
        inherit contentAddressed;
      };
  generatedImplementationCapabilities =
    if fallbackInterpreter == null then null else
    import ./analysis-v3-implementation-capabilities.nix {
      inherit pkgs pythonEnv pythonSource;
      machineIr = machineIrPackage;
      semanticIndex = targetEvidenceGraph.phases."semantic-index-v3".artifact;
      isaQualification = targetEvidenceGraph.phases."isa-qualification-v3".artifact;
      interpreterPackage = fallbackInterpreter;
      inherit fallbackCoverageReceipt;
      namePrefix = "${name}-standard-fallback";
    };
  generatedImplementationCapabilitiesMetadata =
    if generatedImplementationCapabilities == null then null else
    builtins.fromJSON (
      builtins.readFile
        "${generatedImplementationCapabilities}/projection-metadata.json"
    );
  generatedProviderArtifacts =
    generatedExceptionEvidenceArtifact
    // generatedTargetEvidenceArtifact
    // generatedISAEvidenceArtifact
    // lib.optionalAttrs (generatedExternalSiteEvidence != null) {
      external_site_evidence = {
        artifact = "${generatedExternalSiteEvidence}/artifact";
        expectedKind = externalKinds.external_site_evidence;
        expectedRecordIds =
          generatedExternalSiteEvidenceMetadata.record_ids;
      };
    }
    // lib.optionalAttrs (generatedImplementationCapabilities != null) {
      implementation_capabilities = {
        artifact =
          "${generatedImplementationCapabilities}/implementation-capabilities";
        expectedKind = externalKinds.implementation_capabilities;
        expectedRecordIds =
          generatedImplementationCapabilitiesMetadata.record_ids;
      };
    };
  standardExternalArtifacts =
    earlyStandardExternalArtifacts // generatedProviderArtifacts;
  resolvedExternalArtifacts = emptyArtifacts // nativeExternalArtifacts // (
    if diagnosticEmptyEvidence then { } else standardExternalArtifacts
  ) // externalArtifacts // {
    machine_ir = machineInput.externalArtifact;
  };
  graph = mkGraph resolvedExternalArtifacts;
  finalAuthority = graph.phases."final-authority-v3".derivation or null;
  finalAuthorityArtifact = graph.outputs."final-authority-v3" or null;
  finalAuthorityGate =
    if finalAuthorityArtifact == null then
      null
    else
      import ./analysis-v3-final-authority-gate.nix {
        inherit pkgs pythonEnv pythonSource contentAddressed;
        name = "${name}-final-authority-gate-v3";
        artifact = finalAuthorityArtifact;
      };
  diagnosticsArtifacts = lib.mapAttrs (
    _: phase: phase.artifact
  ) graph.phases;
  diagnostics = import ./analysis-v3-diagnostics.nix {
    inherit pkgs pythonEnv pythonSource contentAddressed;
    name = "${name}-diagnostics-v3";
    artifacts = diagnosticsArtifacts;
    graphManifest = manifest;
  };
in
assert builtins.isAttrs externalArtifacts;
assert builtins.isList machineImportProfiles;
assert builtins.isBool diagnosticEmptyEvidence;
assert !(builtins.hasAttr "machine_ir" externalArtifacts);
assert unknownOverrides == [ ];
{
  inherit
    emptyArtifacts
    bootstrapGraph
    bootstrapExternalArtifacts
    externalInputs
    fallbackCoverageReceipt
    fallbackInterpreter
    generatedExternalSiteEvidence
    generatedExceptionEvidence
    generatedISAEvidence
    generatedIndexedTargetEvidence
    generatedImplementationCapabilities
    generatedProviderArtifacts
    graph
    machineInput
    manifest
    manifestDerivation
    nativeExternalArtifacts
    standardEvidence
    targetEvidenceGraph
    targetEvidenceExternalArtifacts
    earlyStandardExternalArtifacts
    standardExternalArtifacts
    resolvedExternalArtifacts
    finalAuthority
    finalAuthorityArtifact
    finalAuthorityGate
    diagnostics
    ;
}
