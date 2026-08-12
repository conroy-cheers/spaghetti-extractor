{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  phases,
  contentAddressed ? true,
}:

# Each phase specification declares its own Python roots, raw Nix-store inputs,
# output schema, and producer body.  The producer body runs with `inputs`, a
# name-to-Path mapping, and `output`, its declared artifact Path.  Missing or
# contradictory evidence is a successful fail-closed artifact status; only a
# separate consumer may treat a final `pass` audit as candidate authority.

let
  lib = pkgs.lib;
  requiredPhaseNames = [
    "exactUnitPrep"
    "transitionSummaries"
    "memoryVersionGraph"
    "baseGraph"
    "structuralTargetProposals"
    "interproceduralSeed"
    "parametricIndirectExitSummaries"
    "controlInvariantCertificates"
    "memoryRangeInvariants"
    "jointInterproceduralV2"
    "interproceduralV2"
    "inductiveCertificateProposals"
    "inductiveCertificateAuthority"
    "inductiveDependencyClosure"
    "rootedClosure"
    "externalProfileAuthority"
    "checkedExternalSites"
    "globalSlotAnalysis"
    "globalSlotAuthority"
    "callbackEntryContracts"
    "finalizedLaunchProfile"
    "entryRootClosure"
    "isaRequirements"
    "isaSelectionAuthority"
    "exceptionCertificates"
    "staticAuthority"
    "authorityBundle"
    "finalAudit"
  ];
  missingPhases = lib.filter (name: !(builtins.hasAttr name phases)) requiredPhaseNames;
  unexpectedPhases = lib.filter (name: !(builtins.elem name requiredPhaseNames)) (
    builtins.attrNames phases
  );

  mkPhase =
    phaseName: dependencies:
    let
      spec = phases.${phaseName};
      ownInputs = spec.inputs or { };
      overlap = lib.intersectLists (builtins.attrNames ownInputs) (builtins.attrNames dependencies);
    in
    assert overlap == [ ];
    import ./ca-python-json-phase.nix {
      inherit
        pkgs
        pythonEnv
        contentAddressed
        ;
      pythonSource = spec.pythonSource or pythonSource;
      name = "${namePrefix}-${spec.derivationSuffix}";
      kind = spec.kind;
      artifactName = spec.artifactName;
      expectedFormat = spec.expectedFormat;
      allowedStatuses = spec.allowedStatuses;
      pythonModules = spec.pythonModules;
      pythonExtraPaths = spec.pythonExtraPaths or [ ];
      extraNativeBuildInputs = spec.extraNativeBuildInputs or [ ];
      inputs = ownInputs // dependencies;
      program = spec.program;
    };

  exactUnitPrep = mkPhase "exactUnitPrep" { };
  transitionSummaries = mkPhase "transitionSummaries" {
    exact_unit_prep = exactUnitPrep.artifact;
  };
  memoryVersionGraph = mkPhase "memoryVersionGraph" {
    exact_unit_prep = exactUnitPrep.artifact;
    transition_summaries = transitionSummaries.artifact;
  };
  baseGraph = mkPhase "baseGraph" {
    exact_unit_prep = exactUnitPrep.artifact;
  };
  structuralTargetProposals = mkPhase "structuralTargetProposals" {
    exact_unit_prep = exactUnitPrep.artifact;
    transition_summaries = transitionSummaries.artifact;
  };
  interproceduralSeed = mkPhase "interproceduralSeed" {
    exact_unit_prep = exactUnitPrep.artifact;
    base_graph = baseGraph.artifact;
  };
  parametricIndirectExitSummaries = mkPhase "parametricIndirectExitSummaries" {
    interprocedural_seed = interproceduralSeed.artifact;
  };
  controlInvariantCertificates = mkPhase "controlInvariantCertificates" {
    exact_unit_prep = exactUnitPrep.artifact;
  };
  memoryRangeInvariants = mkPhase "memoryRangeInvariants" {
    exact_unit_prep = exactUnitPrep.artifact;
  };
  jointInterproceduralV2 = mkPhase "jointInterproceduralV2" {
    exact_unit_prep = exactUnitPrep.artifact;
    base_graph = baseGraph.artifact;
    interprocedural_seed = interproceduralSeed.artifact;
    parametric_indirect_exit_summaries =
      parametricIndirectExitSummaries.artifact;
    control_invariants = controlInvariantCertificates.artifact;
    memory_range_invariants = memoryRangeInvariants.artifact;
  };
  interproceduralV2 = mkPhase "interproceduralV2" {
    joint_interprocedural = jointInterproceduralV2.artifact;
  };
  inductiveCertificateProposals = mkPhase "inductiveCertificateProposals" {
    exact_unit_prep = exactUnitPrep.artifact;
    transition_summaries = transitionSummaries.artifact;
    memory_version_graph = memoryVersionGraph.artifact;
    base_graph = baseGraph.artifact;
    structural_target_proposals = structuralTargetProposals.artifact;
  };
  inductiveCertificateAuthority = mkPhase "inductiveCertificateAuthority" {
    exact_unit_prep = exactUnitPrep.artifact;
    transition_summaries = transitionSummaries.artifact;
    memory_version_graph = memoryVersionGraph.artifact;
    base_graph = baseGraph.artifact;
    structural_target_proposals = structuralTargetProposals.artifact;
    inductive_certificate_proposals = inductiveCertificateProposals.artifact;
  };
  globalSlotAnalysis = mkPhase "globalSlotAnalysis" {
    joint_interprocedural = jointInterproceduralV2.artifact;
  };
  globalSlotAuthority = mkPhase "globalSlotAuthority" {
    joint_interprocedural = jointInterproceduralV2.artifact;
    base_graph = baseGraph.artifact;
    memory_range_invariants = memoryRangeInvariants.artifact;
  };
  externalProfileAuthority = mkPhase "externalProfileAuthority" { };
  rootedClosure = mkPhase "rootedClosure" {
    base_graph = baseGraph.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
  };
  checkedExternalSites = mkPhase "checkedExternalSites" {
    interprocedural_v2 = interproceduralV2.artifact;
    rooted_closure = rootedClosure.artifact;
    external_profile_authority = externalProfileAuthority.artifact;
  };
  callbackEntryContracts = mkPhase "callbackEntryContracts" {
    exact_unit_prep = exactUnitPrep.artifact;
    base_graph = baseGraph.artifact;
    global_slot_authority = globalSlotAuthority.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
  };
  inductiveDependencyClosure = mkPhase "inductiveDependencyClosure" {
    exact_unit_prep = exactUnitPrep.artifact;
    transition_summaries = transitionSummaries.artifact;
    memory_version_graph = memoryVersionGraph.artifact;
    structural_target_proposals = structuralTargetProposals.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
    inductive_certificate_proposals = inductiveCertificateProposals.artifact;
    local_inductive_authority = inductiveCertificateAuthority.artifact;
    rooted_closure = rootedClosure.artifact;
    external_profile_authority = externalProfileAuthority.artifact;
    checked_external_sites = checkedExternalSites.artifact;
    callback_entry_contracts = callbackEntryContracts.artifact;
    global_slot_authority = globalSlotAuthority.artifact;
  };
  finalizedLaunchProfile = mkPhase "finalizedLaunchProfile" {
    base_graph = baseGraph.artifact;
    callback_entry_contracts = callbackEntryContracts.artifact;
  };
  entryRootClosure = mkPhase "entryRootClosure" {
    base_graph = baseGraph.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
    rooted_closure = rootedClosure.artifact;
    external_profile_authority = externalProfileAuthority.artifact;
    checked_external_sites = checkedExternalSites.artifact;
    global_slot_authority = globalSlotAuthority.artifact;
    callback_entry_contracts = callbackEntryContracts.artifact;
    finalized_launch_profile = finalizedLaunchProfile.artifact;
  };
  isaRequirements = mkPhase "isaRequirements" {
    exact_unit_prep = exactUnitPrep.artifact;
    base_graph = baseGraph.artifact;
  };
  isaSelectionAuthority = mkPhase "isaSelectionAuthority" {
    isa_requirements = isaRequirements.artifact;
  };
  exceptionCertificates = mkPhase "exceptionCertificates" {
    exact_unit_prep = exactUnitPrep.artifact;
    rooted_closure = rootedClosure.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
  };
  staticAuthority = mkPhase "staticAuthority" {
    exact_unit_prep = exactUnitPrep.artifact;
    base_graph = baseGraph.artifact;
    rooted_closure = rootedClosure.artifact;
    interprocedural_v2 = interproceduralV2.artifact;
    external_profile_authority = externalProfileAuthority.artifact;
    checked_external_sites = checkedExternalSites.artifact;
    entry_root_closure = entryRootClosure.artifact;
    isa_requirements = isaRequirements.artifact;
    isa_selection_authority = isaSelectionAuthority.artifact;
    exception_certificates = exceptionCertificates.artifact;
    inductive_certificate_authority = inductiveDependencyClosure.artifact;
  };
  authorityBundle = mkPhase "authorityBundle" {
    static_authority = staticAuthority.artifact;
  };
  finalAudit = mkPhase "finalAudit" {
    static_authority = staticAuthority.artifact;
    authority_bundle = authorityBundle.artifact;
  };

  phaseList = [
    exactUnitPrep
    transitionSummaries
    memoryVersionGraph
    baseGraph
    structuralTargetProposals
    interproceduralSeed
    parametricIndirectExitSummaries
    controlInvariantCertificates
    memoryRangeInvariants
    jointInterproceduralV2
    interproceduralV2
    inductiveCertificateProposals
    inductiveCertificateAuthority
    globalSlotAnalysis
    globalSlotAuthority
    rootedClosure
    externalProfileAuthority
    checkedExternalSites
    callbackEntryContracts
    inductiveDependencyClosure
    finalizedLaunchProfile
    entryRootClosure
    isaRequirements
    isaSelectionAuthority
    exceptionCertificates
    staticAuthority
    authorityBundle
    finalAudit
  ];
in
assert missingPhases == [ ];
assert unexpectedPhases == [ ];
assert contentAddressed;
{
  inherit
    exactUnitPrep
    transitionSummaries
    memoryVersionGraph
    baseGraph
    structuralTargetProposals
    interproceduralSeed
    parametricIndirectExitSummaries
    controlInvariantCertificates
    memoryRangeInvariants
    jointInterproceduralV2
    inductiveCertificateProposals
    inductiveCertificateAuthority
    inductiveDependencyClosure
    interproceduralV2
    rootedClosure
    externalProfileAuthority
    checkedExternalSites
    globalSlotAnalysis
    globalSlotAuthority
    callbackEntryContracts
    finalizedLaunchProfile
    entryRootClosure
    isaRequirements
    isaSelectionAuthority
    exceptionCertificates
    staticAuthority
    authorityBundle
    finalAudit
    ;

  artifacts = lib.listToAttrs (
    map (phase: {
      name = phase.kind;
      value = phase.artifact;
    }) phaseList
  );
  manifests = lib.listToAttrs (
    map (phase: {
      name = phase.kind;
      value = phase.manifest;
    }) phaseList
  );
}
