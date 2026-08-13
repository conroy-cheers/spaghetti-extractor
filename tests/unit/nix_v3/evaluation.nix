{ pkgs }:
let
  fixture = import ./fixture.nix;
  base = fixture { inherit pkgs; };
  repeated = fixture { inherit pkgs; };
  structuralChanged = fixture { inherit pkgs; structuralMutation = true; };
  edgeChanged = fixture { inherit pkgs; edgeMutation = true; };
  recordChanged = fixture { inherit pkgs; recordMutation = true; };
  phaseSourceChanged = fixture { inherit pkgs; phaseSourceMutation = true; };
  lib = base.pkgs.lib;

  drvPath =
    value:
    builtins.unsafeDiscardStringContext (
      if builtins.isAttrs value.derivation then
        value.derivation.drvPath
      else
        toString value.derivation
    );
  packDrvPaths = packs: lib.mapAttrs (_: pack: drvPath pack) packs;
  shardDrvPaths =
    graph: phaseId: lib.mapAttrs (_: shard: drvPath shard) graph.phases.${phaseId}.shards;
  externalDrvPaths = graph: lib.mapAttrs (_: shard: drvPath shard) graph.external.units.shards;
  compositionDrvPaths =
    graph:
    lib.mapAttrs (
      _: shard: drvPath shard.inputCompositions.transitions
    ) graph.phases."scc-summarize".shards;
  changedKeys =
    left: right:
    let
      common = builtins.filter (key: builtins.hasAttr key right) (builtins.attrNames left);
    in
    builtins.filter (key: left.${key} != right.${key}) common;
  stableKeys =
    left: right:
    let
      common = builtins.filter (key: builtins.hasAttr key right) (builtins.attrNames left);
    in
    builtins.filter (key: left.${key} == right.${key}) common;
  keyForItem =
    packs: itemId:
    builtins.head (
      builtins.filter (key: builtins.elem itemId packs.${key}.itemIds) (builtins.attrNames packs)
    );
  dependencyKeyForMember =
    graph: member:
    builtins.head (
      builtins.filter (
        key: builtins.elem member graph.dependency.packs.${key}.payload.selected_node_ids
      ) (builtins.attrNames graph.dependency.packs)
    );

  structuralKeyA = keyForItem base.structuralPacks "unit:a";
  structuralKeyB = keyForItem base.structuralPacks "unit:b";
  structuralKeyC = keyForItem base.structuralPacks "unit:c";
  structuralKeyD = keyForItem base.structuralPacks "unit:d";
  dependencyKeyAB = dependencyKeyForMember base "unit:a";
  dependencyKeyC = dependencyKeyForMember base "unit:c";
  dependencyKeyD = dependencyKeyForMember base "unit:d";
  dependentSccKeys = lib.sort builtins.lessThan [
    dependencyKeyAB
    dependencyKeyD
  ];

  baseStructural = packDrvPaths base.structuralPacks;
  repeatedStructural = packDrvPaths repeated.structuralPacks;
  changedStructural = packDrvPaths structuralChanged.structuralPacks;
  baseDependency = packDrvPaths base.dependencyPacks;
  repeatedDependency = packDrvPaths repeated.dependencyPacks;
  structuralChangedDependency = packDrvPaths structuralChanged.dependencyPacks;
  edgeChangedDependency = packDrvPaths edgeChanged.dependencyPacks;
  recordChangedDependency = packDrvPaths recordChanged.dependencyPacks;
  baseExternal = externalDrvPaths base;
  changedExternal = externalDrvPaths recordChanged;
  baseTransition = shardDrvPaths base "transition";
  changedTransition = shardDrvPaths recordChanged "transition";
  baseScc = shardDrvPaths base "scc-summarize";
  changedScc = shardDrvPaths recordChanged "scc-summarize";
  baseCompositions = compositionDrvPaths base;
  changedCompositions = compositionDrvPaths recordChanged;
  phaseDrv = graph: phaseId: drvPath graph.phases.${phaseId};
  compositionManifest = builtins.fromJSON (
    builtins.readFile base.phases.composition.manifest
  );
  compositionBindingNames = map (binding: binding.name) compositionManifest.bindings;
in
assert base.structural.plan.format == "spaghetti-extractor-structural-pack-index-v3";
assert base.dependency.plan.format == "spaghetti-extractor-dependency-pack-index-v3";
assert base.structural.plan.unit_count == 4;
assert base.dependency.plan.scc_count == 3;
assert baseStructural == repeatedStructural;
assert baseDependency == repeatedDependency;
assert changedKeys baseStructural changedStructural == [ structuralKeyA ];
assert changedKeys baseDependency structuralChangedDependency == dependentSccKeys;
assert changedKeys baseDependency edgeChangedDependency == dependentSccKeys;
assert baseDependency == recordChangedDependency;
assert changedKeys baseExternal changedExternal == [ "a" ];
assert changedKeys baseTransition changedTransition == [ structuralKeyA ];
assert
  stableKeys baseTransition changedTransition == lib.sort builtins.lessThan [
    structuralKeyB
    structuralKeyC
    structuralKeyD
  ];
assert changedKeys baseCompositions changedCompositions == dependentSccKeys;
assert stableKeys baseCompositions changedCompositions == [ dependencyKeyC ];
assert changedKeys baseScc changedScc == dependentSccKeys;
assert stableKeys baseScc changedScc == [ dependencyKeyC ];
assert phaseDrv base "transition" != phaseDrv recordChanged "transition";
assert phaseDrv base "scc-summarize" != phaseDrv recordChanged "scc-summarize";
assert phaseDrv base "composition" != phaseDrv recordChanged "composition";
assert shardDrvPaths base "transition" == shardDrvPaths phaseSourceChanged "transition";
assert shardDrvPaths base "scc-summarize" == shardDrvPaths phaseSourceChanged "scc-summarize";
assert phaseDrv base "composition" != phaseDrv phaseSourceChanged "composition";
assert base.phases.transition.shards.${structuralKeyA}.memoryLimitMiB == 768;
assert base.phases.transition.shards.${structuralKeyB}.memoryLimitMiB == 1536;
assert base.phases.transition.shards.${structuralKeyC}.memoryLimitMiB == 3584;
assert base.phases.transition.shards.${structuralKeyD}.memoryLimitMiB == 32768;
assert base.phases."scc-summarize".shards.${dependencyKeyAB}.memoryLimitMiB == 768;
assert base.phases."scc-summarize".shards.${dependencyKeyC}.memoryLimitMiB == 1536;
assert base.phases."scc-summarize".shards.${dependencyKeyD}.memoryLimitMiB == 3584;
assert base.phases.composition.memoryLimitMiB == 768;
assert builtins.elem "phase-runner" compositionBindingNames;
assert builtins.elem "phase-source" compositionBindingNames;
assert base.metadataValue.packs.structural.${structuralKeyA}.resource.memory_mib < 2048;
assert base.metadataValue.packs.structural.${structuralKeyB}.resource.memory_mib < 2048;
assert base.metadataValue.packs.structural.${structuralKeyC}.resource.memory_mib < 4096;
{
  success = true;
  structural_invalidated = changedKeys baseStructural changedStructural;
  structural_stable = stableKeys baseStructural changedStructural;
  dependency_invalidated = changedKeys baseDependency edgeChangedDependency;
  dependency_stable = stableKeys baseDependency edgeChangedDependency;
  external_record_invalidated = changedKeys baseExternal changedExternal;
  transition_invalidated = changedKeys baseTransition changedTransition;
  transition_stable = stableKeys baseTransition changedTransition;
  composition_invalidated = changedKeys baseCompositions changedCompositions;
  composition_stable = stableKeys baseCompositions changedCompositions;
  scc_invalidated = changedKeys baseScc changedScc;
  scc_stable = stableKeys baseScc changedScc;
  output_ids = base.metadataValue.outputs;
}
