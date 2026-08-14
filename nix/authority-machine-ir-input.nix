{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  machineIr,
  binary,
  binaryIdentity,
  shardBucketCount ? 4,
  resourceClasses ? import ./authority-resource-classes-v3.nix,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  sourcePlanPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.authority.source_plan" ];
    name = "${name}-source-plan-python-closure";
  };
  artifactSeedPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.artifact_set_v3" ];
    name = "${name}-artifact-seed-python-closure";
  };
  preparation = import ./authority-source-plan.nix {
    inherit pkgs pythonEnv machineIr binary resourceClasses contentAddressed;
    pythonSource = sourcePlanPythonSource;
    shardBucketCount = shardBucketCount;
    name = "${name}-source-plan-v3";
  };
  # This is the sole dynamic source boundary. Unit payloads are immediately
  # re-interned below, so unchanged content regains its old store identity.
  plan = builtins.fromJSON (builtins.readFile "${preparation}/plan.json");
  preplanned = plan.preplanned_boundaries or { };
  mkPreplannedBoundary = row: {
    derivation = preparation;
    manifest = "${preparation}/${row.schedule.filename}";
    validation = "${preparation}/${row.validation.filename}";
    packIndex = "${preparation}/${row.pack_index.filename}";
    packsDirectory = "${preparation}/${row.packs_directory}";
  };
  preplannedBoundaries = {
    structural = mkPreplannedBoundary preplanned.structural;
    dependency = mkPreplannedBoundary preplanned.dependency;
  };
  expectedRecordIds = lib.sort builtins.lessThan (
    lib.concatMap (row: row.unit_ids) plan.shards
  );
  binaryBinding = {
    name = "binary";
    kind = "pe32";
    identity = binaryIdentity;
    sha256 = plan.binary_sha256;
  };
  mkBucketShard =
    row:
    let
      source = builtins.toFile "${name}-bucket-${row.key}.ndjson" (
        builtins.readFile "${preparation}/shards/${row.filename}"
      );
      artifact = import ./artifact-seed-v3.nix {
        inherit pkgs pythonEnv contentAddressed;
        pythonSource = artifactSeedPythonSource;
        name = "${name}-bucket-${row.key}-machine-ir-v3";
        artifactKind = "machine-ir-v3-input";
        bindings = [ binaryBinding ];
        input = source;
        inputFormat = "ndjson";
        bindInputSource = false;
      };
    in
    {
      inherit artifact;
      expectedRecordIds = row.unit_ids;
    };
  shards = builtins.listToAttrs (map (row: {
    name = row.key;
    value = mkBucketShard row;
  }) plan.shards);
in
assert (plan.format or null) == "spaghetti-extractor-analysis-source-plan-v3";
assert builtins.isString binaryIdentity && binaryIdentity != "";
assert builtins.elem shardBucketCount [ 1 2 4 8 16 32 64 ];
assert plan.shard_bucket_count == shardBucketCount;
assert (preplanned.format or null) == "spaghetti-extractor-scheduling-boundaries-v3";
assert preplanned.schedule_bucket_count == shardBucketCount;
assert builtins.hashFile "sha256" preplannedBoundaries.structural.manifest
  == preplanned.structural.schedule.sha256;
assert builtins.hashFile "sha256" preplannedBoundaries.structural.validation
  == preplanned.structural.validation.sha256;
assert builtins.hashFile "sha256" preplannedBoundaries.structural.packIndex
  == preplanned.structural.pack_index.sha256;
assert builtins.hashFile "sha256" preplannedBoundaries.dependency.manifest
  == preplanned.dependency.schedule.sha256;
assert builtins.hashFile "sha256" preplannedBoundaries.dependency.validation
  == preplanned.dependency.validation.sha256;
assert builtins.hashFile "sha256" preplannedBoundaries.dependency.packIndex
  == preplanned.dependency.pack_index.sha256;
{
  inherit binaryBinding expectedRecordIds plan preparation preplannedBoundaries shards;
  bindings = [ binaryBinding ];
  expectedKind = "machine-ir-v3-input";
  structuralInventory = "${preparation}/${plan.structural_inventory.filename}";
  recordEdges = "${preparation}/${plan.record_edges.filename}";
  unresolvedDirectTargets = "${preparation}/${plan.unresolved_direct_targets.filename}";
  externalArtifact = {
    inherit shards;
    expectedKind = "machine-ir-v3-input";
    inherit expectedRecordIds;
  };
}
