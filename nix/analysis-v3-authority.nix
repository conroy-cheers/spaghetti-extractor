{
  pkgs,
  pythonEnv,
  pythonSource,
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
  manifestDerivation = import ./analysis-v3-graph-manifest.nix {
    inherit pkgs pythonEnv pythonSource outputs contentAddressed;
    name = "${name}-graph-manifest";
    graphId = name;
  };
  manifest = builtins.fromJSON (builtins.readFile "${manifestDerivation}/graph.json");
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
  resolvedExternalArtifacts = emptyArtifacts // nativeExternalArtifacts // externalArtifacts // {
    machine_ir = machineInput.externalArtifact;
  };
  graph = import ./authority-graph-v3.nix {
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
    externalArtifacts = resolvedExternalArtifacts;
    bindings = machineInput.bindings;
    preplannedBoundaries = machineInput.preplannedBoundaries;
  };
in
assert builtins.isAttrs externalArtifacts;
assert builtins.isList machineImportProfiles;
assert !(builtins.hasAttr "machine_ir" externalArtifacts);
assert unknownOverrides == [ ];
{
  inherit
    emptyArtifacts
    externalInputs
    graph
    machineInput
    manifest
    manifestDerivation
    nativeExternalArtifacts
    resolvedExternalArtifacts
    ;
  finalAuthority = graph.phases."final-authority-v3".derivation or null;
  finalAuthorityArtifact = graph.outputs."final-authority-v3" or null;
}
