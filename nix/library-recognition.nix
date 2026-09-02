# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  pythonSource,
  original,
  machineIr,
  namePrefix,
  targetId,
  binaryIdentity ? targetId,
  catalogIndexes ? [ ],
  abiCatalogs ? [ ],
  catalogLock ? null,
  implementations ? { },
}:

# Keep root-independent recognition physically separate from the post-authority
# island/adoption pass. Nix laziness means no downstream library derivation is
# realized through this facade.
let
  recognition = import ./linked-libraries.nix {
    inherit pkgs pythonEnv pythonSource original machineIr namePrefix targetId
      binaryIdentity
      catalogIndexes abiCatalogs catalogLock implementations;
    adoptionIntents = { };
  };
in {
  inherit (recognition)
    artifactIndex
    effectiveCatalogLock
    catalogSearchIndex
    targetSignatureGraph
    releaseHypotheses
    ;
}
