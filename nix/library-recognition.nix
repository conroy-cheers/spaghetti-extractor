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
  physicalAbiCatalogs ? [ ],
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
      catalogIndexes abiCatalogs physicalAbiCatalogs catalogLock implementations;
    adoptionIntents = { };
    parametricSummaries = null;
    canonicalExternalSites = null;
    targetCertificates = null;
  };
in {
  inherit (recognition)
    artifactIndex
    effectiveCatalogLock
    catalogSearchIndex
    targetSignatureGraph
    releaseHypotheses
    catalogCallContracts
    ;
}
