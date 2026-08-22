# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  pythonSource,
  unitFacts,
  memoryVersions,
  structuralTargets,
  externalProfiles,
  staticValueOrigins,
  catalogCallContracts,
  callBoundaryContracts,
  name,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "authority";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.authority_inputs.parametric_summary_proposals"
    ];
    name = "${name}-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
in
pkgs.runCommand name (
  {
    nativeBuildInputs = [ pythonEnv ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  // caAttrs
) ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export SPAGHETTI_REQUIRE_NATIVE=1
  export PYTHONPATH=${phasePythonSource}/src

  ${pythonEnv}/bin/python3 -m \
    spaghetti_extractor.authority_inputs.parametric_summary_proposals \
    --unit-facts ${unitFacts} \
    --memory-versions ${memoryVersions} \
    --structural-targets ${structuralTargets} \
    --external-profiles ${externalProfiles} \
    --static-value-origins ${staticValueOrigins} \
    --catalog-call-contracts ${catalogCallContracts} \
    --call-boundary-contracts ${callBoundaryContracts} \
    --out "$out/artifact"

  ${pythonEnv}/bin/python3 - "$out/artifact" "$out/metadata.json" <<'PY'
  from pathlib import Path
  import sys

  from spaghetti_extractor.artifacts.artifact_set import canonical_json_bytes_v3
  from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3

  reader = ArtifactSetReaderV3(Path(sys.argv[1]))
  Path(sys.argv[2]).write_bytes(canonical_json_bytes_v3({
      "format": "spaghetti-extractor-parametric-summary-proposal-metadata-v3",
      "artifact_kind": reader.manifest.artifact_kind,
      "artifact_id": reader.manifest.artifact_id,
      "status": reader.manifest.status,
      "record_ids": [row.record_id for row in reader.iter_records()],
  }))
  PY
''
