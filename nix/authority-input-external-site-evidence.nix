{
  pkgs,
  pythonEnv,
  pythonSource,
  semanticIndex,
  transitionSummaries,
  targetCertificates,
  externalProfiles,
  name,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.authority_inputs.external_site_evidence" ];
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
  export PYTHONPATH=${phasePythonSource}/src

  mkdir -p "$out"
  ${pythonEnv}/bin/python3 -m spaghetti_extractor.authority_inputs.external_site_evidence \
    --semantic-index ${semanticIndex} \
    --transition-summaries ${transitionSummaries} \
    --target-certificates ${targetCertificates} \
    --external-profiles ${externalProfiles} \
    --out "$out/artifact"

  ${pythonEnv}/bin/python3 - "$out" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.artifact_set_v3 import (
      ArtifactSetReaderV3,
      canonical_json_bytes_v3,
  )

  output = pathlib.Path(sys.argv[1])
  reader = ArtifactSetReaderV3(output / "artifact")
  (output / "metadata.json").write_bytes(canonical_json_bytes_v3({
      "format": "spaghetti-extractor-external-site-evidence-metadata-v3",
      "artifact_kind": reader.manifest.artifact_kind,
      "record_ids": sorted(record.record_id for record in reader.iter_records()),
      "status": reader.manifest.status,
  }))
  PY
''
