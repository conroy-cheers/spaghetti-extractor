# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  profile,
  binary,
  binaryIdentity,
  name,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "authority";
    inherit pkgs;
    modules = [ "spaghetti_extractor.authority.normal_call_abi" ];
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

  ${pythonEnv}/bin/python3 -m spaghetti_extractor.authority.normal_call_abi \
    --profile ${profile} \
    --binary ${binary} \
    --binary-identity ${lib.escapeShellArg binaryIdentity} \
    --out "$out/artifact"

  ${pythonEnv}/bin/python3 - "$out/artifact" "$out/metadata.json" <<'PY'
  from pathlib import Path
  import sys

  from spaghetti_extractor.artifacts.artifact_set import canonical_json_bytes_v3
  from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3

  reader = ArtifactSetReaderV3(Path(sys.argv[1]))
  Path(sys.argv[2]).write_bytes(canonical_json_bytes_v3({
      "format": "spaghetti-extractor-normal-call-abi-premise-metadata-v3",
      "artifact_kind": reader.manifest.artifact_kind,
      "artifact_id": reader.manifest.artifact_id,
      "status": reader.manifest.status,
      "record_ids": [row.record_id for row in reader.iter_records()],
  }))
  PY
''
