{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  artifact,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.analysis_v3.final_authority" ];
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
  export PYTHONPATH=${pythonClosure}/src

  ${pythonEnv}/bin/python3 - \
    ${lib.escapeShellArg (toString artifact)} \
    "$out" <<'PY'
  from __future__ import annotations

  import pathlib
  import sys

  from spaghetti_extractor.analysis_v3.final_authority import (
      FINAL_AUTHORITY_ARTIFACT_KIND_V3,
      FINAL_AUTHORITY_CODEC_V3,
  )
  from spaghetti_extractor.artifact_set_v3 import (
      ArtifactSetReaderV3,
      canonical_json_bytes_v3,
  )

  artifact, output = sys.argv[1:]
  reader = ArtifactSetReaderV3(pathlib.Path(artifact))
  if reader.manifest.artifact_kind != FINAL_AUTHORITY_ARTIFACT_KIND_V3:
      raise SystemExit(
          "final authority artifact kind mismatch: "
          f"expected {FINAL_AUTHORITY_ARTIFACT_KIND_V3!r}, "
          f"observed {reader.manifest.artifact_kind!r}"
      )
  records = tuple(reader.iter_records())
  if len(records) != 1:
      raise SystemExit(
          "final authority gate requires exactly one record; "
          f"observed {len(records)}"
      )
  authority = FINAL_AUTHORITY_CODEC_V3.read(records[0]).value
  if reader.manifest.status != "complete":
      raise SystemExit(
          "final authority artifact is not complete: "
          f"{reader.manifest.status}"
      )
  if authority.status != "complete" or not authority.authorizing:
      blocker = (
          None
          if authority.primary_blocker is None
          else authority.primary_blocker.to_payload()
      )
      raise SystemExit(
          "final authority record is not authorizing: "
          f"status={authority.status}, authorizing={authority.authorizing}, "
          f"primary_blocker={blocker}"
      )
  if authority.primary_blocker is not None:
      raise SystemExit(
          "complete final authority unexpectedly retains a primary blocker"
      )

  destination = pathlib.Path(output)
  destination.mkdir(parents=True)
  result = {
      "format": "spaghetti-extractor-final-authority-gate-v3",
      "artifact_id": reader.manifest.artifact_id,
      "manifest_sha256": reader.manifest_sha256,
      "record_id": authority.record_id,
      "status": authority.status,
      "authorizing": authority.authorizing,
      "pe_sha256": authority.pe_sha256,
      "exact_universe_sha256": authority.exact_universe_sha256,
      "exact_unit_count": authority.exact_unit_count,
  }
  (destination / "authority-gate.json").write_bytes(
      canonical_json_bytes_v3(result)
  )
  PY
''
