{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  artifact,
  expectedKind,
  allowedStatuses ? [ "complete" "incomplete" "violated" ],
  expectedRecordIds ? null,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";
assert builtins.isString expectedKind && expectedKind != "";
assert builtins.isList allowedStatuses && allowedStatuses != [ ];
assert expectedRecordIds == null || builtins.isList expectedRecordIds;

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  statusesFile = builtins.toFile "${name}-allowed-statuses.json" (builtins.toJSON allowedStatuses);
  expectedIdsFile = builtins.toFile "${name}-expected-record-ids.json" (builtins.toJSON expectedRecordIds);
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  derivation = pkgs.runCommand name (
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
    export PYTHONPATH=${pythonSource}/src

    ${python} - \
      ${lib.escapeShellArg (toString artifact)} \
      ${lib.escapeShellArg expectedKind} \
      ${statusesFile} \
      ${expectedIdsFile} \
      "$out" <<'PY'
    from __future__ import annotations

    import pathlib
    import sys

    from spaghetti_extractor.artifact_set_v3 import (
        ArtifactSetReaderV3,
        canonical_json_bytes_v3,
        parse_canonical_json_v3,
    )

    artifact, expected_kind, statuses_file, expected_ids_file, output = sys.argv[1:]
    statuses = parse_canonical_json_v3(
        pathlib.Path(statuses_file).read_bytes(), location=statuses_file
    )
    expected_ids = parse_canonical_json_v3(
        pathlib.Path(expected_ids_file).read_bytes(), location=expected_ids_file
    )
    reader = ArtifactSetReaderV3(pathlib.Path(artifact))
    if reader.manifest.artifact_kind != expected_kind:
        raise SystemExit(
            "artifact kind mismatch: "
            f"expected {expected_kind!r}, observed {reader.manifest.artifact_kind!r}"
        )
    if reader.manifest.status not in statuses:
        raise SystemExit(
            "artifact status is outside the declared fail-closed inventory: "
            f"{reader.manifest.status!r}"
        )
    if expected_ids is None:
        observed_count = sum(1 for _ in reader.iter_records())
    else:
        reader.validate_completeness(expected_ids)
        observed_count = len(expected_ids)
    result = {
        "format": "spaghetti-extractor-artifact-validation-v3",
        "artifact_kind": reader.manifest.artifact_kind,
        "artifact_id": reader.manifest.artifact_id,
        "manifest_sha256": reader.manifest_sha256,
        "status": reader.manifest.status,
        "record_count": observed_count,
    }
    destination = pathlib.Path(output)
    destination.mkdir(parents=True)
    (destination / "validation.json").write_bytes(canonical_json_bytes_v3(result))
    PY
  '';
in
{
  inherit derivation artifact;
  validation = "${derivation}/validation.json";
}
