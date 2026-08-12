{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  phaseReference,
  expectedKind,
  inputs,
  bindings,
  status ? "complete",
  schedule ? null,
  selectedSccIds ? null,
  maxPackBytes ? null,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";
assert builtins.match "^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$" phaseReference != null;
assert builtins.isString expectedKind && expectedKind != "";
assert builtins.isAttrs inputs && inputs != { };
assert builtins.isList bindings;
assert builtins.elem status [ "complete" "incomplete" "violated" ];
assert selectedSccIds == null || builtins.isList selectedSccIds;
assert maxPackBytes == null || (builtins.isInt maxPackBytes && maxPackBytes >= 256 && maxPackBytes <= 8388608);

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  inputsJson = builtins.toJSON (lib.mapAttrs (_: value: toString value) inputs);
  bindingsJson = builtins.toJSON bindings;
  selectedSccIdsJson = builtins.toJSON selectedSccIds;
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
    mkdir -p "$out"

    ${python} - \
      ${lib.escapeShellArg phaseReference} \
      ${lib.escapeShellArg inputsJson} \
      ${lib.escapeShellArg bindingsJson} \
      ${lib.escapeShellArg status} \
      ${if schedule == null then "-" else lib.escapeShellArg (toString schedule)} \
      ${lib.escapeShellArg selectedSccIdsJson} \
      ${if maxPackBytes == null then "-" else toString maxPackBytes} \
      ${lib.escapeShellArg expectedKind} \
      "$out/artifact" \
      "$out/phase-result.json" <<'PY'
    from __future__ import annotations

    import pathlib
    import sys

    from spaghetti_extractor.artifact_set_v3 import (
        canonical_json_bytes_v3,
        parse_canonical_json_v3,
    )
    from spaghetti_extractor.phase_framework_v3 import run_phase_reference_v3

    (
        reference,
        inputs_json,
        bindings_json,
        status,
        schedule,
        selected_scc_ids_json,
        max_pack_bytes,
        expected_kind,
        output,
        receipt,
    ) = sys.argv[1:]
    inputs = parse_canonical_json_v3(
        inputs_json.encode("ascii"), location="declared inputs"
    )
    bindings = parse_canonical_json_v3(
        bindings_json.encode("ascii"), location="declared bindings"
    )
    selected_scc_ids = parse_canonical_json_v3(
        selected_scc_ids_json.encode("ascii"), location="selected SCC IDs"
    )
    result = run_phase_reference_v3(
        reference,
        output_directory=pathlib.Path(output),
        inputs={name: pathlib.Path(path) for name, path in inputs.items()},
        bindings=bindings,
        status=status,
        schedule=None if schedule == "-" else pathlib.Path(schedule),
        selected_scc_ids=selected_scc_ids,
        max_pack_bytes=None if max_pack_bytes == "-" else int(max_pack_bytes),
    )
    if result.manifest.artifact_kind != expected_kind:
        raise SystemExit(
            "phase artifact kind mismatch: "
            f"expected {expected_kind!r}, observed {result.manifest.artifact_kind!r}"
        )
    pathlib.Path(receipt).write_bytes(canonical_json_bytes_v3({
        "format": "spaghetti-extractor-phase-result-v3",
        "phase_reference": reference,
        "artifact_kind": result.manifest.artifact_kind,
        "artifact_id": result.manifest.artifact_id,
        "manifest_sha256": result.manifest.manifest_sha256,
        "status": result.manifest.status,
        "record_count": result.manifest.record_count,
    }))
    PY
  '';
in
{
  inherit derivation;
  artifact = "${derivation}/artifact";
  manifest = "${derivation}/artifact/manifest.json";
  result = "${derivation}/phase-result.json";
}
