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
  selectedRecordIds ? null,
  workManifest ? null,
  maxPackBytes ? null,
  memoryLimitMiB ? null,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";
assert builtins.match "^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$" phaseReference != null;
assert builtins.isString expectedKind && expectedKind != "";
assert builtins.isAttrs inputs && inputs != { };
assert builtins.isList bindings;
assert builtins.all
  (binding: !(builtins.elem (binding.name or null) [ "phase-runner" "phase-source" ]))
  bindings;
assert builtins.elem status [
  "complete"
  "incomplete"
  "violated"
];
assert selectedSccIds == null || builtins.isList selectedSccIds;
assert selectedRecordIds == null || builtins.isList selectedRecordIds;
assert selectedSccIds == null || selectedRecordIds == null;
assert
  maxPackBytes == null
  || (builtins.isInt maxPackBytes && maxPackBytes >= 256 && maxPackBytes <= 8388608);
assert memoryLimitMiB == null || (builtins.isInt memoryLimitMiB && memoryLimitMiB >= 256);

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  inputsJson = builtins.toJSON (lib.mapAttrs (_: value: toString value) inputs);
  provenanceBindings = [
    {
      name = "phase-runner";
      kind = "nix-checker";
      identity = "artifact-phase-v3.nix";
      sha256 = builtins.hashFile "sha256" ./artifact-phase-v3.nix;
    }
    {
      name = "phase-source";
      kind = "nix-python-closure";
      identity = phaseReference;
      sha256 = builtins.hashString "sha256" (
        builtins.unsafeDiscardStringContext (toString pythonSource)
      );
    }
  ];
  bindingsJson = builtins.toJSON (bindings ++ provenanceBindings);
  selectedSccIdsFile = builtins.toFile "${name}-selected-scc-ids.json" (builtins.toJSON selectedSccIds);
  selectedRecordIdsFile = builtins.toFile "${name}-selected-record-ids.json" (builtins.toJSON selectedRecordIds);
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  derivation =
    pkgs.runCommand name
      (
        {
          nativeBuildInputs = [ pythonEnv ];
          preferLocalBuild = false;
          allowSubstitutes = true;
          SPAGHETTI_PHASE_MEMORY_LIMIT_MIB =
            if memoryLimitMiB == null then "unlimited" else toString memoryLimitMiB;
        }
        // caAttrs
      )
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export PYTHONDONTWRITEBYTECODE=1
        export LC_ALL=C.UTF-8
        export SOURCE_DATE_EPOCH=1
        export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
        export PYTHONPATH=${pythonSource}/src
        ${if memoryLimitMiB == null then "" else "ulimit -v ${toString (memoryLimitMiB * 1024)}"}
        mkdir -p "$out"

        ${python} - \
          ${lib.escapeShellArg phaseReference} \
          ${lib.escapeShellArg inputsJson} \
          ${lib.escapeShellArg bindingsJson} \
          ${lib.escapeShellArg status} \
          ${if schedule == null then "-" else lib.escapeShellArg (toString schedule)} \
          ${selectedSccIdsFile} \
          ${selectedRecordIdsFile} \
          ${if workManifest == null then "-" else lib.escapeShellArg (toString workManifest)} \
          ${if maxPackBytes == null then "-" else toString maxPackBytes} \
          ${lib.escapeShellArg expectedKind} \
          producer \
          "$out/artifact" \
          "$out/phase-result.json" <<'PY'
        from __future__ import annotations

        import hashlib
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
            selected_scc_ids_file,
            selected_record_ids_file,
            work_manifest,
            max_pack_bytes,
            expected_kind,
            validation_mode,
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
            pathlib.Path(selected_scc_ids_file).read_bytes(), location=selected_scc_ids_file
        )
        selected_record_ids = parse_canonical_json_v3(
            pathlib.Path(selected_record_ids_file).read_bytes(), location=selected_record_ids_file
        )
        input_paths = {name: pathlib.Path(path) for name, path in inputs.items()}
        work_manifest_sha256 = None
        if work_manifest != "-":
            work_manifest_bytes = pathlib.Path(work_manifest).read_bytes()
            if not work_manifest_bytes:
                raise SystemExit("phase work manifest is empty")
            work_manifest_sha256 = hashlib.sha256(work_manifest_bytes).hexdigest()
        result = run_phase_reference_v3(
            reference,
            output_directory=pathlib.Path(output),
            inputs=input_paths,
            bindings=bindings,
            status=status,
            schedule=None if schedule == "-" else pathlib.Path(schedule),
            selected_scc_ids=selected_scc_ids,
            selected_record_ids=selected_record_ids,
            max_pack_bytes=None if max_pack_bytes == "-" else int(max_pack_bytes),
            validation_mode=validation_mode,
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
            "selected_record_ids": selected_record_ids,
            "selected_scc_ids": selected_scc_ids,
            "work_manifest_sha256": work_manifest_sha256,
            "validation_mode": validation_mode,
        }))
        PY
      '';
in
{
  inherit derivation memoryLimitMiB;
  artifact = "${derivation}/artifact";
  manifest = "${derivation}/artifact/manifest.json";
  result = "${derivation}/phase-result.json";
}
