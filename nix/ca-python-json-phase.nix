# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  name,
  kind,
  artifactName,
  expectedFormat,
  allowedStatuses,
  pythonModules,
  phaseRole,
  pythonSource ? null,
  pythonExtraPaths ? [ ],
  extraNativeBuildInputs ? [ ],
  inputs ? { },
  program,
  contentAddressed ? true,
  dontFixup ? false,
}:

assert builtins.isAttrs inputs;
assert builtins.isList pythonModules && pythonModules != [ ];
assert builtins.isString phaseRole && phaseRole != "";
assert builtins.isList pythonExtraPaths;
assert builtins.isList extraNativeBuildInputs;
assert builtins.isList allowedStatuses;
assert builtins.match "^[a-z0-9][a-z0-9._-]*$" kind != null;
assert builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*\\.json$" artifactName != null;
assert builtins.isString expectedFormat && expectedFormat != "";
assert builtins.all (status: builtins.isString status && status != "") allowedStatuses;

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  normalizedInputs = lib.mapAttrs (inputName: value:
    if builtins.isPath value then
      builtins.path {
        path = value;
        name = "spaghetti-ca-input-${lib.replaceStrings [ ":" "_" ] [ "-" "-" ] inputName}";
      }
    else value
  ) inputs;
  phasePythonSource =
    if pythonSource != null then pythonSource else
    import ./python-module-closure.nix {
      phaseRole = phaseRole;
      inherit pkgs;
      modules = lib.unique (
        pythonModules ++ [
          "spaghetti_extractor.artifacts.build_manifest"
          "spaghetti_extractor.util"
        ]
      );
      extraPaths = pythonExtraPaths;
      name = "${name}-python-closure";
    };
  declaredInputsJson = builtins.toJSON {
    format = "spaghetti-extractor-ca-phase-inputs-v1";
    phase = kind;
    inputs = lib.mapAttrs (_: value: toString value) normalizedInputs;
  };
  allowedStatusesJson = builtins.toJSON allowedStatuses;
  caAttrs = lib.optionalAttrs contentAddressed {
    __contentAddressed = true;
  };
  derivation =
    pkgs.runCommand name
      (
        {
          # Provenance is independently content-addressed.  Keeping it out of
          # `out` lets an implementation-only edit converge on the same
          # semantic/package output when the emitted bytes are unchanged.
          outputs = [ "out" "manifest" ];
          nativeBuildInputs = [
            pythonEnv
            pkgs.jq
          ] ++ extraNativeBuildInputs;
          preferLocalBuild = false;
          allowSubstitutes = true;
          inherit dontFixup;
          SPAGHETTI_CA_DECLARED_INPUT_REFERENCES =
            lib.concatStringsSep "\n"
              (map toString (builtins.attrValues normalizedInputs));
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
        export PYTHONPATH=${phasePythonSource.pythonPath}
        mkdir -p "$out" "$manifest"

        ${python} - \
          ${lib.escapeShellArg declaredInputsJson} \
          "$out/${artifactName}" <<'PY'
        from __future__ import annotations

        import json
        import pathlib
        import sys

        declared_inputs_json = sys.argv[1]
        output = pathlib.Path(sys.argv[2])
        declaration = json.loads(declared_inputs_json)
        inputs = {
            name: pathlib.Path(path)
            for name, path in declaration["inputs"].items()
        }
        output.parent.mkdir(parents=True, exist_ok=True)

        ${program}

        if not output.is_file():
            raise SystemExit("phase producer did not create its declared artifact")
        PY

        ${python} - \
          ${lib.escapeShellArg declaredInputsJson} \
          "$out/${artifactName}" \
          "$manifest/phase-manifest.json" \
          ${lib.escapeShellArg kind} \
          ${lib.escapeShellArg expectedFormat} \
          ${lib.escapeShellArg allowedStatusesJson} \
          ${lib.escapeShellArg artifactName} \
          ${if contentAddressed then "true" else "false"} <<'PY'
        from __future__ import annotations

        import json
        import pathlib
        import sys

        from spaghetti_extractor.artifacts.build_manifest import phase_manifest
        from spaghetti_extractor.util import write_json

        (
            declared_inputs_json,
            artifact_path,
            manifest_path,
            phase_kind,
            expected_format,
            allowed_statuses_json,
            artifact_name,
            content_addressed_text,
        ) = sys.argv[1:]
        declared = json.loads(declared_inputs_json)
        artifact_bytes = pathlib.Path(artifact_path).read_bytes()
        try:
            artifact = json.loads(artifact_bytes)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"phase artifact is not JSON: {exc}") from exc
        if not isinstance(artifact, dict):
            raise SystemExit("phase artifact must be a JSON object")
        if artifact.get("format") != expected_format:
            raise SystemExit(
                "phase artifact format mismatch: "
                f"expected {expected_format!r}, observed {artifact.get('format')!r}"
            )
        allowed_statuses = json.loads(allowed_statuses_json)
        if allowed_statuses and artifact.get("status") not in allowed_statuses:
            raise SystemExit(
                "phase artifact status is outside the declared fail-closed set: "
                f"{artifact.get('status')!r}"
            )
        closure_manifest_path = pathlib.Path(
            "${phasePythonSource.manifest}"
        )
        manifest = phase_manifest(
            phase=phase_kind,
            content_addressed=content_addressed_text == "true",
            artifact_name=artifact_name,
            artifact=artifact,
            artifact_bytes=artifact_bytes,
            inputs={
                name: pathlib.Path(path)
                for name, path in declared["inputs"].items()
            },
            python_closure_manifest=closure_manifest_path,
        )
        write_json(pathlib.Path(manifest_path), manifest)
        PY

        jq -e \
          --arg phase ${lib.escapeShellArg kind} \
          --arg artifact ${lib.escapeShellArg artifactName} '
          .format == "spaghetti-extractor-ca-phase-manifest-v1" and
          .phase == $phase and .content_addressed == ${if contentAddressed then "true" else "false"} and
          .artifact.name == $artifact and
          (.artifact.sha256 | test("^[0-9a-f]{64}$")) and
          ([.inputs[].name] == ([.inputs[].name] | sort | unique)) and
          ([.inputs[].sha256] | all(test("^[0-9a-f]{64}$"))) and
          ([.inputs[] | has("store_path")] | any | not) and
          (.python_module_closure.manifest_sha256 | test("^[0-9a-f]{64}$"))
        ' "$manifest/phase-manifest.json" >/dev/null
      '';
in
{
  inherit derivation phasePythonSource;
  artifact = "${derivation}/${artifactName}";
  manifest = "${derivation.manifest}/phase-manifest.json";
  inherit kind artifactName expectedFormat;
}
