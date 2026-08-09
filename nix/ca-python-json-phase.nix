{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  kind,
  artifactName,
  expectedFormat,
  allowedStatuses,
  pythonModules,
  pythonExtraPaths ? [ ],
  extraNativeBuildInputs ? [ ],
  inputs ? { },
  program,
  contentAddressed ? true,
}:

assert builtins.isAttrs inputs;
assert builtins.isList pythonModules && pythonModules != [ ];
assert builtins.isList pythonExtraPaths;
assert builtins.isList extraNativeBuildInputs;
assert builtins.isList allowedStatuses && allowedStatuses != [ ];
assert builtins.match "^[a-z0-9][a-z0-9._-]*$" kind != null;
assert builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*\\.json$" artifactName != null;
assert builtins.isString expectedFormat && expectedFormat != "";
assert builtins.all (status: builtins.isString status && status != "") allowedStatuses;

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = pythonModules;
    extraPaths = pythonExtraPaths;
    name = "${name}-python-closure";
  };
  declaredInputsJson = builtins.toJSON {
    format = "spaghetti-extractor-ca-phase-inputs-v1";
    phase = kind;
    inputs = lib.mapAttrs (_: value: toString value) inputs;
  };
  allowedStatusesJson = builtins.toJSON allowedStatuses;
  caAttrs = lib.optionalAttrs contentAddressed {
    __contentAddressed = true;
  };
  derivation =
    pkgs.runCommand name
      (
        {
          nativeBuildInputs = [
            pythonEnv
            pkgs.jq
          ] ++ extraNativeBuildInputs;
          preferLocalBuild = false;
          allowSubstitutes = true;
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
        export PYTHONPATH=${phasePythonSource}/src
        mkdir -p "$out"

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
          "$out/phase-manifest.json" \
          ${lib.escapeShellArg kind} \
          ${lib.escapeShellArg expectedFormat} \
          ${lib.escapeShellArg allowedStatusesJson} \
          ${lib.escapeShellArg artifactName} \
          ${if contentAddressed then "true" else "false"} <<'PY'
        from __future__ import annotations

        import hashlib
        import json
        import pathlib
        import sys

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
        if artifact.get("status") not in allowed_statuses:
            raise SystemExit(
                "phase artifact status is outside the declared fail-closed set: "
                f"{artifact.get('status')!r}"
            )
        input_rows = [
            {"name": name, "store_path": path}
            for name, path in sorted(declared["inputs"].items())
        ]
        if any(not row["store_path"].startswith("/nix/store/") for row in input_rows):
            raise SystemExit("every CA phase input must be a Nix store path")
        manifest = {
            "format": "spaghetti-extractor-ca-phase-manifest-v1",
            "phase": phase_kind,
            "content_addressed": content_addressed_text == "true",
            "inputs": input_rows,
            "python_module_closure": {
                "store_path": "${phasePythonSource}",
                "manifest": "${phasePythonSource}/python-module-closure.json",
            },
            "artifact": {
                "name": artifact_name,
                "format": expected_format,
                "status": artifact["status"],
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            },
        }
        pathlib.Path(manifest_path).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY

        jq -e \
          --arg phase ${lib.escapeShellArg kind} \
          --arg artifact ${lib.escapeShellArg artifactName} '
          .format == "spaghetti-extractor-ca-phase-manifest-v1" and
          .phase == $phase and .content_addressed == ${if contentAddressed then "true" else "false"} and
          .artifact.name == $artifact and
          (.artifact.sha256 | test("^[0-9a-f]{64}$")) and
          ([.inputs[].name] == ([.inputs[].name] | sort | unique))
        ' "$out/phase-manifest.json" >/dev/null
      '';
in
{
  inherit derivation phasePythonSource;
  artifact = "${derivation}/${artifactName}";
  manifest = "${derivation}/phase-manifest.json";
  inherit kind artifactName expectedFormat;
}
