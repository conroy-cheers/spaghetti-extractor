# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  name,
  kind,
  artifact,
  artifactName,
  expectedFormat,
  allowedStatuses,
  pythonModules,
  phaseRole,
  inputs ? { },
  program ? "",
  pythonExtraPaths ? [ ],
  extraNativeBuildInputs ? [ ],
  contentAddressed ? true,
}:

assert builtins.isAttrs inputs;
assert builtins.isList pythonModules && pythonModules != [ ];
assert builtins.isString phaseRole && phaseRole != "";
assert builtins.isList allowedStatuses && allowedStatuses != [ ];
assert builtins.match "^[a-z0-9][a-z0-9._-]*$" kind != null;
assert builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*\\.json$" artifactName != null;

let
  lib = pkgs.lib;
  normalizedInputs = lib.mapAttrs (inputName: value:
    if builtins.isPath value then
      builtins.path {
        path = value;
        name = "spaghetti-ca-input-${lib.replaceStrings [ ":" "_" ] [ "-" "-" ] inputName}";
      }
    else value
  ) inputs;
  gatePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    phaseRole = phaseRole;
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
    inputs = lib.mapAttrs (_: value: toString value) normalizedInputs;
  };
  allowedStatusesJson = builtins.toJSON allowedStatuses;
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  derivation = pkgs.runCommand name (
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ] ++ extraNativeBuildInputs;
      preferLocalBuild = false;
      allowSubstitutes = true;
      SPAGHETTI_CA_DECLARED_INPUT_REFERENCES =
        lib.concatStringsSep "\n"
          (map toString (builtins.attrValues normalizedInputs));
    }
    // caAttrs
  ) ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export PYTHONPATH=${gatePythonSource.pythonPath}
    mkdir -p "$out"

    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg (toString artifact)} \
      ${lib.escapeShellArg artifactName} \
      ${lib.escapeShellArg expectedFormat} \
      ${lib.escapeShellArg allowedStatusesJson} \
      ${lib.escapeShellArg declaredInputsJson} \
      ${lib.escapeShellArg kind} \
      ${lib.escapeShellArg phaseRole} \
      ${gatePythonSource.manifest} \
      "$out" <<'PY'
    from __future__ import annotations

    import json
    import pathlib
    import shutil
    import sys

    from spaghetti_extractor.artifacts.build_manifest import (
        receipt_gate_manifest,
    )
    from spaghetti_extractor.util import write_json

    (
        artifact_text,
        artifact_name,
        expected_format,
        allowed_statuses_text,
        declared_inputs_text,
        gate_kind,
        phase_role,
        closure_manifest_text,
        output_text,
    ) = sys.argv[1:]
    artifact_path = pathlib.Path(artifact_text)
    output = pathlib.Path(output_text)
    artifact_bytes = artifact_path.read_bytes()
    artifact = json.loads(artifact_bytes)
    if not isinstance(artifact, dict):
        raise SystemExit("gate artifact must be a JSON object")
    if artifact.get("format") != expected_format:
        raise SystemExit("gate artifact format is unsupported")
    if artifact.get("status") not in json.loads(allowed_statuses_text):
        raise SystemExit("gate artifact status is outside the fail-closed set")
    declared = json.loads(declared_inputs_text)
    inputs = {
        key: pathlib.Path(value)
        for key, value in declared["inputs"].items()
    }

    def fail(message):
        raise SystemExit(message)

    ${program}

    shutil.copyfile(artifact_path, output / artifact_name)
    manifest = receipt_gate_manifest(
        gate=gate_kind,
        phase_role=phase_role,
        artifact_name=artifact_name,
        artifact=artifact,
        artifact_bytes=artifact_bytes,
        inputs=inputs,
        python_closure_manifest=pathlib.Path(closure_manifest_text),
    )
    write_json(output / "gate-manifest.json", manifest)
    PY

    jq -e \
      --arg gate ${lib.escapeShellArg kind} \
      --arg artifact ${lib.escapeShellArg artifactName} '
      .format == "spaghetti-extractor-ca-receipt-gate-v1" and
      .status == "complete" and .gate == $gate and
      .acceptance_authority == "none" and
      .artifact.name == $artifact and
      (.artifact.sha256 | test("^[0-9a-f]{64}$")) and
      ([.inputs[].name] == ([.inputs[].name] | sort | unique)) and
      ([.inputs[].sha256] | all(test("^[0-9a-f]{64}$")))
    ' "$out/gate-manifest.json" >/dev/null
  '';
in
{
  inherit derivation gatePythonSource;
  receipt = "${derivation}/${artifactName}";
  manifest = "${derivation}/gate-manifest.json";
}
