{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  artifacts,
  graphManifest ? null,
  contentAddressed ? true,
}:

assert builtins.isAttrs artifacts && artifacts != { };

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.authority.diagnostics" ];
    name = "${name}-python-closure";
  };
  artifactPaths = lib.mapAttrs (_: value: toString value) artifacts;
  artifactsFile = pkgs.writeText "${name}-artifacts.json" (
    builtins.toJSON artifactPaths
  );
  graphManifestFile =
    if graphManifest == null then null
    else pkgs.writeText "${name}-graph-manifest.json" (builtins.toJSON graphManifest);
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

  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${artifactsFile} \
    ${if graphManifestFile == null then "-" else graphManifestFile} \
    "$out/authority-diagnostics-v3.json" <<'PY'
  from __future__ import annotations

  import json
  import pathlib
  import sys

  from spaghetti_extractor.authority.diagnostics import (
      summarize_authority_artifacts_v3,
  )
  from spaghetti_extractor.artifact_set_v3 import canonical_json_bytes_v3

  artifacts_file = pathlib.Path(sys.argv[1])
  graph_manifest_path = sys.argv[2]
  output = pathlib.Path(sys.argv[3])
  artifacts = {
      name: pathlib.Path(path)
      for name, path in json.loads(
          artifacts_file.read_text(encoding="utf-8")
      ).items()
  }
  graph_manifest = (
      None
      if graph_manifest_path == "-"
      else json.loads(pathlib.Path(graph_manifest_path).read_text(encoding="utf-8"))
  )
  report = summarize_authority_artifacts_v3(
      artifacts,
      graph_manifest=graph_manifest,
  )
  output.write_bytes(canonical_json_bytes_v3(report))
  PY
''
