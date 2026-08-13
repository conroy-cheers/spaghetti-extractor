{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  graphId,
  outputs ? [ "final-authority-v3" ],
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  graphPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.analysis_v3.graph" ];
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
  export PYTHONPATH=${graphPythonSource}/src

  ${pythonEnv}/bin/python3 - \
    ${lib.escapeShellArg graphId} \
    ${lib.escapeShellArg (builtins.toJSON outputs)} \
    "$out" <<'PY'
  from __future__ import annotations

  import pathlib
  import sys

  from spaghetti_extractor.analysis_v3.graph import authority_graph_manifest_v3
  from spaghetti_extractor.artifact_set_v3 import (
      canonical_json_bytes_v3,
      parse_canonical_json_v3,
  )


  graph_id, outputs_json, output = sys.argv[1:]
  outputs = parse_canonical_json_v3(outputs_json.encode("ascii"), location="graph outputs")
  if not isinstance(outputs, list) or not all(isinstance(row, str) for row in outputs):
      raise SystemExit("analysis-v3 graph outputs must be an array of phase IDs")
  manifest = authority_graph_manifest_v3(graph_id=graph_id, outputs=outputs)
  destination = pathlib.Path(output)
  destination.mkdir(parents=True)
  (destination / "graph.json").write_bytes(canonical_json_bytes_v3(manifest))
  PY
''
