{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  machineIr,
  binary,
  shardBucketCount ? 4,
  resourceClasses ? import ./authority-resource-classes-v3.nix,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
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
  export PYTHONPATH=${pythonSource}/src

  ${pythonEnv}/bin/python3 - \
      ${machineIr} \
      ${binary} \
      ${toString shardBucketCount} \
      ${lib.escapeShellArg (builtins.toJSON resourceClasses)} \
      "$out" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.authority.source_plan import (
      prepare_analysis_source_v3,
  )

  prepare_analysis_source_v3(
      machine_ir=pathlib.Path(sys.argv[1]),
      binary=pathlib.Path(sys.argv[2]),
      shard_bucket_count=int(sys.argv[3]),
      resource_classes=json.loads(sys.argv[4]),
      output_directory=pathlib.Path(sys.argv[5]),
  )
  PY
''
