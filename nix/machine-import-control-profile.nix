{
  pkgs,
  pythonEnv,
  pythonSource,
  profiles,
  name ? "spaghetti-extractor-machine-import-control-dispositions-v1",
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  profilePathsJson = builtins.toJSON (map toString profiles);
  closure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.control_disposition_profile" ];
    name = "${name}-python-closure";
  };
in
assert builtins.isList profiles && profiles != [ ];
pkgs.runCommand name {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${closure}/src
  mkdir -p "$out"
  ${python} - \
    ${lib.escapeShellArg profilePathsJson} \
    "$out/control-dispositions.json" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.control_disposition_profile import (
      build_control_disposition_profile,
  )
  from spaghetti_extractor.util import write_json

  paths = tuple(pathlib.Path(path) for path in json.loads(sys.argv[1]))
  write_json(
      pathlib.Path(sys.argv[2]),
      build_control_disposition_profile(paths),
  )
  PY
  jq -e '
    .format == "stage-a-static-machine-import-profile-v1" and
    .id == "pe32-control-dispositions-v1" and
    .default_callback_effect == "none" and
    ([.machine_import_signatures[] |
      .disposition == "terminates" and
      (.abi_template == "pe32-cdecl-v1" or
       .abi_template == "pe32-stdcall-v1") and
      (.argument_words | type) == "number"] | all)
  ' "$out/control-dispositions.json" >/dev/null
''
