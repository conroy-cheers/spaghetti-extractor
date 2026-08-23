# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, moduleInterface, refinements ? [ ], namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.native_ingress" ];
    name = "${namePrefix}-object-authority-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-machine-object-authority-v2" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${moduleInterface}/module-interface.json "$out" <<'PY'
  import json
  import pathlib
  import sys
  from spaghetti_extractor.candidate.native_ingress import (
      write_pe32_machine_object_authority_v2,
  )

  write_pe32_machine_object_authority_v2(
      module_interface=pathlib.Path(sys.argv[1]),
      refinements=json.loads(${builtins.toJSON (builtins.toJSON refinements)}),
      out=pathlib.Path(sys.argv[2]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-machine-object-authority-v2" and
    (.rules | length > 0) and (.authority_sha256 | length == 64)
  ' "$out/machine-object-authority.json" >/dev/null
''
