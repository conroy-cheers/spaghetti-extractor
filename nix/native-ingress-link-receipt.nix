# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, nativeIngressPlan, linkedModule, linkerMap ? null, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.native_ingress" ];
    name = "${namePrefix}-native-ingress-link-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-native-ingress-link-receipt-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - \
    ${nativeIngressPlan}/native-ingress-plan.json ${linkedModule} \
    ${lib.escapeShellArg (if linkerMap == null then "" else toString linkerMap)} \
    "$out" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.native_ingress import (
      write_native_ingress_link_receipt,
  )

  write_native_ingress_link_receipt(
      native_ingress_plan=pathlib.Path(sys.argv[1]),
      linked_module=pathlib.Path(sys.argv[2]),
      linker_map=None if not sys.argv[3] else pathlib.Path(sys.argv[3]),
      out=pathlib.Path(sys.argv[4]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-native-ingress-link-receipt-v1" and
    .status == "complete" and (.symbols | length > 0)
  ' "$out/native-ingress-link-receipt.json" >/dev/null
''
