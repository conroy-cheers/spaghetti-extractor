# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, originalModuleInterface, nativeIngressPlan
, nativeIngressLinkReceipt, compositionManifest, candidateModule
, candidateModuleInterface, namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.native_ingress" ];
    name = "${namePrefix}-loader-surface-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-pe32-loader-surface-receipt-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - \
    ${originalModuleInterface}/module-interface.json \
    ${nativeIngressPlan}/native-ingress-plan.json \
    ${nativeIngressLinkReceipt}/native-ingress-link-receipt.json \
    ${compositionManifest} ${candidateModule} \
    ${candidateModuleInterface}/module-interface.json "$out" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.native_ingress import (
      write_pe32_loader_surface_receipt,
  )

  write_pe32_loader_surface_receipt(
      original_module_interface=pathlib.Path(sys.argv[1]),
      native_ingress_plan=pathlib.Path(sys.argv[2]),
      native_ingress_link_receipt=pathlib.Path(sys.argv[3]),
      composition_manifest=pathlib.Path(sys.argv[4]),
      candidate_module=pathlib.Path(sys.argv[5]),
      candidate_module_interface=pathlib.Path(sys.argv[6]),
      out=pathlib.Path(sys.argv[7]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-loader-surface-receipt-v1" and
    .status == "complete" and .counts.blockers == 0
  ' "$out/loader-surface-receipt.json" >/dev/null
''
