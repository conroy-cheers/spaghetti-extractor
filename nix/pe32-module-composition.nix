# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, baseCandidate, baseCompositionManifest
, originalModuleInterface, nativeIngressPlan, nativeIngressLinkReceipt
, candidateFilename, namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.module_composer" ];
    name = "${namePrefix}-module-composition-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-pe32-module-composition" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${baseCandidate} ${baseCompositionManifest} \
    ${originalModuleInterface}/module-interface.json \
    ${nativeIngressPlan}/native-ingress-plan.json \
    ${nativeIngressLinkReceipt}/native-ingress-link-receipt.json "$out" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.module_composer import (
      compose_pe32_native_module,
  )

  compose_pe32_native_module(
      base_candidate=pathlib.Path(sys.argv[1]),
      base_composition_manifest=pathlib.Path(sys.argv[2]),
      original_module_interface=pathlib.Path(sys.argv[3]),
      native_ingress_plan=pathlib.Path(sys.argv[4]),
      native_ingress_link_receipt=pathlib.Path(sys.argv[5]),
      out=pathlib.Path(sys.argv[6]),
      candidate_filename=${builtins.toJSON candidateFilename},
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe-composition-manifest-v1" and
    .status == "composed" and
    .policy.entrypoint == "direct_linked_ingress_bridge" and
    (.policy | has("executable_anchors") | not)
  ' "$out/pe-composition-manifest.json" >/dev/null
  test -f "$out/${candidateFilename}"
''
