# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, originalModuleInterface, behavioralCCompletion
, nativeIngressPlan, nativeIngressLinkReceipt, exactRuntimeQualification
, loaderSurfaceReceipt, candidateStaticAssurance, candidateModule
, candidateModuleInterface, namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.native_ingress" ];
    name = "${namePrefix}-module-deployment-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-pe32-module-deployment-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - \
    ${originalModuleInterface}/module-interface.json \
    ${behavioralCCompletion} ${nativeIngressPlan}/native-ingress-plan.json \
    ${nativeIngressLinkReceipt}/native-ingress-link-receipt.json \
    ${exactRuntimeQualification} ${loaderSurfaceReceipt}/loader-surface-receipt.json \
    ${candidateStaticAssurance} ${candidateModule} \
    ${candidateModuleInterface}/module-interface.json "$out" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.native_ingress import write_pe32_module_deployment

  write_pe32_module_deployment(
      original_module_interface=pathlib.Path(sys.argv[1]),
      behavioral_c_completion=pathlib.Path(sys.argv[2]),
      native_ingress_plan=pathlib.Path(sys.argv[3]),
      native_ingress_link_receipt=pathlib.Path(sys.argv[4]),
      exact_runtime_qualification=pathlib.Path(sys.argv[5]),
      loader_surface_receipt=pathlib.Path(sys.argv[6]),
      candidate_static_assurance=pathlib.Path(sys.argv[7]),
      candidate_module=pathlib.Path(sys.argv[8]),
      candidate_module_interface=pathlib.Path(sys.argv[9]),
      out=pathlib.Path(sys.argv[10]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-module-deployment-v1" and
    .status == "complete" and (.deployment_sha256 | length == 64)
  ' "$out/module-deployment.json" >/dev/null
''
