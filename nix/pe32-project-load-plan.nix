# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, intent, moduleInterfaces, nativeIngressPlans ? { }
, edgeAuthorities ? { }, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-load-plan-python-closure";
  };
  interfaceArgs = lib.concatMapStringsSep " "
    (imageId: "${lib.escapeShellArg imageId} ${moduleInterfaces.${imageId}}/module-interface.json")
    (builtins.attrNames moduleInterfaces);
  ingressArgs = lib.concatMapStringsSep " "
    (imageId: "${lib.escapeShellArg imageId} ${nativeIngressPlans.${imageId}}/native-ingress-plan.json")
    (builtins.attrNames nativeIngressPlans);
in
pkgs.runCommand "${namePrefix}-load-plan-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${intent} "$out" \
    ${toString (builtins.length (builtins.attrNames moduleInterfaces))} \
    ${interfaceArgs} ${toString (builtins.length (builtins.attrNames nativeIngressPlans))} \
    ${ingressArgs} <<'PY'
  import json
  import pathlib
  import sys
  from spaghetti_extractor.candidate.project import write_pe32_project_load_plan

  interface_count = int(sys.argv[3])
  arguments = sys.argv[4:]
  interface_arguments = arguments[:interface_count * 2]
  ingress_count = int(arguments[interface_count * 2])
  ingress_arguments = arguments[interface_count * 2 + 1:]
  if len(ingress_arguments) != ingress_count * 2:
      raise SystemExit("native ingress plan arguments are not pairs")
  interfaces = {
      interface_arguments[index]: pathlib.Path(interface_arguments[index + 1])
      for index in range(0, len(interface_arguments), 2)
  }
  ingress = {
      ingress_arguments[index]: pathlib.Path(ingress_arguments[index + 1])
      for index in range(0, len(ingress_arguments), 2)
  }
  write_pe32_project_load_plan(
      intent=pathlib.Path(sys.argv[1]),
      module_interfaces=interfaces,
      native_ingress_plans=ingress or None,
      edge_authorities=json.loads(
          ${builtins.toJSON (builtins.toJSON edgeAuthorities)}
      ) or None,
      out=pathlib.Path(sys.argv[2]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-project-load-plan-v1" and
    .status == "complete" and .counts.blockers == 0 and
    .policy.duplicate_logical_import_slots == "preserved"
  ' "$out/project-load-plan.json" >/dev/null
''
