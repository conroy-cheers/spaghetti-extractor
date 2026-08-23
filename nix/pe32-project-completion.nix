# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, loadPlan, moduleDeployments, observedLoadGraph ? null, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-completion-python-closure";
  };
  completionArgs = lib.concatMapStringsSep " "
    (imageId: "${lib.escapeShellArg imageId} ${moduleDeployments.${imageId}}/module-deployment.json")
    (builtins.attrNames moduleDeployments);
  observedArg = if observedLoadGraph == null then "" else toString observedLoadGraph;
in
pkgs.runCommand "${namePrefix}-completion-v2" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${loadPlan}/project-load-plan.json \
    ${lib.escapeShellArg observedArg} "$out" ${completionArgs} <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.project import write_pe32_project_completion

  arguments = sys.argv[4:]
  if len(arguments) % 2:
      raise SystemExit("module deployment arguments are not pairs")
  deployments = {
      arguments[index]: pathlib.Path(arguments[index + 1])
      for index in range(0, len(arguments), 2)
  }
  write_pe32_project_completion(
      load_plan=pathlib.Path(sys.argv[1]),
      observed_load_graph=pathlib.Path(sys.argv[2]) if sys.argv[2] else None,
      module_deployments=deployments,
      out=pathlib.Path(sys.argv[3]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-project-completion-v2" and
    (.status == "complete" or .status == "incomplete")
  ' "$out/project-completion.json" >/dev/null
''
