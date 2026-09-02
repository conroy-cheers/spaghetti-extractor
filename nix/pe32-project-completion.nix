# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, loadPlan, nativeRealizations
, observedLoadGraph ? null, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-completion-python-closure";
  };
  completionArgs = lib.concatMapStringsSep " "
    (imageId: "${lib.escapeShellArg imageId} ${nativeRealizations.${imageId}}/native-realization.json")
    (builtins.attrNames nativeRealizations);
  observedArg = if observedLoadGraph == null then "" else toString observedLoadGraph;
in
pkgs.runCommand "${namePrefix}-completion-v3" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource.pythonPath}
  ${pythonEnv}/bin/python3 - ${loadPlan}/project-load-plan.json \
    ${lib.escapeShellArg observedArg} "$out" ${completionArgs} <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.project import write_pe32_project_completion

  arguments = sys.argv[4:]
  if len(arguments) % 2:
      raise SystemExit("project realization arguments are not pairs")
  realizations = {}
  for index in range(0, len(arguments), 2):
      image_id, path = arguments[index:index + 2]
      if image_id in realizations:
          raise SystemExit("project realization argument is invalid")
      realizations[image_id] = pathlib.Path(path)
  write_pe32_project_completion(
      load_plan=pathlib.Path(sys.argv[1]),
      observed_load_graph=pathlib.Path(sys.argv[2]) if sys.argv[2] else None,
      native_realizations=realizations,
      out=pathlib.Path(sys.argv[3]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-project-completion-v3" and
    (.status == "complete" or .status == "incomplete")
  ' "$out/project-completion.json" >/dev/null
''
