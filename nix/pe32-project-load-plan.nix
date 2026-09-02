# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, intent, linkedSemanticModules, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-load-plan-python-closure";
  };
  linkedArgs = lib.concatMapStringsSep " "
    (imageId: "${lib.escapeShellArg imageId} ${linkedSemanticModules.${imageId}}")
    (builtins.attrNames linkedSemanticModules);
in
pkgs.runCommand "${namePrefix}-load-plan-v2" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource.pythonPath}
  ${pythonEnv}/bin/python3 - ${intent} "$out" \
    ${toString (builtins.length (builtins.attrNames linkedSemanticModules))} \
    ${linkedArgs} <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.project import write_pe32_project_load_plan

  linked_count = int(sys.argv[3])
  arguments = sys.argv[4:]
  if len(arguments) != linked_count * 2:
      raise SystemExit("linked semantic module arguments are not pairs")
  linked = {
      arguments[index]: pathlib.Path(arguments[index + 1])
      for index in range(0, len(arguments), 2)
  }
  write_pe32_project_load_plan(
      intent=pathlib.Path(sys.argv[1]),
      linked_semantic_modules=linked,
      out=pathlib.Path(sys.argv[2]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-project-load-plan-v2" and
    (.status == "complete" or .status == "incomplete") and
    (.status == "complete") == (.counts.blockers == 0) and
    .policy.duplicate_logical_import_slots == "preserved"
  ' "$out/project-load-plan.json" >/dev/null
''
