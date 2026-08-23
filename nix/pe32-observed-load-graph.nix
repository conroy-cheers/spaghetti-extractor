# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, loadPlan, observation, namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-observed-load-graph-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-observed-load-graph-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - \
    ${loadPlan}/project-load-plan.json \
    ${observation} "$out" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.candidate.project import write_pe32_observed_load_graph

  write_pe32_observed_load_graph(
      load_plan=pathlib.Path(sys.argv[1]),
      observation=pathlib.Path(sys.argv[2]),
      out=pathlib.Path(sys.argv[3]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-observed-load-graph-v1" and
    (.status == "qualified" or .status == "incomplete") and
    .policy.physical_import_slots_preserved
  ' "$out/observed-load-graph.json" >/dev/null
''
