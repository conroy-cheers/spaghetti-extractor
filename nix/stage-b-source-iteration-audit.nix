{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  machineIr,
  sourceBinding,
  sourceEvidencePlan,
  candidate,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.source_lift_audit" ];
    name = "${namePrefix}-source-iteration-audit-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-source-iteration-audit-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${phasePythonSource}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${machineIr} \
    ${sourceBinding} \
    ${sourceEvidencePlan} \
    ${candidate} \
    "$out/source-iteration-audit.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.source_lift_audit import audit_source_iteration

  values = [pathlib.Path(value) for value in sys.argv[1:]]
  audit_source_iteration(
      machine_ir=values[0],
      source_binding=values[1],
      source_evidence_plan=values[2],
      candidate_build=values[3],
      out=values[4],
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-source-iteration-audit-v1" and
    (.status == "complete" or .status == "incomplete") and
    (.original_binary_executed | not) and
    (.stages.final_authority_join.status == "not_evaluated") and
    (.stages.candidate_behavior.authorized_to_run | not) and
    (.trust.authorizes_candidate_generation | not) and
    (.trust.authorizes_runtime_testing | not)
  ' "$out/source-iteration-audit.json" >/dev/null
''
