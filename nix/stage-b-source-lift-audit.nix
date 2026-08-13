{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  authorityDiagnostics,
  sourceIterationAudit,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.source_lift_audit" ];
    name = "${namePrefix}-source-lift-audit-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-source-lift-audit-v1" {
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
    ${sourceIterationAudit} \
    ${authorityDiagnostics} \
    "$out/source-lift-audit.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.source_lift_audit import join_source_lift_authority

  values = [pathlib.Path(value) for value in sys.argv[1:]]
  join_source_lift_authority(
      source_iteration_audit=values[0],
      authority_diagnostics=values[1],
      out=values[2],
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-source-lift-audit-v1" and
    (.status == "complete" or .status == "incomplete") and
    (.original_binary_executed | not) and
    (.trust.authorizes_candidate_generation | not) and
    (.trust.authorizes_runtime_testing | not)
  ' "$out/source-lift-audit.json" >/dev/null
''
