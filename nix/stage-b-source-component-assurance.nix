{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  binding,
  sourceInventory,
  sourceCallReport,
  functionalReport,
  upstreamReport,
  evidencePlan,
}:

assert builtins.isString namePrefix && namePrefix != "";

let
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.source_project" ];
    name = "${namePrefix}-source-assurance-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-source-component-assurance-v1"
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export PYTHONPATH=${phasePythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${pkgs.lib.escapeShellArg binding} \
      ${pkgs.lib.escapeShellArg sourceInventory} \
      ${pkgs.lib.escapeShellArg sourceCallReport} \
      ${pkgs.lib.escapeShellArg functionalReport} \
      ${pkgs.lib.escapeShellArg upstreamReport} \
      ${evidencePlan} \
      "$out/source-component-assurance.json" <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.source_project import assess_source_components

    assess_source_components(
        binding=pathlib.Path(sys.argv[1]),
        source_inventory=pathlib.Path(sys.argv[2]),
        source_call_report=pathlib.Path(sys.argv[3]),
        functional_report=pathlib.Path(sys.argv[4]),
        upstream_report=pathlib.Path(sys.argv[5]),
        evidence_plan=pathlib.Path(sys.argv[6]),
        out=pathlib.Path(sys.argv[7]),
    )
    PY
    jq -e '
      .format == "stage-b-source-component-assurance-v1" and
      (.executes_original_binary | not) and
      .equivalence_status == "not_proven" and
      (.authority.proves_equivalence | not) and
      (.authority.can_authorize_machine_override | not)
    ' "$out/source-component-assurance.json" >/dev/null
  ''
