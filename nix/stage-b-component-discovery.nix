{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  namePrefix,
  maxUnits ? 512,
  maxCandidatesPerSeed ? 12,
}:

pkgs.runCommand
  "${namePrefix}-component-proposals-v1"
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
    export PYTHONPATH=${pythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${machineIr} \
      ${reconstructionPlan}/reconstruction-plan.json \
      "$out/component-proposals.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.component_discovery import write_component_proposals

    write_component_proposals(
        machine_ir=pathlib.Path(sys.argv[1]),
        reconstruction_plan=pathlib.Path(sys.argv[2]),
        out=pathlib.Path(sys.argv[3]),
        max_units=${toString maxUnits},
        max_candidates_per_seed=${toString maxCandidatesPerSeed},
    )
    PY
    jq -e '
      .format == "stage-b-component-proposal-set-v1" and
      (.status == "proposed" or .status == "incomplete") and
      (.executes_original_binary | not) and
      (.authority.can_authorize_replacement | not) and
      .authority.requires_operator_selection and
      .authority.requires_interface_refinement and
      .coverage.exact.complete and .coverage.potential.complete and
      (.proposals | length) > 0 and
      (.proposal_set_sha256 | type == "string")
    ' "$out/component-proposals.json" >/dev/null
  ''
