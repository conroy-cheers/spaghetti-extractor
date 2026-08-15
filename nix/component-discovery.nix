# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  machineIr,
  reconstructionPlan,
  namePrefix,
  maxUnits ? 512,
  maxCandidatesPerSeed ? 12,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "proposal";
    inherit pkgs;
    modules = [ "spaghetti_extractor.components.discovery" ];
    name = "${namePrefix}-component-discovery-python-closure";
  };
in
pkgs.runCommand
  "${namePrefix}-component-proposals-v2"
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
      ${machineIr} \
      ${reconstructionPlan}/reconstruction-plan.json \
      "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.components.discovery import write_component_proposals
    from spaghetti_extractor.components.proposal_package import (
        load_component_proposal_package_v2,
    )

    write_component_proposals(
        machine_ir=pathlib.Path(sys.argv[1]),
        reconstruction_plan=pathlib.Path(sys.argv[2]),
        out=pathlib.Path(sys.argv[3]),
        max_units=${toString maxUnits},
        max_candidates_per_seed=${toString maxCandidatesPerSeed},
    )
    load_component_proposal_package_v2(sys.argv[3]).validate_all_proposals()
    PY
    jq -e '
      .format == "spaghetti-extractor-component-proposal-package-v2" and
      (.package_sha256 | type == "string")
    ' "$out/manifest.json" >/dev/null
    jq -e '
      .format == "spaghetti-extractor-component-proposal-index-v2" and
      (.status == "proposed" or .status == "incomplete") and
      (.executes_original_binary | not) and
      (.authority.can_authorize_replacement | not) and
      .authority.requires_operator_selection and
      .authority.requires_interface_refinement and
      (.proposals | length) > 0 and
      (.index_sha256 | type == "string")
    ' "$out/proposal-index.json" >/dev/null
    jq -e '.exact.complete and .potential.complete' \
      "$out/coverage.json" >/dev/null
  ''
