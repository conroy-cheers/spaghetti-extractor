{
  pkgs,
  pythonEnv,
  pythonSource,
  componentProposals,
  selection,
  namePrefix,
}:

pkgs.runCommand
  "${namePrefix}-selected-component-declarations-v1"
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
      ${componentProposals}/component-proposals.json \
      ${selection} \
      "$out/semantic-component-declarations.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.component_selection import materialize_component_declarations

    materialize_component_declarations(
        proposals=pathlib.Path(sys.argv[1]),
        selection=pathlib.Path(sys.argv[2]),
        out=pathlib.Path(sys.argv[3]),
    )
    PY
    jq -e '
      .format == "stage-b-semantic-component-declarations-v1" and
      (.components | length) > 0 and
      ([.components[].refinement.status] | all(. == "not_started")) and
      ([.components[].membership.unit_ids | length] | all(. > 0)) and
      (.selection.proposal_set_sha256 | type == "string") and
      (.selection.selected_proposal_set_sha256 | type == "string") and
      (
        .selection.binding_mode == "exact_proposal_set_v1" or
        .selection.binding_mode == "stable_membership_v1"
      ) and
      (.selection.selection_sha256 | type == "string")
    ' "$out/semantic-component-declarations.json" >/dev/null
  ''
