{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  declarations,
  namePrefix,
}:

pkgs.runCommand
  "${namePrefix}-semantic-components-v1"
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
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
      ${declarations} \
      "$out/semantic-component-catalog.json" <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.semantic_components import (
        write_semantic_component_catalog,
    )

    write_semantic_component_catalog(
        machine_ir=pathlib.Path(sys.argv[1]),
        reconstruction_plan=pathlib.Path(sys.argv[2]),
        declarations=pathlib.Path(sys.argv[3]),
        out=pathlib.Path(sys.argv[4]),
    )
    PY
    jq -e '
      .format == "stage-b-semantic-component-catalog-v1" and
      .status == "incomplete" and
      .definition_status == "valid" and
      .assurance_status == "incomplete" and
      (.executes_original_binary | not) and
      (.generates_component_implementations | not) and
      .counts.components == 10 and
      .counts.leaf_components == 9 and
      .counts.aggregate_components == 1 and
      .counts.valid_definitions == 10 and
      .counts.validated_refinements == 0 and
      .coverage.complete == false and
      .coverage.counts.declared_exact_reachable_units > 0 and
      .coverage.counts.unassigned_exact_reachable_units > 0 and
      any(.components[];
        .id == "static-word-initialization" and
        .membership.noncontiguous and
        (.membership.resolved_unit_ids | length) == 2 and
        .refinement.machine_to_logical_projection_validated == false) and
      any(.components[];
        .id == "rotate-pending-words" and
        (.membership.resolved_unit_ids | length) == 31 and
        .machine_boundary.counts.entries == 1 and
        .machine_boundary.counts.exits == 1 and
        .refinement.machine_to_logical_projection_validated == false) and
      any(.components[];
        .id == "finite-selector-dispatch" and
        .machine_boundary.exits[0].target_inventory.status == "recovered" and
        (.machine_boundary.exits[0].target_inventory.target_unit_ids | length) == 12) and
      any(.components[];
        .id == "short-option-classifier" and
        .machine_boundary.boundary_minimization_status == "not_attempted")
    ' "$out/semantic-component-catalog.json" >/dev/null
  ''
