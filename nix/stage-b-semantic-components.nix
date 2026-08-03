{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  declarations,
  namePrefix,
  validationProfile ? "generic-v1",
  linkedIslands ? null,
}:

let
  linkedIslandAssertion =
    if linkedIslands == null then
      ""
    else
      ''
        and (.bindings.linked_island_manifest_sha256 | type) == "string"
        and .policy.linked_island_identity_authorizes_replacement == false
        and .coverage.linked_islands.identity_authorizes_replacement == false
        and (.coverage.linked_islands.machine_units_by_kind
          | to_entries | map(.value) | add) > 0
        and all(.components[];
          .linked_island_membership.identity_authorizes_replacement == false)
      '';
  profileAssertion =
    if validationProfile == "generic-v1" then
      ""
    else if validationProfile == "gnu-hello-validation-set-v1" then
      ''
        and .counts.components == 12
        and .counts.leaf_components == 11
        and .counts.aggregate_components == 1
        and .counts.valid_definitions == 12
        and any(.components[];
          .id == "static-word-initialization" and
          .membership.noncontiguous and
          (.membership.resolved_unit_ids | length) == 2 and
          .refinement.machine_to_logical_projection_validated == false)
        and any(.components[];
          .id == "rotate-pending-words" and
          (.membership.resolved_unit_ids | length) == 31 and
          .machine_boundary.counts.entries == 1 and
          .machine_boundary.counts.exits == 1 and
          .refinement.machine_to_logical_projection_validated == false)
        and any(.components[];
          .id == "finite-selector-dispatch" and
          .machine_boundary.exits[0].target_inventory.status == "recovered" and
          (.machine_boundary.exits[0].target_inventory.target_unit_ids | length) == 12)
        and any(.components[];
          .id == "short-option-classifier" and
          .machine_boundary.boundary_minimization_status == "not_attempted")
        and any(.components[];
          .id == "windows-error-message-lookup" and
          (.membership.resolved_unit_ids | length) == 43 and
          .machine_boundary.counts.entries == 1 and
          .machine_boundary.counts.exits == 1 and
          .machine_boundary.counts.external_events == 0)
        and any(.components[];
          .id == "bounded-string-length" and
          (.membership.resolved_unit_ids | length) == 8 and
          .machine_boundary.counts.entries == 1 and
          .machine_boundary.counts.exits == 1 and
          .machine_boundary.counts.external_events == 0)
      ''
    else
      throw "unsupported semantic-component validation profile: ${validationProfile}";
in
pkgs.runCommand "${namePrefix}-semantic-components-v1"
  {
    nativeBuildInputs = [
      pythonEnv
      pkgs.jq
      pkgs.coreutils
    ];
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
      ${pkgs.lib.escapeShellArg (if linkedIslands == null then "-" else linkedIslands)} \
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
        linked_islands=(None if sys.argv[4] == "-" else pathlib.Path(sys.argv[4])),
        out=pathlib.Path(sys.argv[5]),
    )
    PY
    jq -e '
      .format == "stage-b-semantic-component-catalog-v1" and
      .status == "incomplete" and
      .definition_status == "valid" and
      .assurance_status == "incomplete" and
      (.executes_original_binary | not) and
      (.generates_component_implementations | not) and
      .counts.components > 0 and
      .counts.valid_definitions == .counts.components and
      .counts.validated_refinements == 0 and
      .counts.issues == 0 and
      .counts.declared_units > 0 and
      (.coverage.counts.declared_exact_reachable_units +
        .coverage.counts.declared_potential_units) == .counts.declared_units and
      ([.components[].refinement.machine_to_logical_projection_validated] |
        all(. == false))
      ${linkedIslandAssertion}
      ${profileAssertion}
    ' "$out/semantic-component-catalog.json" >/dev/null
  ''
