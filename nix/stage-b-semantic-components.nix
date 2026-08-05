{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  declarations,
  namePrefix,
  validationAssertion ? "",
  linkedIslands ? null,
}:

let
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.semantic_components" ];
    name = "${namePrefix}-semantic-components-python-closure";
  };
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
    export PYTHONPATH=${phasePythonSource}/src
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
      ${validationAssertion}
    ' "$out/semantic-component-catalog.json" >/dev/null
  ''
