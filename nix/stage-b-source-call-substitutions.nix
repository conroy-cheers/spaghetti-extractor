{
  pkgs,
  pythonEnv,
  pythonSource,
  sourceBinding,
  linkedIslands,
  dynamicRequirements,
  namePrefix,
  original ? null,
  machineIr ? null,
  indirectTargets ? null,
  interfaceCatalog ? null,
  substitutionCatalog ? null,
  assignments ? null,
  clangAst ? null,
  sourceRoot ? null,
  sourceCallBindings ? null,
  candidate ? null,
  allowedRuntimeImports ? null,
  proposeSourceComponents ? false,
}:

assert (clangAst == null) == (sourceRoot == null);
assert (candidate == null) == (allowedRuntimeImports == null);
assert (original == null) == (machineIr == null);
assert (interfaceCatalog == null) == (substitutionCatalog == null);
assert (interfaceCatalog == null) == (assignments == null);

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  commonAttrs = {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };
  environment = ''
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${pythonSource}/src
  '';
  asStoreInput = name: value:
    if value != null && builtins.typeOf value == "path" then
      builtins.path { path = value; inherit name; }
    else
      value;
  indirectTargetsInput = asStoreInput "indirect-call-targets.json" indirectTargets;
  interfaceCatalogInput = asStoreInput "callable-interface-catalog.json" interfaceCatalog;
  substitutionCatalogInput = asStoreInput "source-substitution-catalog.json" substitutionCatalog;
  assignmentsInput = asStoreInput "call-substitution-assignments.json" assignments;
  clangAstInput = asStoreInput "clang-ast.json" clangAst;
  sourceRootInput = asStoreInput "source-root" sourceRoot;
  sourceCallBindingsInput = asStoreInput "source-call-bindings.json" sourceCallBindings;
  allowedRuntimeImportsInput = asStoreInput "allowed-runtime-imports.json" allowedRuntimeImports;

  generatedIndirectTargets =
    if indirectTargetsInput != null || original == null then null else
    pkgs.runCommand "${namePrefix}-static-indirect-call-targets-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg original} \
        ${lib.escapeShellArg machineIr} \
        ${lib.escapeShellArg sourceBinding} \
        "$out/indirect-call-targets.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import derive_static_indirect_call_targets

      derive_static_indirect_call_targets(
          original=pathlib.Path(sys.argv[1]),
          machine_ir=pathlib.Path(sys.argv[2]),
          source_binding=pathlib.Path(sys.argv[3]),
          out=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e '
        .format == "stage-b-indirect-call-targets-v1" and
        (.status == "qualified" or .status == "incomplete") and
        (.executes_original_binary | not) and
        (.authority.authorizes_semantic_substitution | not)
      ' "$out/indirect-call-targets.json" >/dev/null
    '';

  effectiveIndirectTargets =
    if indirectTargetsInput != null then indirectTargetsInput
    else if generatedIndirectTargets != null then
      "${generatedIndirectTargets}/indirect-call-targets.json"
    else null;

  callFrontier = pkgs.runCommand "${namePrefix}-call-frontier-v1" commonAttrs ''
    set -euo pipefail
    ${environment}
    mkdir -p "$out"
    ${python} - \
      ${lib.escapeShellArg sourceBinding} \
      ${lib.escapeShellArg linkedIslands} \
      ${lib.escapeShellArg dynamicRequirements} \
      ${if effectiveIndirectTargets == null then "-" else lib.escapeShellArg effectiveIndirectTargets} \
      "$out/call-frontier.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.source_call_substitution import generate_call_frontier

    generate_call_frontier(
        source_binding=pathlib.Path(sys.argv[1]),
        linked_islands=pathlib.Path(sys.argv[2]),
        dynamic_requirements=pathlib.Path(sys.argv[3]),
        indirect_targets=None if sys.argv[4] == "-" else pathlib.Path(sys.argv[4]),
        out=pathlib.Path(sys.argv[5]),
    )
    PY
    jq -e '
      .format == "stage-b-call-frontier-v1" and
      (.status == "complete" or .status == "incomplete") and
      (.executes_original_binary | not) and
      .counts.calls == (.calls | length) and
      (.authority.can_authorize_source_substitution | not)
    ' "$out/call-frontier.json" >/dev/null
  '';

  proposedSourceComponents =
    if !proposeSourceComponents || interfaceCatalogInput != null then null else
    pkgs.runCommand "${namePrefix}-proposed-source-components-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${callFrontier}/call-frontier.json \
        ${lib.escapeShellArg sourceBinding} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import propose_source_component_artifacts

      out = pathlib.Path(sys.argv[3])
      propose_source_component_artifacts(
          frontier=pathlib.Path(sys.argv[1]),
          source_binding=pathlib.Path(sys.argv[2]),
          interfaces_out=out / "callable-interface-catalog.json",
          substitutions_out=out / "source-substitution-catalog.json",
          assignments_out=out / "call-substitution-assignments.json",
      )
      PY
      jq -e '
        .format == "stage-b-callable-interface-catalog-v1" and
        all(.interfaces[]; .qualification.status == "incomplete" and
          .qualification.kind == "operator_proposal")
      ' "$out/callable-interface-catalog.json" >/dev/null
    '';

  effectiveInterfaceCatalogInput =
    if interfaceCatalogInput != null then interfaceCatalogInput
    else if proposedSourceComponents != null then
      "${proposedSourceComponents}/callable-interface-catalog.json"
    else null;
  effectiveSubstitutionCatalogInput =
    if substitutionCatalogInput != null then substitutionCatalogInput
    else if proposedSourceComponents != null then
      "${proposedSourceComponents}/source-substitution-catalog.json"
    else null;
  effectiveAssignmentsInput =
    if assignmentsInput != null then assignmentsInput
    else if proposedSourceComponents != null then
      "${proposedSourceComponents}/call-substitution-assignments.json"
    else null;

  effectiveInterfaceCatalog = pkgs.runCommand
    "${namePrefix}-callable-interface-catalog-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${if effectiveInterfaceCatalogInput == null then "-" else lib.escapeShellArg effectiveInterfaceCatalogInput} \
        "$out/callable-interface-catalog.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import bind_callable_interface_catalog
      from spaghetti_extractor.util import write_json

      if sys.argv[1] == "-":
          payload = {
              "format": "stage-b-callable-interface-catalog-v1",
              "catalog_id": "empty-callable-interface-catalog-v1",
              "interfaces": [],
          }
      else:
          payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
      write_json(pathlib.Path(sys.argv[2]), bind_callable_interface_catalog(payload))
      PY
    '';

  effectiveSubstitutionCatalog = pkgs.runCommand
    "${namePrefix}-source-substitution-catalog-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${if effectiveSubstitutionCatalogInput == null then "-" else lib.escapeShellArg effectiveSubstitutionCatalogInput} \
        "$out/source-substitution-catalog.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import bind_source_substitution_catalog
      from spaghetti_extractor.util import write_json

      if sys.argv[1] == "-":
          payload = {
              "format": "stage-b-source-substitution-catalog-v1",
              "catalog_id": "empty-source-substitution-catalog-v1",
              "substitutions": [],
          }
      else:
          payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
      write_json(pathlib.Path(sys.argv[2]), bind_source_substitution_catalog(payload))
      PY
    '';

  effectiveAssignments = pkgs.runCommand
    "${namePrefix}-call-substitution-assignments-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${callFrontier}/call-frontier.json \
        ${if effectiveAssignmentsInput == null then "-" else lib.escapeShellArg effectiveAssignmentsInput} \
        "$out/call-substitution-assignments.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import bind_call_substitution_assignments
      from spaghetti_extractor.util import write_json

      frontier = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
      if sys.argv[2] == "-":
          payload = {
              "format": "stage-b-call-substitution-assignments-v1",
              "assignments": [],
          }
      else:
          payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
      payload["frontier_sha256"] = frontier["frontier_sha256"]
      write_json(pathlib.Path(sys.argv[3]), bind_call_substitution_assignments(payload))
      PY
    '';

  callPlan = pkgs.runCommand "${namePrefix}-call-substitution-plan-v1" commonAttrs ''
    set -euo pipefail
    ${environment}
    mkdir -p "$out"
    ${python} - \
      ${callFrontier}/call-frontier.json \
      ${effectiveInterfaceCatalog}/callable-interface-catalog.json \
      ${effectiveSubstitutionCatalog}/source-substitution-catalog.json \
      ${effectiveAssignments}/call-substitution-assignments.json \
      "$out/call-substitution-plan.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.source_call_substitution import plan_call_substitutions

    plan_call_substitutions(
        frontier=pathlib.Path(sys.argv[1]),
        interface_catalog=pathlib.Path(sys.argv[2]),
        substitution_catalog=pathlib.Path(sys.argv[3]),
        assignments=pathlib.Path(sys.argv[4]),
        out=pathlib.Path(sys.argv[5]),
    )
    PY
    jq -e '
      .format == "stage-b-call-substitution-plan-v1" and
      (.status == "complete" or .status == "incomplete" or .status == "violated") and
      (.executes_original_binary | not) and
      .counts.frontier_calls >= 0
    ' "$out/call-substitution-plan.json" >/dev/null
  '';

  sourceInventory =
    if clangAstInput == null then null else
    pkgs.runCommand "${namePrefix}-source-call-inventory-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg clangAstInput} \
        ${lib.escapeShellArg sourceRootInput} \
        ${lib.escapeShellArg sourceBinding} \
        "$out/source-call-inventory.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import inventory_clang_source_calls

      binding = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
      inventory_clang_source_calls(
          ast_json=pathlib.Path(sys.argv[1]),
          source_root=pathlib.Path(sys.argv[2]),
          source_hashes=binding["sources"],
          project_symbols=[island["source_symbol"] for island in binding["islands"]],
          out=pathlib.Path(sys.argv[4]),
      )
      PY
    '';

  effectiveSourceCallBindings =
    if sourceInventory == null then null else
    pkgs.runCommand "${namePrefix}-source-call-bindings-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${callPlan}/call-substitution-plan.json \
        ${sourceInventory}/source-call-inventory.json \
        ${if sourceCallBindingsInput == null then "-" else lib.escapeShellArg sourceCallBindingsInput} \
        "$out/source-call-bindings.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import bind_source_call_bindings
      from spaghetti_extractor.util import write_json

      plan = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
      inventory = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
      if sys.argv[3] == "-" and ${if proposeSourceComponents then "True" else "False"}:
          from spaghetti_extractor.source_call_substitution import propose_source_component_bindings
          propose_source_component_bindings(
              call_plan=pathlib.Path(sys.argv[1]),
              source_inventory=pathlib.Path(sys.argv[2]),
              out=pathlib.Path(sys.argv[4]),
          )
          raise SystemExit(0)
      if sys.argv[3] == "-":
          payload = {"format": "stage-b-source-call-bindings-v1", "bindings": []}
      else:
          payload = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
      payload["call_plan_sha256"] = plan["plan_sha256"]
      payload["source_inventory_sha256"] = inventory["inventory_sha256"]
      write_json(pathlib.Path(sys.argv[4]), bind_source_call_bindings(payload))
      PY
    '';

  sourceBindingReport =
    if sourceInventory == null then null else
    pkgs.runCommand "${namePrefix}-source-call-binding-report-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${callPlan}/call-substitution-plan.json \
        ${sourceInventory}/source-call-inventory.json \
        ${effectiveSourceCallBindings}/source-call-bindings.json \
        "$out/source-call-binding-report.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import check_source_call_bindings

      check_source_call_bindings(
          call_plan=pathlib.Path(sys.argv[1]),
          source_inventory=pathlib.Path(sys.argv[2]),
          bindings=pathlib.Path(sys.argv[3]),
          out=pathlib.Path(sys.argv[4]),
      )
      PY
    '';

  candidateAudit =
    if candidate == null then null else
    pkgs.runCommand "${namePrefix}-candidate-dependency-audit-v1" commonAttrs ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg candidate} \
        ${callPlan}/call-substitution-plan.json \
        ${lib.escapeShellArg allowedRuntimeImportsInput} \
        "$out/candidate-dependency-audit.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.source_call_substitution import (
          audit_candidate_dependencies,
          bind_allowed_runtime_imports,
      )

      supplied = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
      allowed = bind_allowed_runtime_imports(supplied)
      if (
          supplied.get("envelope_sha256") is not None
          and supplied["envelope_sha256"] != allowed["envelope_sha256"]
      ):
          raise ValueError("allowed runtime imports hash is stale")
      audit_candidate_dependencies(
          candidate=pathlib.Path(sys.argv[1]),
          call_plan=pathlib.Path(sys.argv[2]),
          allowed_runtime_imports=allowed["imports"],
          allowed_runtime_imports_sha256=allowed["envelope_sha256"],
          out=pathlib.Path(sys.argv[4]),
      )
      PY
    '';
in
{
  inherit
    callFrontier
    generatedIndirectTargets
    proposedSourceComponents
    effectiveInterfaceCatalog
    effectiveSubstitutionCatalog
    effectiveAssignments
    callPlan
    sourceInventory
    effectiveSourceCallBindings
    sourceBindingReport
    candidateAudit
    ;
}
