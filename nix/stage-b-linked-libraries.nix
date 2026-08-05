{
  pkgs,
  pythonEnv,
  pythonSource,
  original,
  machineIr,
  namePrefix,
  artifactInputs ? null,
  artifactRoot ? null,
  catalogIndexes ? [ ],
  catalogLock ? null,
  review ? null,
  interfaceCatalog ? null,
  assignments ? null,
  machineImportReport ? null,
}:

assert (artifactInputs == null) == (artifactRoot == null);

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [
      "spaghetti_extractor.linked_libraries"
      "spaghetti_extractor.util"
    ];
    name = "${namePrefix}-linked-libraries-python-closure";
  };
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
    export PYTHONPATH=${phasePythonSource}/src
  '';
  asStoreInput = name: value:
    if value != null && builtins.typeOf value == "path" then
      builtins.path { path = value; inherit name; }
    else
      value;
  artifactInputsInput = asStoreInput "library-artifact-inputs.json" artifactInputs;
  artifactRootInput = asStoreInput "library-artifact-root" artifactRoot;
  catalogIndexInputs = map (asStoreInput "library-artifact-index.json") catalogIndexes;
  catalogLockInput = asStoreInput "library-catalog-lock.json" catalogLock;
  reviewInput = asStoreInput "linked-island-review.json" review;
  interfaceCatalogInput = asStoreInput "interface-contract-catalog.json" interfaceCatalog;
  assignmentsInput = asStoreInput "linked-interface-assignments.json" assignments;
  machineImportReportInput = asStoreInput "machine-import-contract-report.json" machineImportReport;

  artifactIndex =
    if artifactInputs == null then
      null
    else
      pkgs.runCommand "${namePrefix}-library-artifact-index-v2" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - \
          ${lib.escapeShellArg artifactInputsInput} \
          ${lib.escapeShellArg artifactRootInput} \
          "$out/library-artifact-index.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import index_library_artifacts

        index_library_artifacts(
            inputs=pathlib.Path(sys.argv[1]),
            artifact_root=pathlib.Path(sys.argv[2]),
            out=pathlib.Path(sys.argv[3]),
        )
        PY
        jq -e '
          (.format == "stage-b-library-artifact-index-v1" or
           .format == "stage-b-library-artifact-index-v2") and
          .status == "indexed" and
          (.executes_original_binary | not) and
          (.authority.can_authorize_replacement | not)
        ' "$out/library-artifact-index.json" >/dev/null
      '';

  allIndexes = catalogIndexInputs ++ lib.optional (artifactIndex != null) "${artifactIndex}/library-artifact-index.json";

  generatedCatalogLock =
    if catalogLockInput != null || allIndexes == [ ] then
      null
    else
      pkgs.runCommand "${namePrefix}-library-catalog-lock-v1" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - "$out/library-catalog-lock.json" ${lib.escapeShellArgs allIndexes} <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import lock_library_catalog

        lock_library_catalog(
            indexes=[pathlib.Path(value) for value in sys.argv[2:]],
            out=pathlib.Path(sys.argv[1]),
        )
        PY
        jq -e '
          .format == "stage-b-library-catalog-lock-v1" and
          .status == "locked"
        ' "$out/library-catalog-lock.json" >/dev/null
      '';

  effectiveCatalogLock =
    if catalogLockInput != null then catalogLockInput
    else if generatedCatalogLock != null then "${generatedCatalogLock}/library-catalog-lock.json"
    else null;

  matchEvidence = pkgs.runCommand
    "${namePrefix}-library-match-evidence-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg original} \
        ${lib.escapeShellArg machineIr} \
        ${lib.escapeShellArg effectiveCatalogLock} \
        ${if reviewInput == null then "-" else lib.escapeShellArg reviewInput} \
        "$out/match-evidence.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.linked_libraries import propose_library_match_evidence

      original, machine_ir, catalog_lock, review, output = sys.argv[1:]
      propose_library_match_evidence(
          original=pathlib.Path(original),
          machine_ir=pathlib.Path(machine_ir),
          catalog_lock=pathlib.Path(catalog_lock),
          review=None if review == "-" else pathlib.Path(review),
          out=pathlib.Path(output),
      )
      PY
      jq -e '
        .format == "stage-b-library-match-evidence-v1" and
        .status == "proposed" and
        (.executes_original_binary | not) and
        (.authority.can_authorize_replacement | not)
      ' "$out/match-evidence.json" >/dev/null
    '';

  libraryHypotheses = pkgs.runCommand
    "${namePrefix}-library-hypothesis-set-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${matchEvidence}/match-evidence.json \
        "$out/library-hypotheses.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.linked_libraries import infer_library_hypotheses

      infer_library_hypotheses(
          match_evidence=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
      )
      PY
      jq -e '
        .format == "stage-b-library-hypothesis-set-v1" and
        (.status == "inferred" or .status == "incomplete") and
        (.executes_original_binary | not) and
        (.authority.can_authorize_replacement | not)
      ' "$out/library-hypotheses.json" >/dev/null
    '';

  dynamicRequirements = pkgs.runCommand
    "${namePrefix}-dynamic-library-requirements-v1"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg machineIr} \
        ${if machineImportReportInput == null then "-" else lib.escapeShellArg machineImportReportInput} \
        "$out/dynamic-library-requirements.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.linked_libraries import derive_dynamic_library_requirements

      derive_dynamic_library_requirements(
          machine_ir=pathlib.Path(sys.argv[1]),
          machine_import_report=(
              None if sys.argv[2] == "-" else pathlib.Path(sys.argv[2])
          ),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        .format == "stage-b-dynamic-library-requirements-v1" and
        (.status == "qualified" or .status == "incomplete") and
        (.executes_original_binary | not) and
        (.authority.same_abi_implies_same_behavior | not)
      ' "$out/dynamic-library-requirements.json" >/dev/null
    '';

  linkedIslands = pkgs.runCommand
    "${namePrefix}-linked-island-manifest-v2"
    commonAttrs
    ''
      set -euo pipefail
      ${environment}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg original} \
        ${lib.escapeShellArg machineIr} \
        ${matchEvidence}/match-evidence.json \
        ${libraryHypotheses}/library-hypotheses.json \
        ${if reviewInput == null then "-" else lib.escapeShellArg reviewInput} \
        "$out/linked-islands.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.linked_libraries import refine_linked_islands

      original, machine_ir, evidence, hypotheses, review, output = sys.argv[1:]
      refine_linked_islands(
          original=pathlib.Path(original),
          machine_ir=pathlib.Path(machine_ir),
          match_evidence=pathlib.Path(evidence),
          hypotheses=pathlib.Path(hypotheses),
          review=None if review == "-" else pathlib.Path(review),
          out=pathlib.Path(output),
      )
      PY
      jq -e '
        .format == "stage-b-linked-island-manifest-v2" and
        (.status == "classified" or .status == "incomplete") and
        (.executes_original_binary | not) and
        .coverage.classified_exactly_once and
        .coverage.classified_units == .coverage.machine_units and
        (.authority.artifact_recognition_authorizes_replacement | not)
      ' "$out/linked-islands.json" >/dev/null
    '';

  generatedInterfaceCatalog =
    if interfaceCatalog != null then
      null
    else
      pkgs.runCommand "${namePrefix}-empty-interface-contract-catalog-v1" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - "$out/interface-contract-catalog.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import bind_interface_contract_catalog
        from spaghetti_extractor.util import write_json

        write_json(pathlib.Path(sys.argv[1]), bind_interface_contract_catalog({
            "format": "stage-b-interface-contract-catalog-v1",
            "catalog_id": "empty-unqualified-interface-catalog-v1",
            "contracts": [],
            "replacements": [],
        }))
        PY
      '';

  effectiveInterfaceCatalog =
    if interfaceCatalogInput != null then interfaceCatalogInput
    else "${generatedInterfaceCatalog}/interface-contract-catalog.json";

  generatedAssignments =
    if assignments != null then
      null
    else
      pkgs.runCommand "${namePrefix}-empty-linked-interface-assignments-v1" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - \
          ${linkedIslands}/linked-islands.json \
          "$out/linked-interface-assignments.json" <<'PY'
        import json
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import bind_linked_interface_assignments
        from spaghetti_extractor.util import write_json

        manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
        write_json(pathlib.Path(sys.argv[2]), bind_linked_interface_assignments({
            "format": "stage-b-linked-interface-assignments-v1",
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "assignments": [],
        }))
        PY
      '';

  effectiveAssignments =
    if assignmentsInput != null then assignmentsInput
    else "${generatedAssignments}/linked-interface-assignments.json";

  interfaceQualification =
      pkgs.runCommand "${namePrefix}-linked-interface-qualification-v1" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - \
          ${linkedIslands}/linked-islands.json \
          ${lib.escapeShellArg effectiveInterfaceCatalog} \
          ${lib.escapeShellArg effectiveAssignments} \
          "$out/interface-qualification.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import qualify_linked_interfaces

        qualify_linked_interfaces(
            linked_islands=pathlib.Path(sys.argv[1]),
            interface_catalog=pathlib.Path(sys.argv[2]),
            assignments=pathlib.Path(sys.argv[3]),
            out=pathlib.Path(sys.argv[4]),
        )
        PY
        jq -e '
          .format == "stage-b-linked-interface-qualification-v1" and
          (.status == "qualified" or .status == "incomplete" or .status == "violated") and
          (.executes_original_binary | not) and
          (.authority.artifact_identity_is_semantic_proof | not)
        ' "$out/interface-qualification.json" >/dev/null
      '';

  replacementPlan =
      pkgs.runCommand "${namePrefix}-library-replacement-plan-v1" commonAttrs ''
        set -euo pipefail
        ${environment}
        mkdir -p "$out"
        ${python} - \
          ${linkedIslands}/linked-islands.json \
          ${interfaceQualification}/interface-qualification.json \
          ${lib.escapeShellArg effectiveInterfaceCatalog} \
          ${dynamicRequirements}/dynamic-library-requirements.json \
          "$out/replacement-plan.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.linked_libraries import plan_library_replacements

        plan_library_replacements(
            linked_islands=pathlib.Path(sys.argv[1]),
            interface_qualification=pathlib.Path(sys.argv[2]),
            interface_catalog=pathlib.Path(sys.argv[3]),
            dynamic_requirements=pathlib.Path(sys.argv[4]),
            out=pathlib.Path(sys.argv[5]),
        )
        PY
        jq -e '
          .format == "stage-b-library-replacement-plan-v1" and
          (.status == "complete" or .status == "incomplete") and
          (.completion.fallback_counts_as_lifting_progress | not)
        ' "$out/replacement-plan.json" >/dev/null
      '';
in
{
  inherit
    artifactIndex
    dynamicRequirements
    generatedCatalogLock
    linkedIslands
    libraryHypotheses
    matchEvidence
    interfaceQualification
    replacementPlan
    ;
}
