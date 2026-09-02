# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  pythonSource,
  original,
  machineIr,
  linkedSemanticModule ? null,
  namePrefix,
  artifactInputs ? null,
  artifactRoot ? null,
  catalogIndexes ? [ ],
  abiCatalogs ? [ ],
  catalogLock ? null,
  implementations ? { },
  adoptionIntents ? { },
  targetId ? namePrefix,
  binaryIdentity ? targetId,
}:

assert (artifactInputs == null) == (artifactRoot == null);

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  identifier = value:
    builtins.isString value && value != ""
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  asStoreInput = name: value:
    if value != null && builtins.typeOf value == "path" then
      builtins.path { path = value; inherit name; }
    else value;
  mkPhaseSource = phase: role: modules: import ./python-module-closure.nix {
    phaseRole = role;
    inherit pkgs modules;
    name = "${namePrefix}-libraries-${phase}-python-closure";
  };
  environment = phaseSource: ''
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phaseSource.pythonPath}
  '';
  commonAttrs = {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };

  catalogSource = mkPhaseSource "catalog" "proposal" [
    "spaghetti_extractor.libraries.catalog"
  ];
  targetSignatureSource = mkPhaseSource "target-signature" "proposal" [
    "spaghetti_extractor.libraries.signature_graph"
  ];
  catalogSearchSource = mkPhaseSource "catalog-search" "proposal" [
    "spaghetti_extractor.libraries.abi_catalog"
  ];
  releaseSource = mkPhaseSource "release-hypotheses" "proposal" [
    "spaghetti_extractor.libraries.v4_matching"
  ];
  emptyReleaseSource = mkPhaseSource "empty-release-hypotheses" "proposal" [
    "spaghetti_extractor.libraries.v4_record_support"
    "spaghetti_extractor.util"
  ];
  artifactInputsInput = asStoreInput "library-artifact-inputs.json" artifactInputs;
  artifactRootInput = asStoreInput "library-artifact-root" artifactRoot;
  catalogIndexInputs = map (asStoreInput "library-artifact-index.json") catalogIndexes;
  abiCatalogInputs = map (asStoreInput "library-abi-catalog-v3.json") abiCatalogs;
  catalogLockInput = asStoreInput "library-catalog-lock.json" catalogLock;
  implementationInputs = lib.mapAttrs
    (id: value: asStoreInput "${id}-reusable-library-implementation-v1.json" value)
    implementations;
  intentInputs = lib.mapAttrs
    (id: value: asStoreInput "${id}-library-adoption-intent-v1.json" value)
    adoptionIntents;
  intentPayloads = lib.mapAttrs
    (_: value: builtins.fromJSON (builtins.readFile value))
    intentInputs;

  artifactIndex =
    if artifactInputs == null then null else
    pkgs.runCommand "${namePrefix}-library-artifact-index-v2" commonAttrs ''
      set -euo pipefail
      ${environment catalogSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg artifactInputsInput} \
        ${lib.escapeShellArg artifactRootInput} \
        "$out/library-artifact-index.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.libraries.catalog import index_library_artifacts

      index_library_artifacts(
          inputs=pathlib.Path(sys.argv[1]),
          artifact_root=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        (.format == "spaghetti-extractor-library-artifact-index-v1" or
         .format == "spaghetti-extractor-library-artifact-index-v2") and
        .status == "indexed" and
        (.executes_original_binary | not) and
        (.authority.can_authorize_replacement | not)
      ' "$out/library-artifact-index.json" >/dev/null
    '';

  allIndexes = catalogIndexInputs
    ++ lib.optional (artifactIndex != null) "${artifactIndex}/library-artifact-index.json";
  generatedCatalogLock =
    if catalogLockInput != null || allIndexes == [ ] then null else
    pkgs.runCommand "${namePrefix}-library-catalog-lock-v1" commonAttrs ''
      set -euo pipefail
      ${environment catalogSource}
      mkdir -p "$out"
      ${python} - "$out/library-catalog-lock.json" ${lib.escapeShellArgs allIndexes} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.libraries.catalog import lock_library_catalog

      lock_library_catalog(
          indexes=[pathlib.Path(value) for value in sys.argv[2:]],
          out=pathlib.Path(sys.argv[1]),
      )
      PY
      jq -e '.format == "spaghetti-extractor-library-catalog-lock-v1" and .status == "locked"' \
        "$out/library-catalog-lock.json" >/dev/null
    '';
  effectiveCatalogLock =
    if catalogLockInput != null then catalogLockInput
    else if generatedCatalogLock != null then "${generatedCatalogLock}/library-catalog-lock.json"
    else null;
  catalogSearchInputs = lib.optional (effectiveCatalogLock != null) effectiveCatalogLock
    ++ abiCatalogInputs;

  targetSignatureGraph = pkgs.runCommand
    "${namePrefix}-library-target-signature-graph-v3" commonAttrs ''
      set -euo pipefail
      ${environment targetSignatureSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg machineIr} \
        ${lib.escapeShellArg original} \
        "$out/target-signature-graph.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.libraries.signature_graph import build_target_signature_graph

      build_target_signature_graph(
          machine_ir=pathlib.Path(sys.argv[1]),
          original_pe=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-library-target-signature-graph-v3" and
        (.status == "complete" or .status == "incomplete" or .status == "violated") and
        (.executes_original_binary | not)
      ' "$out/target-signature-graph.json" >/dev/null
    '';

  catalogSearchIndex =
    if catalogSearchInputs == [ ] then null else
    pkgs.runCommand "${namePrefix}-library-catalog-search-index-v3" commonAttrs ''
      set -euo pipefail
      ${environment catalogSearchSource}
      mkdir -p "$out"
      ${python} - "$out/catalog-search-index.json" ${lib.escapeShellArgs catalogSearchInputs} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.libraries.abi_catalog import build_catalog_search_index

      build_catalog_search_index(
          catalog_lock_or_indexes=[pathlib.Path(value) for value in sys.argv[2:]],
          out=pathlib.Path(sys.argv[1]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-library-catalog-search-index-v3" and
        (.status == "complete" or .status == "incomplete" or .status == "violated") and
        (.executes_original_binary | not)
      ' "$out/catalog-search-index.json" >/dev/null
    '';

  releaseHypotheses =
    if catalogSearchIndex == null then
      pkgs.runCommand "${namePrefix}-library-release-hypotheses-empty-v4" commonAttrs ''
        set -euo pipefail
        ${environment emptyReleaseSource}
        mkdir -p "$out"
        ${python} - ${lib.escapeShellArg targetId} "$out/manifest.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.artifacts.formats import LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT
        from spaghetti_extractor.libraries.v4_record_support import canonical_sha256
        from spaghetti_extractor.util import write_json

        core = {
            "format": LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
            "target_id": sys.argv[1],
            "target_binary_sha256": "0" * 64,
            "target_signature_graph_sha256": "0" * 64,
            "catalog_search_index_sha256": "0" * 64,
            "releases": [],
        }
        write_json(pathlib.Path(sys.argv[2]), {**core, "manifest_sha256": canonical_sha256(core)})
        PY
      ''
    else
      pkgs.runCommand "${namePrefix}-library-release-hypotheses-v4" commonAttrs ''
        set -euo pipefail
        ${environment releaseSource}
        mkdir -p "$out"
        ${python} - \
          ${lib.escapeShellArg targetId} \
          ${targetSignatureGraph}/target-signature-graph.json \
          ${catalogSearchIndex}/catalog-search-index.json \
          ${lib.escapeShellArg original} \
          "$out" \
          ${lib.escapeShellArgs (builtins.attrValues implementationInputs)} <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.libraries.v4_matching import solve_library_release_hypotheses

        solve_library_release_hypotheses(
            target_id=sys.argv[1],
            target_signatures=pathlib.Path(sys.argv[2]),
            search_index=pathlib.Path(sys.argv[3]),
            target_pe=pathlib.Path(sys.argv[4]),
            out_dir=pathlib.Path(sys.argv[5]),
            implementations=[pathlib.Path(value) for value in sys.argv[6:]],
        )
        PY
        jq -e '
          .format == "spaghetti-extractor-library-release-hypotheses-set-v4" and
          (.releases | type == "array")
        ' "$out/manifest.json" >/dev/null
      '';

  # Physical ABI authority must come from the linked semantic module.  Until
  # that facet lands, adopted islands fail closed in v4_activation.py; there is
  # no target-local extraction or matching compatibility surface.

  checkedIslands = lib.mapAttrs
    (selectionId: intent:
      let
        payload = intentPayloads.${selectionId};
        implementationId = payload.implementation_id or null;
        implementation =
          if implementationId == null then null
          else implementations.${implementationId} or null;
      in
      assert lib.assertMsg (payload.format or null == "spaghetti-extractor-library-adoption-intent-v1")
        "library adoption ${selectionId} has the wrong format";
      assert lib.assertMsg (payload.target_id or null == targetId)
        "library adoption ${selectionId} belongs to another target";
      if (payload.mode or null) != "adopt" then null else
      assert lib.assertMsg (implementation != null)
        "library adoption ${selectionId} references an unavailable implementation";
      assert lib.assertMsg (linkedSemanticModule != null
        && catalogSearchIndex != null)
        "adopted library islands require linked semantics and a catalog";
      import ./library-island-check.nix {
        inherit pkgs pythonEnv targetId linkedSemanticModule;
        name = "${namePrefix}-${selectionId}-checked-library-island-v1";
        releaseHypotheses = releaseHypotheses;
        islandId = payload.island_id;
        adoptionIntent = intent;
        behaviorPack = implementation;
        catalogSearchIndex =
          "${catalogSearchIndex}/catalog-search-index.json";
      })
    adoptionIntents;
  nonNullCheckedIslands = lib.filterAttrs (_: value: value != null) checkedIslands;
  providerBindings = lib.mapAttrs
    (selectionId: receipt:
      let
        payload = intentPayloads.${selectionId};
        implementation = implementationInputs.${payload.implementation_id};
      in import ./library-provider-binding.nix {
        inherit pkgs pythonEnv linkedSemanticModule;
        name = "${namePrefix}-${selectionId}-library-provider-binding";
        releaseHypotheses = releaseHypotheses;
        checkedIsland = "${receipt}/checked-library-island.json";
        behaviorPack = implementation;
        catalogSearchIndex =
          "${catalogSearchIndex}/catalog-search-index.json";
      })
    nonNullCheckedIslands;
  providerSemanticSlices = lib.mapAttrs
    (selectionId: binding: import ./component-semantic-slice-v2.nix {
      inherit pkgs pythonEnv;
      namePrefix = "${namePrefix}-library-${selectionId}";
      componentId = selectionId;
      linkedSemanticModule =
        "${linkedSemanticModule}/linked-semantic-module.json";
      bindingIntent = binding.bindingIntent;
    })
    providerBindings;
  providerInputs = lib.mapAttrs
    (selectionId: binding:
      let
        payload = intentPayloads.${selectionId};
        implementation = implementationInputs.${payload.implementation_id};
      in {
        interfacePackage = binding.interfacePackage;
        bindingIntent = binding.bindingIntent;
        semanticSlice = providerSemanticSlices.${selectionId}.semanticSlice;
        sourcePackage = "${implementation}/source-package";
        behaviorPack = implementation;
        checkedIsland = binding.checkedIsland;
      })
    providerBindings;
  checks = lib.mapAttrs
    (selectionId: receipt: pkgs.runCommand
      "${namePrefix}-${selectionId}-library-adoption-check-v1"
      { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
        set -euo pipefail
        jq -e '.status == "complete"' ${receipt}/checked-library-island.json >/dev/null
        jq -e '.status == "complete" and .blockers == []' \
          ${providerBindings.${selectionId}.bindingIntent} >/dev/null
        jq -e '.format == "spaghetti-extractor-semantic-slice-v2"' \
          ${providerSemanticSlices.${selectionId}.semanticSlice} >/dev/null
        mkdir -p "$out"
        ln -s ${receipt}/checked-library-island.json "$out/checked-library-island.json"
        ln -s ${providerBindings.${selectionId}.derivation} \
          "$out/provider-binding"
        ln -s ${providerSemanticSlices.${selectionId}.derivation} \
          "$out/semantic-slice"
      '')
    nonNullCheckedIslands;
in
assert lib.assertMsg (identifier targetId) "library targetId must be an identifier";
assert lib.assertMsg (builtins.all (value: builtins.isString value && value != "")
  (builtins.attrNames implementations))
  "reusable implementation keys must be nonempty implementation IDs";
assert lib.assertMsg (builtins.all identifier (builtins.attrNames adoptionIntents))
  "library adoption keys must be identifiers";
assert lib.assertMsg (
  nonNullCheckedIslands == { }
  || linkedSemanticModule != null
) "adopted library providers require linked semantics";
{
  inherit artifactIndex catalogSearchIndex generatedCatalogLock effectiveCatalogLock targetSignatureGraph
    releaseHypotheses checkedIslands
    providerBindings providerSemanticSlices providerInputs checks;
  implementations = implementationInputs;
  adoptionIntents = intentInputs;
}
