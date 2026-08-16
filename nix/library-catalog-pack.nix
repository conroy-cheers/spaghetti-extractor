# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  snapshot,
  artifacts,
  abiCatalog ? null,
  implementations ? { },
}:

let
  lib = pkgs.lib;
  identifier = value:
    builtins.isString value && value != ""
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  requiredSnapshotFields = [ "id" "target" ];
  requiredTargetFields = [ "abi" "architecture" "object_format" ];
  validSnapshot = builtins.isAttrs snapshot
    && builtins.attrNames snapshot == requiredSnapshotFields
    && identifier snapshot.id
    && builtins.isAttrs snapshot.target
    && builtins.attrNames snapshot.target == requiredTargetFields
    && builtins.all (field: identifier snapshot.target.${field}) requiredTargetFields;
  validArtifact = artifact:
    builtins.isAttrs artifact
    && builtins.all (field: builtins.hasAttr field artifact) [
      "id" "path" "familyId" "componentId" "abiId"
    ]
    && identifier artifact.id
    && identifier artifact.familyId
    && identifier artifact.componentId
    && identifier artifact.abiId;
  # The parser resolves artifact paths before enforcing root confinement.
  # Materialize regular immutable files instead of a symlink farm so that the
  # confinement check remains meaningful and catalog inputs cannot escape.
  artifactRoot = pkgs.runCommand "${name}-library-artifact-root" {
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    mkdir -p "$out"
    ${lib.concatMapStringsSep "\n" (artifact: ''
      cp --reflink=auto --dereference \
        ${lib.escapeShellArg artifact.path} \
        "$out/${artifact.id}"
    '') artifacts}
  '';
  declaration = pkgs.writeText "${name}-library-artifact-inputs-v2-unbound.json"
    (builtins.toJSON {
      format = "spaghetti-extractor-library-artifact-inputs-v2";
      catalog_id = name;
      inherit snapshot;
      artifacts = map (artifact: {
        inherit (artifact) id;
        path = artifact.id;
        visibility = artifact.visibility or "public";
        redistributable = artifact.redistributable or false;
        island_kind = artifact.islandKind or "linked_dependency";
        retention_model = artifact.retentionModel or "archive_member";
        provenance = artifact.provenance or { };
        library_identity = {
          family_id = artifact.familyId;
          component_id = artifact.componentId;
          release_id = artifact.releaseId or null;
          build_id = artifact.buildId or null;
          abi_id = artifact.abiId;
        };
        interface_claims = artifact.interfaceClaims or [ ];
      }) artifacts;
    });
  abiCatalogInput =
    if abiCatalog == null then null
    else if builtins.typeOf abiCatalog == "path" then
      builtins.path {
        path = abiCatalog;
        name = "${name}-library-abi-catalog-v3.json";
      }
    else abiCatalog;
  implementationInputs = lib.mapAttrs
    (id: value:
      if builtins.typeOf value == "path" then
        builtins.path {
          path = value;
          name = "${builtins.hashString "sha256" id}-library-implementation.json";
        }
      else value)
    implementations;
  implementationDirectoryNames = lib.mapAttrs
    (id: _: builtins.hashString "sha256" id)
    implementations;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "proposal";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.libraries.abi_catalog"
      "spaghetti_extractor.libraries.abi_records"
      "spaghetti_extractor.libraries.catalog"
      "spaghetti_extractor.libraries.v4_behavior_manifest"
    ];
    name = "${name}-library-catalog-python-closure";
  };
in
assert lib.assertMsg (identifier name) "library catalog name must be an identifier";
assert lib.assertMsg validSnapshot "library catalog snapshot is malformed";
assert lib.assertMsg (artifacts != [ ]) "library catalog contains no artifacts";
assert lib.assertMsg (builtins.all validArtifact artifacts)
  "library catalog artifact declaration is malformed";
assert lib.assertMsg
  (lib.length (lib.unique (map (artifact: artifact.id) artifacts)) == lib.length artifacts)
  "library catalog artifact IDs must be unique";
let
  package = pkgs.runCommand "${name}-library-catalog-pack-v3" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH=${phasePythonSource}/src
  mkdir -p "$out/behavior-packs"
  ${pythonEnv}/bin/python3 - \
    ${declaration} ${artifactRoot} "$out/library-artifact-index.json" <<'PY'
  import json
  import pathlib
  import sys
  from spaghetti_extractor.libraries.catalog import (
      bind_library_artifact_inputs,
      index_library_artifacts,
  )

  declaration = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
  index_library_artifacts(
      inputs=bind_library_artifact_inputs(declaration),
      artifact_root=pathlib.Path(sys.argv[2]),
      out=pathlib.Path(sys.argv[3]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-library-artifact-index-v2" and
    .status == "indexed" and
    (.executes_original_binary | not) and
    (.authority.can_authorize_replacement | not)
  ' "$out/library-artifact-index.json" >/dev/null
  ${lib.optionalString (abiCatalogInput != null) ''
    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg abiCatalogInput} \
      "$out/library-abi-catalog.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.libraries.abi_catalog import LIBRARY_ABI_CATALOG_CODEC_V3

    source = pathlib.Path(sys.argv[1])
    catalog = LIBRARY_ABI_CATALOG_CODEC_V3.read(source)
    if catalog.catalog_id != ${builtins.toJSON name}:
        raise SystemExit(
            f"ABI catalog ID {catalog.catalog_id!r} does not match pack "
            "${name}"
        )
    LIBRARY_ABI_CATALOG_CODEC_V3.write(pathlib.Path(sys.argv[2]), catalog)
    PY
    jq -e '
      .format == "spaghetti-extractor-library-abi-catalog-v3" and
      .catalog_id == ${builtins.toJSON name}
    ' "$out/library-abi-catalog.json" >/dev/null
  ''}
  ${lib.concatStringsSep "\n" (lib.mapAttrsToList (id: source: ''
    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg source} \
      ${lib.escapeShellArg id} <<'PY'
    import sys
    from spaghetti_extractor.libraries.v4_behavior_manifest import (
        read_library_behavior_pack_declaration_v1,
    )

    behavior_pack = read_library_behavior_pack_declaration_v1(sys.argv[1])
    if behavior_pack.implementation.implementation_id != sys.argv[2]:
        raise SystemExit("reusable implementation ID disagrees with its catalog key")
    PY
    ln -s ${lib.escapeShellArg source} \
      "$out/behavior-packs/${implementationDirectoryNames.${id}}"
  '') implementationInputs)}
  ln -s ${declaration} "$out/input-declaration.json"
  '';
in
package // {
  implementationPaths = lib.mapAttrs
    (id: _: "${package}/behavior-packs/${implementationDirectoryNames.${id}}")
    implementations;
}
