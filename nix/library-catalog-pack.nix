# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  snapshot,
  artifacts,
  abiCatalog ? null,
  abiDeclarations ? null,
  abiDeclarationSpec ? null,
  decorationModel ? "pe32-coff-gnu-v1",
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
  abiDeclarationsInput =
    if abiDeclarations == null then null
    else if builtins.typeOf abiDeclarations == "path" then
      builtins.path {
        path = abiDeclarations;
        name = "${name}-physical-abi-declarations-v1.json";
      }
    else abiDeclarations;
  abiDeclarationSpecInput =
    if abiDeclarationSpec == null then null
    else if builtins.typeOf abiDeclarationSpec == "path" then
      builtins.path {
        path = abiDeclarationSpec;
        name = "${name}-physical-abi-declaration-spec-v1.json";
      }
    else abiDeclarationSpec;
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
  catalogPythonSource = import ./python-module-closure.nix {
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
  abiPythonSource = import ./python-module-closure.nix {
    phaseRole = "proposal";
    inherit pkgs;
    modules = [ "spaghetti_extractor.abi.catalog" ];
    name = "${name}-physical-abi-python-closure";
  };
  abiSpecPythonSource = import ./python-module-closure.nix {
    phaseRole = "proposal";
    inherit pkgs;
    modules = [ "spaghetti_extractor.abi.declaration_spec" ];
    name = "${name}-physical-abi-spec-python-closure";
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
assert lib.assertMsg (abiDeclarations == null || abiDeclarationSpec == null)
  "provide canonical ABI declarations or an authored declaration spec, not both";
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
  export PYTHONPATH=${catalogPythonSource}/src
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
  generatedAbiDeclarations =
    if abiDeclarationSpecInput == null then null else
    pkgs.runCommand "${name}-physical-abi-declarations-v1" {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export PYTHONDONTWRITEBYTECODE=1
      export PYTHONPATH=${abiSpecPythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${lib.escapeShellArg abiDeclarationSpecInput} \
        "$out/physical-abi-declarations.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.abi.declaration_spec import (
          build_declaration_set_from_spec,
      )

      build_declaration_set_from_spec(
          spec=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-physical-abi-declarations-v1" and
        .snapshot_id == ${builtins.toJSON snapshot.id}
      ' "$out/physical-abi-declarations.json" >/dev/null
    '';
  effectiveAbiDeclarations =
    if abiDeclarationsInput != null then abiDeclarationsInput
    else if generatedAbiDeclarations != null then
      "${generatedAbiDeclarations}/physical-abi-declarations.json"
    else null;
  physicalAbiPackage = pkgs.runCommand "${name}-physical-abi-catalog-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${abiPythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${package}/library-artifact-index.json \
      "$out/physical-abi-catalog.json" \
      ${lib.escapeShellArg decorationModel} \
      ${if effectiveAbiDeclarations == null then "''" else lib.escapeShellArg effectiveAbiDeclarations} <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.abi.catalog import build_physical_abi_catalog

    build_physical_abi_catalog(
        artifact_index=pathlib.Path(sys.argv[1]),
        out=pathlib.Path(sys.argv[2]),
        decoration_model=sys.argv[3],
        declarations=(pathlib.Path(sys.argv[4]) if sys.argv[4] else None),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-physical-abi-catalog-v1" and
      .catalog_id == ${builtins.toJSON name} and
      (.status == "complete" or .status == "incomplete" or .status == "violated")
    ' "$out/physical-abi-catalog.json" >/dev/null
  '';
in
package // {
  artifactIndex = "${package}/library-artifact-index.json";
  physicalAbiCatalog = "${physicalAbiPackage}/physical-abi-catalog.json";
  inherit physicalAbiPackage generatedAbiDeclarations;
  implementationPaths = lib.mapAttrs
    (id: _: "${package}/behavior-packs/${implementationDirectoryNames.${id}}")
    implementations;
}
