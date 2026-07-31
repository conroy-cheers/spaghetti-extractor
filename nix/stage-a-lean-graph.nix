{
  pkgs,
  prepared ? null,
  graphFile ? null,
  preparedManifest ? null,
  artifactManifest ? null,
  sourceRoot ? prepared,
  activeNodeIds ? [ ],
  prebuiltNodes ? { },
  standaloneSourceRoot ? null,
  standaloneModules ? [ ],
  standaloneModuleResources ? { },
  schedulingMode ? "dag",
  precompiledKernel ? null,
  targetNodes ? [ ],
  targetBundle ? false,
  targetAxiomAudit ? null,
  graphSmoke ? false,
  contentAddressed ? true,
  bundleContentAddressed ? contentAddressed,
}:

if schedulingMode == "closure" then
  import ./stage-a-lean-compact.nix {
    inherit
      contentAddressed
      graphFile
      pkgs
      precompiledKernel
      prepared
      preparedManifest
      sourceRoot
      targetBundle
      targetNodes
      ;
  }
else
  let
    lib = pkgs.lib;
    standalone = standaloneSourceRoot != null;
    standaloneAggregateRoot =
      if standalone then builtins.dirOf (toString standaloneSourceRoot) else null;
    standaloneMetadataSource = module: standaloneSourceRoot + "/${module}.lean";
    standaloneSource =
      module:
      builtins.toFile "stage-a-source-${module}.lean" (
        builtins.unsafeDiscardStringContext (builtins.readFile (standaloneMetadataSource module))
      );
    standaloneNestedBuildPackManifestPath =
      if standalone then standaloneSourceRoot + "/module-build-packs.json" else null;
    standaloneBuildPackManifestPath =
      if standalone && builtins.pathExists standaloneNestedBuildPackManifestPath then
        standaloneNestedBuildPackManifestPath
      else if standalone then
        standaloneAggregateRoot + "/module-build-packs.json"
      else
        null;
    standaloneBuildPacksAvailable = standalone && builtins.pathExists standaloneBuildPackManifestPath;
    standaloneBuildPackManifest =
      if standaloneBuildPacksAvailable then
        builtins.fromJSON (builtins.readFile standaloneBuildPackManifestPath)
      else
        null;
    standaloneModuleBuildPacks =
      if standaloneBuildPacksAvailable then
        standaloneBuildPackManifest.modules
      else
        builtins.listToAttrs (
          map (module: {
            name = module;
            value = module;
          }) standaloneModules
        );
    standaloneBuildPacks =
      if standaloneBuildPacksAvailable then
        standaloneBuildPackManifest.packs
      else
        builtins.listToAttrs (
          map (module: {
            name = module;
            value = [ module ];
          }) standaloneModules
        );
    standaloneImports =
      module:
      lib.unique (
        lib.filter (dependency: dependency != null) (
          map (
            line:
            let
              matched = builtins.match "^import StageA\\.([A-Za-z0-9_]+)$" line;
            in
            if matched == null then null else builtins.head matched
          ) (lib.splitString "\n" (builtins.readFile (standaloneMetadataSource module)))
        )
      );
    standaloneModuleSet = builtins.listToAttrs (
      map (module: {
        name = module;
        value = true;
      }) standaloneModules
    );
    standaloneModuleMetadata = builtins.listToAttrs (
      map (
        module:
        let
          sourceSha256 = builtins.hashFile "sha256" (standaloneMetadataSource module);
        in
        {
          name = module;
          value = {
            source = "${module}.lean";
            source_sha256 = sourceSha256;
            imports = standaloneImports module;
          };
        }
      ) standaloneModules
    );
    standaloneImportsValid = builtins.all (
      module:
      builtins.all (
        dependency: builtins.hasAttr dependency standaloneModuleSet
      ) standaloneModuleMetadata.${module}.imports
    ) standaloneModules;
    standaloneBuildPacksValid =
      !standaloneBuildPacksAvailable
      || (
        standaloneBuildPackManifest.format == "stage-a-lean-build-packs-v1"
        &&
          lib.sort builtins.lessThan (builtins.attrNames standaloneBuildPackManifest.modules)
          == lib.sort builtins.lessThan standaloneModules
        &&
          lib.sort builtins.lessThan (lib.concatLists (builtins.attrValues standaloneBuildPackManifest.packs))
          == lib.sort builtins.lessThan standaloneModules
        && builtins.all (
          module:
          let
            packId = standaloneBuildPackManifest.modules.${module};
          in
          builtins.hasAttr packId standaloneBuildPackManifest.packs
          && builtins.elem module standaloneBuildPackManifest.packs.${packId}
        ) standaloneModules
        && builtins.all (
          packId:
          let
            packModules = standaloneBuildPackManifest.packs.${packId};
            positions = builtins.listToAttrs (
              lib.imap0 (index: module: {
                name = module;
                value = index;
              }) packModules
            );
          in
          builtins.all (
            module:
            builtins.all (
              dependency:
              standaloneBuildPackManifest.modules.${dependency} != packId
              || positions.${dependency} < positions.${module}
            ) standaloneModuleMetadata.${module}.imports
          ) packModules
        ) (builtins.attrNames standaloneBuildPackManifest.packs)
      );
    standaloneGraph = {
      format = "stage-a-lean-module-graph-v1";
      lean.trust = 0;
      modules = standaloneModuleMetadata;
      nodes = map (
        packId:
        let
          packModules = standaloneBuildPacks.${packId};
          moduleResources = map (
            module:
            standaloneModuleResources.${module} or {
              resource_class = "light";
              estimated_memory_mb = 512;
            }
          ) packModules;
          resourceClasses = map (resource: resource.resource_class) moduleResources;
          resourceClass =
            if builtins.elem "high-memory" resourceClasses then
              "high-memory"
            else if builtins.elem "large-memory" resourceClasses then
              "large-memory"
            else if builtins.elem "medium" resourceClasses then
              "medium"
            else
              "light";
          dependencyModules = lib.concatMap (module: standaloneModuleMetadata.${module}.imports) packModules;
          dependencies = lib.sort builtins.lessThan (
            lib.unique (
              map (dependency: standaloneModuleBuildPacks.${dependency}) (
                lib.filter (dependency: standaloneModuleBuildPacks.${dependency} != packId) dependencyModules
              )
            )
          );
        in
        {
          id = packId;
          modules = packModules;
          inherit dependencies;
          resource_class = resourceClass;
          estimated_memory_mb = lib.foldl' (
            maximum: resource:
            if resource.estimated_memory_mb > maximum then resource.estimated_memory_mb else maximum
          ) 0 moduleResources;
          source_sha256 = builtins.hashString "sha256" (
            lib.concatMapStringsSep ":" (module: standaloneModuleMetadata.${module}.source_sha256) packModules
          );
        }
      ) (builtins.attrNames standaloneBuildPacks);
    };
    effectiveGraphFile =
      if graphFile != null then
        graphFile
      else if prepared != null then
        prepared + "/module-graph.json"
      else
        null;
    effectivePreparedManifest =
      if preparedManifest != null then
        preparedManifest
      else if prepared != null then
        prepared + "/prepared-proof.json"
      else
        null;
    effectiveArtifactManifest =
      if artifactManifest != null then
        artifactManifest
      else if prepared != null && builtins.pathExists (prepared + "/artifact-manifest.json") then
        prepared + "/artifact-manifest.json"
      else
        null;
    graph =
      if standalone then standaloneGraph else builtins.fromJSON (builtins.readFile effectiveGraphFile);
    graphV2 = graph.format == "stage-a-lean-module-graph-v2";
    checkedArtifactManifest =
      if graphV2 then builtins.fromJSON (builtins.readFile effectiveArtifactManifest) else null;
    sourcePackIds =
      if standalone then
        [ ]
      else
        lib.unique (
          lib.filter (packId: packId != null) (
            map (
              metadata: metadata.source_pack or null
            ) (builtins.attrValues graph.modules)
          )
        );
    sourcePackDataPaths = builtins.listToAttrs (
      map (
        packId: {
          name = packId;
          value = builtins.toFile
            (lib.strings.sanitizeDerivationName
              "stage-a-source-pack-${packId}.json")
            (
              builtins.unsafeDiscardStringContext (
                builtins.readFile (
                  sourceRoot + "/source-pack-data/${packId}.json"
                )
              )
            );
        }
      ) sourcePackIds
    );
    sourcePackPaths = builtins.listToAttrs (
      map (
        packId: {
          name = packId;
          value = pkgs.runCommand
            (lib.strings.sanitizeDerivationName
              "stage-a-source-pack-${packId}")
            {
              nativeBuildInputs = [ pkgs.python3 ];
              # Source packs only materialize generated text. Keeping them
              # local prevents remote Lean saturation from starving the graph
              # scheduler without moving proof computation onto this host.
              preferLocalBuild = true;
              allowSubstitutes = true;
            }
            ''
              ${pkgs.python3}/bin/python3 - \
                "${sourcePackDataPaths.${packId}}" "$out" \
                ${lib.escapeShellArg packId} <<'PY'
              import json
              import pathlib
              import re
              import sys

              source = pathlib.Path(sys.argv[1])
              out = pathlib.Path(sys.argv[2])
              expected_id = sys.argv[3]
              payload = json.loads(source.read_text(encoding="utf-8"))
              if (
                  payload.get("format") != "stage-a-lean-source-pack-v1"
                  or payload.get("id") != expected_id
                  or not isinstance(payload.get("modules"), dict)
              ):
                  raise SystemExit("invalid generated Lean source pack")
              out.mkdir(parents=True)
              for module, text in sorted(payload["modules"].items()):
                  if (
                      not isinstance(module, str)
                      or re.fullmatch(r"[A-Za-z0-9_]+", module) is None
                      or not isinstance(text, str)
                  ):
                      raise SystemExit("malformed generated Lean source module")
                  (out / f"{module}.lean").write_text(
                      text,
                      encoding="utf-8",
                  )
              PY
            '';
        }
      ) sourcePackIds
    );
    moduleSources = lib.mapAttrs (
      module: metadata:
      if standalone then
        standaloneSource module
      else if metadata ? source_pack then
        sourcePackPaths.${metadata.source_pack} + "/${module}.lean"
      else
        builtins.path {
          path = sourceRoot + "/${metadata.source}";
          name = "stage-a-${module}.lean";
        }
    ) graph.modules;

    sourceChecks =
      node:
      lib.concatMapStringsSep "\n" (
        module:
        let
          metadata = graph.modules.${module};
        in
        "${metadata.source_sha256}  ${moduleSources.${module}}"
      ) node.modules;

    nodeById = builtins.listToAttrs (
      map (node: {
        name = node.id;
        value = node;
      }) graph.nodes
    );
    nodeIds = map (node: node.id) graph.nodes;
    effectiveActiveNodeIds = if activeNodeIds == [ ] then nodeIds else activeNodeIds;
    activeNodeSet = builtins.listToAttrs (
      map (node: {
        name = node;
        value = true;
      }) effectiveActiveNodeIds
    );
    activeGraphNodes = builtins.filter (node: builtins.hasAttr node.id activeNodeSet) graph.nodes;
    assignedModules = lib.concatMap (node: node.modules) graph.nodes;
    moduleOwners = builtins.listToAttrs (
      lib.concatMap (
        node:
        map (module: {
          name = module;
          value = node.id;
        }) node.modules
      ) graph.nodes
    );
    graphNodeIdsUnique = builtins.length nodeIds == builtins.length (builtins.attrNames nodeById);
    graphModuleImportsValid = builtins.all (
      module:
      graph.modules.${module} ? imports
      && builtins.isList graph.modules.${module}.imports
      && builtins.all (
        dependency: builtins.hasAttr dependency graph.modules
      ) graph.modules.${module}.imports
    ) (builtins.attrNames graph.modules);
    graphModuleOwnershipValid =
      builtins.length assignedModules == builtins.length (builtins.attrNames moduleOwners)
      && lib.sort builtins.lessThan assignedModules == builtins.attrNames graph.modules;
    graphNodeDependenciesValid =
      graphModuleImportsValid
      && graphModuleOwnershipValid
      && builtins.all (
        node:
        let
          expected = lib.sort builtins.lessThan (
            lib.unique (
              lib.filter (dependency: dependency != node.id) (
                lib.concatMap (
                  module: map (dependency: moduleOwners.${dependency}) graph.modules.${module}.imports
                ) node.modules
              )
            )
          );
        in
        node.dependencies == expected
      ) graph.nodes;
    graphNodeResourcesValid = builtins.all (
      node:
      builtins.elem node.resource_class [
        "light"
        "medium"
        "large-memory"
        "high-memory"
      ]
      && builtins.isInt node.estimated_memory_mb
      && node.estimated_memory_mb > 0
    ) graph.nodes;
    graphNodeSemanticIdentitiesValid =
      standalone
      || builtins.all (
        node:
        builtins.isString node.semantic_id
        && builtins.stringLength node.semantic_id == 64
        && builtins.isString node.semantic_recipe_version
        && node.semantic_recipe_version == "stage-a-lean-semantic-recipe-v1"
        && builtins.isList node.dependency_semantic_ids
        &&
          node.dependency_semantic_ids
          == map (dependency: nodeById.${dependency}.semantic_id) node.dependencies
      ) graph.nodes;
    prebuiltNodePaths = lib.mapAttrs (_: entry: builtins.storePath entry.semantic_path) prebuiltNodes;
    prebuiltNodesValid = builtins.all (
      nodeId:
      let
        entry = prebuiltNodes.${nodeId};
        expected = nodeById.${nodeId};
        semanticPath = prebuiltNodePaths.${nodeId};
        interface = builtins.fromJSON (builtins.readFile (semanticPath + "/interface.json"));
      in
      builtins.hasAttr nodeId nodeById
      && !builtins.hasAttr nodeId activeNodeSet
      && builtins.isAttrs entry
      && entry.node_id == nodeId
      && entry.semantic_id == expected.semantic_id
      && builtins.isString entry.semantic_path
      && builtins.match "/nix/store/[a-z0-9]+-[^ ]+" entry.semantic_path != null
      && interface.format == "stage-a-lean-semantic-interface-v1"
      && interface.id == nodeId
      && interface.modules == expected.modules
      && interface.dependencies == expected.dependencies
      && interface.source_sha256 == expected.source_sha256
      && interface.semantic_id == expected.semantic_id
      && interface.dependency_semantic_ids == expected.dependency_semantic_ids
      && interface.semantic_recipe_version == expected.semantic_recipe_version
    ) (builtins.attrNames prebuiltNodes);
    activeDependenciesAvailable = builtins.all (
      node:
      builtins.all (
        dependency: builtins.hasAttr dependency activeNodeSet || builtins.hasAttr dependency prebuiltNodes
      ) node.dependencies
    ) activeGraphNodes;
    checkedArtifactIds =
      if graphV2 then
        map (artifact: artifact.identity.artifact_id) checkedArtifactManifest.artifacts
      else
        [ ];
    graphCheckedArtifactManifestValid =
      !graphV2
      || (
        effectiveArtifactManifest != null
        && checkedArtifactManifest.format == "stage-a-checked-artifact-manifest-v1"
        && graph.artifacts.checked_manifest.path == "artifact-manifest.json"
        && builtins.hashFile "sha256" effectiveArtifactManifest == graph.artifacts.checked_manifest.sha256
        && checkedArtifactManifest.authoritative == graph.artifacts.checked_manifest.authoritative
        && builtins.length checkedArtifactIds == builtins.length (lib.unique checkedArtifactIds)
      );
    graphNodeArtifactMetadataValid = builtins.all (
      node:
      if !graphV2 then
        true
      else
        builtins.isString node.kind
        && node.kind != ""
        && builtins.isString node.stable_key
        && node.stable_key != ""
        && builtins.isString node.checker_version
        && node.checker_version == "stage-a-checked-artifact-checkers-v1"
        && builtins.isList node.artifact_ids
        && builtins.all (artifact: builtins.elem artifact checkedArtifactIds) node.artifact_ids
    ) graph.nodes;

    nodeDrvs = lib.fix (
      self:
      builtins.listToAttrs (
        map (
          node:
          let
            dependencies = map (
              dependency:
              if builtins.hasAttr dependency prebuiltNodePaths then
                prebuiltNodePaths.${dependency}
              else
                self.${dependency}.stable
            ) node.dependencies;
            dependencyArgs = lib.escapeShellArgs (map toString dependencies);
            dependencySemanticIds =
              node.dependency_semantic_ids
                or (map (dependency: nodeById.${dependency}.source_sha256) node.dependencies);
            semanticRecipeVersion = node.semantic_recipe_version or "stage-a-lean-standalone-recipe-v1";
            semanticId =
              node.semantic_id or (builtins.hashString "sha256" (
                builtins.toJSON {
                  format = "stage-a-lean-semantic-node-id-v1";
                  recipe_version = semanticRecipeVersion;
                  modules = node.modules;
                  source_sha256 = node.source_sha256;
                  dependencies = lib.imap0 (index: dependency: {
                    node = dependency;
                    semantic_id = builtins.elemAt dependencySemanticIds index;
                  }) node.dependencies;
                }
              ));
            metadata = builtins.toJSON {
              format = "stage-a-lean-node-result-v1";
              id = node.id;
              inherit (node)
                modules
                dependencies
                source_sha256
                ;
              semantic_id = semanticId;
              dependency_semantic_ids = dependencySemanticIds;
              semantic_recipe_version = semanticRecipeVersion;
            };
            rawDrv =
              pkgs.runCommand (lib.strings.sanitizeDerivationName "stage-a-lean-${node.id}")
                (
                  {
                    outputs = [
                      "out"
                      "audit"
                    ];
                    nativeBuildInputs = [
                      pkgs.lean4
                      pkgs.python3
                      pkgs.coreutils
                      pkgs.time
                    ];
                    preferLocalBuild = false;
                    allowSubstitutes = true;
                    # Every Lean node is intentionally remote-only. Both proof
                    # builders advertise large-memory; the workstation does
                    # not, so local jobs remain limited to lightweight graph
                    # materialization and bundling.
                    requiredSystemFeatures =
                      [ "large-memory" ]
                      ++ (
                        if node.resource_class == "high-memory" then
                          [
                          "big-parallel"
                          "benchmark"
                          ]
                        else
                          lib.optionals (node.resource_class == "large-memory") [
                            "big-parallel"
                            "large-memory"
                          ]
                      );
                  }
                  // lib.optionalAttrs contentAddressed { __contentAddressed = true; }
                )
                ''
                  mkdir -p "$out/StageA" \
                    "$audit/StageA" "$audit/logs" source/StageA compiled/StageA
                  ulimit -s unlimited 2>/dev/null || true
                  cat > source-hashes <<'HASHES'
                  ${sourceChecks node}
                  HASHES
                  sha256sum --check --strict source-hashes
                  ${pkgs.python3}/bin/python3 - \
                    compiled/StageA ${dependencyArgs} <<'PY'
                  import hashlib
                  import json
                  import os
                  import pathlib
                  import sys

                  destination = pathlib.Path(sys.argv[1])
                  pending = [pathlib.Path(path) for path in sys.argv[2:]]
                  visited = set()
                  modules = {}
                  while pending:
                      dependency = pending.pop(0)
                      resolved = dependency.resolve()
                      key = str(resolved)
                      if key in visited:
                          continue
                      visited.add(key)
                      stage_a = resolved / "StageA"
                      interface = resolved / "interface.json"
                      if not stage_a.is_dir() or not interface.is_file():
                          raise SystemExit(
                              f"malformed semantic Lean dependency {resolved}"
                          )
                      payload = json.loads(interface.read_text(encoding="utf-8"))
                      if payload.get("format") != "stage-a-lean-semantic-interface-v1":
                          raise SystemExit(
                              f"invalid semantic Lean interface {interface}"
                          )
                      for output in payload.get("outputs", []):
                          module = output.get("module")
                          expected_hash = output.get("olean_sha256")
                          if not isinstance(module, str) or not isinstance(
                              expected_hash, str
                          ):
                              raise SystemExit(
                                  f"invalid semantic Lean output in {interface}"
                              )
                          olean = stage_a / f"{module}.olean"
                          if not olean.is_file():
                              raise SystemExit(
                                  f"missing semantic Lean module {olean}"
                              )
                          actual_hash = hashlib.sha256(olean.read_bytes()).hexdigest()
                          if actual_hash != expected_hash:
                              raise SystemExit(
                                  f"semantic Lean module hash mismatch for {olean}"
                              )
                          prior = modules.get(module)
                          if prior is not None and prior != olean.resolve():
                              raise SystemExit(
                                  f"conflicting semantic Lean module {module}"
                              )
                          modules[module] = olean.resolve()
                      direct = (
                          resolved
                          / "nix-support"
                          / "stage-a-direct-dependencies"
                      )
                      if direct.is_file():
                          for line in direct.read_text(encoding="utf-8").splitlines():
                              if line:
                                  pending.append(pathlib.Path(line))
                  for module, source in sorted(modules.items()):
                      target = destination / f"{module}.olean"
                      target.parent.mkdir(parents=True, exist_ok=True)
                      os.symlink(source, target)
                  PY
                  export LEAN_PATH="$PWD/compiled"
                  export LC_ALL=C
                  ${lib.concatMapStringsSep "\n" (
                    module: ''cp "${moduleSources.${module}}" "source/StageA/${module}.lean"''
                  ) node.modules}
                  ${
                    if builtins.length node.modules == 1 then
                      let
                        module = builtins.head node.modules;
                        leanJobs =
                          if
                            builtins.elem node.resource_class [
                              "large-memory"
                              "high-memory"
                            ]
                          then
                            "1"
                          else
                            "2";
                      in
                      ''
                        ${pkgs.time}/bin/time -v \
                          -o "$audit/logs/${module}.resource" \
                          ${pkgs.lean4}/bin/lean -j ${leanJobs} --trust=0 \
                          -R source \
                          -o "compiled/StageA/${module}.olean" \
                          "source/StageA/${module}.lean" \
                          > >(tee "$audit/logs/${module}.stdout") \
                          2> >(tee "$audit/logs/${module}.stderr" >&2)
                      ''
                    else
                      ''
                        # Stable build packs may contain internal imports in checked
                        # topological order. Compile sequentially so Nix's node-level
                        # scheduler remains the sole owner of memory concurrency.
                        for module in ${lib.escapeShellArgs node.modules}; do
                            ${pkgs.time}/bin/time -v \
                              -o "$audit/logs/$module.resource" \
                              ${pkgs.lean4}/bin/lean -j 1 --trust=0 \
                              -R source \
                              -o "compiled/StageA/$module.olean" \
                              "source/StageA/$module.lean" \
                              > >(tee "$audit/logs/$module.stdout") \
                              2> >(tee "$audit/logs/$module.stderr" >&2)
                        done
                      ''
                  }
                  ${lib.concatMapStringsSep "\n" (module: ''
                    cp "compiled/StageA/${module}.olean" "$out/StageA/${module}.olean"
                  '') node.modules}
                  ${lib.concatMapStringsSep "\n" (module: ''
                    cp "source/StageA/${module}.lean" "$audit/StageA/${module}.lean"
                  '') node.modules}
                  cat > "$audit/module-result.json" <<'JSON'
                  ${metadata}
                  JSON
                  ${pkgs.python3}/bin/python3 - \
                    "$audit/module-result.json" "$out/interface.json" \
                    "$out/StageA" "$audit/logs" ${dependencyArgs} <<'PY'
                  import hashlib
                  import json
                  import pathlib
                  import re
                  import sys

                  result_path = pathlib.Path(sys.argv[1])
                  interface_path = pathlib.Path(sys.argv[2])
                  stage_a = pathlib.Path(sys.argv[3])
                  logs = pathlib.Path(sys.argv[4])
                  direct_dependencies = [
                      pathlib.Path(path) for path in sys.argv[5:]
                  ]
                  payload = json.loads(result_path.read_text(encoding="utf-8"))
                  dependency_semantic_ids = [
                      json.loads(
                          (dependency / "interface.json").read_text(encoding="utf-8")
                      ).get("semantic_id")
                      for dependency in direct_dependencies
                  ]
                  if (
                      payload["semantic_recipe_version"]
                      != "stage-a-lean-standalone-recipe-v1"
                  ):
                      if dependency_semantic_ids != payload[
                          "dependency_semantic_ids"
                      ]:
                          raise SystemExit(
                              "semantic dependency identities do not match the graph"
                          )
                      semantic_identity = hashlib.sha256(
                          json.dumps(
                              {
                                  "format": "stage-a-lean-semantic-node-id-v1",
                                  "recipe_version": payload[
                                      "semantic_recipe_version"
                                  ],
                                  "modules": payload["modules"],
                                  "source_sha256": payload["source_sha256"],
                                  "dependencies": [
                                      {
                                          "node": dependency,
                                          "semantic_id": semantic_id,
                                      }
                                      for dependency, semantic_id in zip(
                                          payload["dependencies"],
                                          dependency_semantic_ids,
                                          strict=True,
                                      )
                                  ],
                              },
                              separators=(",", ":"),
                              sort_keys=True,
                          ).encode("ascii")
                      ).hexdigest()
                      if semantic_identity != payload["semantic_id"]:
                          raise SystemExit(
                              "semantic node identity does not match checked inputs"
                          )
                  outputs = []
                  for path in sorted(stage_a.glob("*.olean")):
                      module = path.stem
                      source = (
                          result_path.parent
                          / "StageA"
                          / f"{module}.lean"
                      ).read_text(encoding="utf-8")
                      stdout_path = logs / f"{module}.stdout"
                      stderr_path = logs / f"{module}.stderr"
                      resource_path = logs / f"{module}.resource"
                      combined = "\n".join((
                          stdout_path.read_text(encoding="utf-8"),
                          stderr_path.read_text(encoding="utf-8"),
                      ))
                      requested = re.findall(
                          r"(?m)^\s*#print\s+axioms\s+([A-Za-z0-9_'.]+)\s*$", source
                      )
                      parsed = {}
                      for declaration, axioms in re.findall(
                          r"'([^']+)' depends on axioms:\s*\[(.*?)\]",
                          combined,
                          re.DOTALL,
                      ):
                          parsed[declaration] = sorted({
                              item.strip()
                              for item in axioms.replace("\n", " ").split(",")
                              if item.strip()
                          })
                      for declaration in re.findall(
                          r"'([^']+)' does not depend on any axioms", combined
                      ):
                          parsed[declaration] = []
                      matched = {
                          request: next((
                              axioms for declaration, axioms in parsed.items()
                              if declaration == request or declaration.endswith(f".{request}")
                          ), None)
                          for request in requested
                      }
                      resource_usage = None
                      if resource_path.is_file():
                          fields = {}
                          for line in resource_path.read_text(encoding="utf-8").splitlines():
                              parts = line.strip().rsplit(": ", 1)
                              if len(parts) == 2:
                                  key, value = parts
                                  fields[key] = value.strip()
                          resource_usage = {
                              "elapsed_wall_clock": fields.get(
                                  "Elapsed (wall clock) time (h:mm:ss or m:ss)"
                              ),
                              "user_seconds": float(fields["User time (seconds)"]),
                              "system_seconds": float(fields["System time (seconds)"]),
                              "maximum_resident_kib": int(
                                  fields["Maximum resident set size (kbytes)"]
                              ),
                              "log": f"logs/{module}.resource",
                              "log_sha256": hashlib.sha256(
                                  resource_path.read_bytes()
                              ).hexdigest(),
                          }
                      outputs.append({
                          "module": module,
                          "olean_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "olean_bytes": path.stat().st_size,
                          "compile_stdout": f"logs/{module}.stdout",
                          "compile_stderr": f"logs/{module}.stderr",
                          "compile_stdout_sha256": hashlib.sha256(
                              stdout_path.read_bytes()
                          ).hexdigest(),
                          "compile_stderr_sha256": hashlib.sha256(
                              stderr_path.read_bytes()
                          ).hexdigest(),
                          "resource_usage": resource_usage,
                          "axiom_audit": {
                              "requested": requested,
                              "inventories": matched,
                              "complete": all(value is not None for value in matched.values()),
                          },
                      })
                  payload["outputs"] = outputs
                  result_path.write_text(
                      json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8",
                  )
                  interface = {
                      "format": "stage-a-lean-semantic-interface-v1",
                      "id": payload["id"],
                      "modules": payload["modules"],
                      "dependencies": payload["dependencies"],
                      "source_sha256": payload["source_sha256"],
                      "semantic_id": payload["semantic_id"],
                      "dependency_semantic_ids": payload[
                          "dependency_semantic_ids"
                      ],
                      "semantic_recipe_version": payload[
                          "semantic_recipe_version"
                      ],
                      "outputs": [
                          {
                              "module": output["module"],
                              "olean_bytes": output["olean_bytes"],
                              "olean_sha256": output["olean_sha256"],
                          }
                          for output in outputs
                      ],
                  }
                  interface_path.write_text(
                      json.dumps(interface, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8",
                  )
                  PY
                '';
            stableDrv =
              pkgs.runCommand
                (lib.strings.sanitizeDerivationName
                  "stage-a-lean-${node.id}-stable")
                {
                  outputs = [
                    "out"
                    "audit"
                  ];
                  nativeBuildInputs = [ pkgs.coreutils ];
                  preferLocalBuild = false;
                  allowSubstitutes = true;
                }
                ''
                  mkdir -p "$out/nix-support" "$audit"
                  ln -s "${rawDrv.out}/StageA" "$out/StageA"
                  ln -s "${rawDrv.out}/interface.json" "$out/interface.json"
                  : > "$out/nix-support/stage-a-direct-dependencies"
                  for dependency in ${dependencyArgs}; do
                    printf '%s\n' "$dependency" \
                      >> "$out/nix-support/stage-a-direct-dependencies"
                  done
                  ln -s "${rawDrv.audit}/StageA" "$audit/StageA"
                  ln -s "${rawDrv.audit}/logs" "$audit/logs"
                  ln -s "${rawDrv.audit}/module-result.json" \
                    "$audit/module-result.json"
                '';
          in
          {
            name = node.id;
            value = {
              out = rawDrv.out;
              audit = rawDrv.audit;
              stable = stableDrv.out;
              stableAudit = stableDrv.audit;
            };
          }
        ) activeGraphNodes
      )
    );

    rootNode = nodeById.${graph.final_node};
    rootSemantic = nodeDrvs.${graph.final_node}.stable;
    selectedAuditTheorem = graph.expected_final_theorem;
    linkedAcceptanceTheorem =
      "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked";
    mixedChunkedAcceptanceTheorem =
      "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentMixedChunked";
    linkedAcceptanceProfile = "linked-raw-pe32";
    mixedChunkedAcceptanceProfile = "mixed-native-pe32-chunked-closed";
    selectedAuthorityProfile =
      graph.acceptance.authority_profile or (
        if selectedAuditTheorem == linkedAcceptanceTheorem then
          linkedAcceptanceProfile
        else
          null
      );
    acceptanceNodeSteps = graph.acceptance.node_steps or null;
    acceptanceNodeStepsValid =
      builtins.isList acceptanceNodeSteps
      && builtins.all (
        step: builtins.isAttrs step && step ? kind && builtins.isString step.kind
      ) acceptanceNodeSteps;
    parameterizedEnvironment =
      acceptanceNodeStepsValid
      && builtins.any (
        step:
        builtins.elem step.kind [
          "external_call"
          "external_protocol"
          "external_jump"
          "external_terminate"
        ]
      ) acceptanceNodeSteps;
    parameterizedProtocolEnvironment =
      acceptanceNodeStepsValid
      && builtins.any (step: step.kind == "external_protocol") acceptanceNodeSteps;
    linkedCanonicalResult = originalProgram: candidateProgram: ''
      PE32RawProgramsLinkedObservationallyEquivalent staticProofContext
        relationalProductGraph productInvariantTable
        relationalProductReachabilityEvidence linkedProductControlProfile consoleLaunch
        ${originalProgram} ${candidateProgram}
    '';
    linkedCanonicalType =
      if parameterizedProtocolEnvironment then
        ''
          forall (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
            (originalProtocolEnvironment candidateProtocolEnvironment :
              WorldExternalProtocolEnvironment),
            AcceptanceExternalEnvironmentsRefine
                originalEnvironment candidateEnvironment ->
              LinkedWorldExternalProtocolEnvironmentsRefine staticProofContext
                  relationalProductGraph productInvariantTable
                  relationalProductReachabilityEvidence linkedProductControlProfile
                  protocolCallbackTargets externalCallSites
                  originalProtocolEnvironment candidateProtocolEnvironment ->
                ${linkedCanonicalResult "(originalWorldProgram originalEnvironment originalProtocolEnvironment)" "(candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)"}
        ''
      else if parameterizedEnvironment then
        ''
          forall (originalEnvironment candidateEnvironment : WorldExternalEnvironment),
            AcceptanceExternalEnvironmentsRefine
                originalEnvironment candidateEnvironment ->
              ${linkedCanonicalResult "(originalWorldProgram originalEnvironment)" "(candidateWorldProgram candidateEnvironment)"}
        ''
      else
        linkedCanonicalResult "originalWorldProgram" "candidateWorldProgram";
    mixedChunkedCanonicalType = ''
      StageA.Relational.InterpreterMixedProfile.CanonicalMixedWorldProgramsChunkObservationallyEquivalentFamily
        StageA.GeneratedRelational.candidatePE32CanonicalMixedRelationFamily
    '';
    canonicalAuditType =
      if
        selectedAuditTheorem == linkedAcceptanceTheorem
        && selectedAuthorityProfile == linkedAcceptanceProfile
      then
        linkedCanonicalType
      else if
        selectedAuditTheorem == mixedChunkedAcceptanceTheorem
        && selectedAuthorityProfile == mixedChunkedAcceptanceProfile
      then
        mixedChunkedCanonicalType
      else
        throw "Stage A final audit requires an exact authoritative theorem profile";
    canonicalAuditProfile =
      if selectedAuditTheorem == linkedAcceptanceTheorem then
        linkedAcceptanceProfile
        + (
          if parameterizedProtocolEnvironment then
            "-stateful-protocol"
          else if parameterizedEnvironment then
            "-external-environment"
          else
            "-closed"
        )
      else
        mixedChunkedAcceptanceProfile;
    auditSource = pkgs.writeText "StageARelationalAudit.lean" ''
      import StageA.${graph.root_module}

      namespace StageA.FinalTheoremAudit

      open StageA.Formal StageA.Relational StageA.GeneratedRelational

      /-- The final audit is a proof term at the canonical whole-program type.
      Merely finding a declaration with the expected public name is insufficient. -/
      theorem typedFinalTheorem :
          ${canonicalAuditType} :=
        ${selectedAuditTheorem}

      #check ${selectedAuditTheorem}
      #check typedFinalTheorem
      #print axioms typedFinalTheorem

      end StageA.FinalTheoremAudit
    '';
    approvedAxioms = builtins.toJSON graph.approved_axioms;
    selectedTargetNodes = lib.unique (
      map (
        requested:
        if builtins.hasAttr requested nodeById then
          requested
        else if standalone && builtins.hasAttr requested standaloneModuleBuildPacks then
          standaloneModuleBuildPacks.${requested}
        else if builtins.hasAttr requested moduleOwners then
          moduleOwners.${requested}
        else
          requested
      ) targetNodes
    );
    selectedTargetClosureNodes = lib.sort builtins.lessThan (
      map (entry: entry.key) (
        builtins.genericClosure {
          startSet = map (node: { key = node; }) selectedTargetNodes;
          operator =
            entry:
            if builtins.hasAttr entry.key nodeById then
              map (dependency: { key = dependency; }) nodeById.${entry.key}.dependencies
            else
              [ ];
        }
      )
    );
    targetAxiomAuditValid =
      targetAxiomAudit == null
      || (
        builtins.isAttrs targetAxiomAudit
        && targetAxiomAudit ? module
        && builtins.isString targetAxiomAudit.module
        && targetAxiomAudit ? declaration
        && builtins.isString targetAxiomAudit.declaration
        && targetAxiomAudit ? approved_axioms
        && builtins.isList targetAxiomAudit.approved_axioms
        && builtins.all builtins.isString targetAxiomAudit.approved_axioms
        &&
          builtins.length targetAxiomAudit.approved_axioms
          == builtins.length (lib.unique targetAxiomAudit.approved_axioms)
      );
    targetAxiomAuditJson = builtins.toJSON targetAxiomAudit;
    linkedAcceptance = graph.acceptance.linked_acceptance or null;
    mixedChunkedAcceptance =
      graph.acceptance.mixed_chunked_acceptance or null;
    linkedAcceptanceReady =
      acceptanceNodeStepsValid
      && graph.acceptance.status == "ready"
      && graph.acceptance.required_theorem == selectedAuditTheorem
      && graph.acceptance.theorem == selectedAuditTheorem
      && linkedAcceptance != null
      && linkedAcceptance.status == "ready"
      && linkedAcceptance.theorem == selectedAuditTheorem
      && selectedAuditTheorem == linkedAcceptanceTheorem
      && selectedAuthorityProfile == linkedAcceptanceProfile;
    mixedChunkedAcceptanceReady =
      acceptanceNodeStepsValid
      && graph.acceptance.status == "ready"
      && graph.acceptance.required_theorem == selectedAuditTheorem
      && graph.acceptance.theorem == selectedAuditTheorem
      && mixedChunkedAcceptance != null
      && mixedChunkedAcceptance.status == "ready"
      && mixedChunkedAcceptance.theorem == selectedAuditTheorem
      && mixedChunkedAcceptance.profile == mixedChunkedAcceptanceProfile
      && selectedAuditTheorem == mixedChunkedAcceptanceTheorem
      && selectedAuthorityProfile == mixedChunkedAcceptanceProfile;
    acceptanceReady =
      linkedAcceptanceReady || mixedChunkedAcceptanceReady;
    selectedNodeResults = map (
      node:
      let
        semantic = nodeDrvs.${node}.stable;
        audit = nodeDrvs.${node}.stableAudit;
      in
      pkgs.runCommand (lib.strings.sanitizeDerivationName "stage-a-lean-${node}-detached")
        (
          {
            nativeBuildInputs = [ pkgs.coreutils ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          // lib.optionalAttrs contentAddressed { __contentAddressed = true; }
        )
        ''
          mkdir -p "$out/StageA" "$out/logs"
          ln -s "${semantic}" "$out/proof-node-root"
          for source in "${semantic}"/StageA/*.olean "${audit}"/StageA/*.lean; do
            ln -s "$source" "$out/StageA/$(basename "$source")"
          done
          for source in "${audit}"/logs/*; do
            ln -s "$source" "$out/logs/$(basename "$source")"
          done
          cp "${audit}/module-result.json" "$out/module-result.json"
        ''
    ) selectedTargetNodes;
    selectedTargetBundle =
      pkgs.runCommand "stage-a-lean-target-bundle"
        (
          {
            nativeBuildInputs = [
              pkgs.lean4
              pkgs.python3
              pkgs.coreutils
            ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          // lib.optionalAttrs bundleContentAddressed { __contentAddressed = true; }
        )
        ''
          mkdir -p "$out/StageA" "$out/logs" "$out/node-results" \
            "$out/proof-node-roots"
          ${lib.concatMapStringsSep "\n" (
            entry:
            let
              node = entry.value;
              index = entry.index;
              semantic = nodeDrvs.${node}.stable;
            in
            ''
              ln -s "${semantic}" "$out/proof-node-roots/${toString index}"
            ''
          ) (lib.imap0 (index: value: { inherit index value; }) selectedTargetNodes)}
          ${lib.concatMapStringsSep "\n" (
            entry:
            let
              node = entry.value;
              index = entry.index;
              audit = nodeDrvs.${node}.stableAudit;
              resultName = toString index;
            in
            ''
              cp "${audit}/module-result.json" \
                "$out/node-results/${resultName}.json"
              for source in "${audit}"/StageA/*.lean; do
                destination="$out/StageA/$(basename "$source")"
                if [ -e "$destination" ] \
                    && [ "$(readlink -f "$destination")" \
                      != "$(readlink -f "$source")" ]; then
                  echo "conflicting target-bundle module: $(basename "$source")" >&2
                  exit 1
                fi
                if [ ! -e "$destination" ]; then
                  ln -s "$source" "$destination"
                fi
              done
              for source in "${audit}"/logs/*; do
                destination="$out/logs/$(basename "$source")"
                if [ -e "$destination" ] \
                    && [ "$(readlink -f "$destination")" \
                      != "$(readlink -f "$source")" ]; then
                  echo "conflicting target-bundle log: $(basename "$source")" >&2
                  exit 1
                fi
                if [ ! -e "$destination" ]; then
                  ln -s "$source" "$destination"
                fi
              done
            ''
          ) (lib.imap0 (index: value: { inherit index value; }) selectedTargetNodes)}
          lean_version="$(${pkgs.lean4}/bin/lean --version | head -n 1)"
          ${pkgs.python3}/bin/python3 - \
            "$out/proof-node-roots" "$out/StageA" \
            "$out/node-results" "$out/bundle.json" "$lean_version" \
            ${lib.escapeShellArg targetAxiomAuditJson} "$out/axiom-audit.json" \
            ${lib.escapeShellArg (builtins.toJSON selectedTargetNodes)} <<'PY'
          import hashlib
          import json
          import os
          import pathlib
          import sys

          roots = pathlib.Path(sys.argv[1])
          module_overlay = pathlib.Path(sys.argv[2])
          source = pathlib.Path(sys.argv[3])
          pending = sorted(roots.iterdir())
          visited = set()
          closure_ids = []
          modules = {}
          while pending:
              dependency = pending.pop(0).resolve()
              key = str(dependency)
              if key in visited:
                  continue
              visited.add(key)
              stage_a = dependency / "StageA"
              interface_path = dependency / "interface.json"
              if not stage_a.is_dir() or not interface_path.is_file():
                  raise SystemExit(
                      f"malformed semantic Lean dependency {dependency}"
                  )
              interface = json.loads(
                  interface_path.read_text(encoding="utf-8")
              )
              if interface.get("format") != "stage-a-lean-semantic-interface-v1":
                  raise SystemExit(
                      f"unsupported semantic Lean interface {interface_path}"
                  )
              node_id = interface.get("id")
              if not isinstance(node_id, str) or not node_id:
                  raise SystemExit(
                      f"semantic Lean interface omits its node id: {interface_path}"
                  )
              closure_ids.append(node_id)
              outputs = interface.get("outputs")
              if not isinstance(outputs, list):
                  raise SystemExit(
                      f"semantic Lean interface omits outputs: {interface_path}"
                  )
              for output in outputs:
                  module = output.get("module")
                  olean = stage_a / f"{module}.olean"
                  if (
                      not isinstance(module, str)
                      or not module
                      or not olean.is_file()
                      or output.get("olean_bytes") != olean.stat().st_size
                      or output.get("olean_sha256")
                          != hashlib.sha256(olean.read_bytes()).hexdigest()
                  ):
                      raise SystemExit(
                          f"semantic Lean interface output mismatch: {interface_path}"
                      )
                  prior = modules.get(module)
                  resolved = olean.resolve()
                  if prior is not None and prior != resolved:
                      raise SystemExit(
                          f"conflicting target-bundle module: {module}"
                      )
                  modules[module] = resolved
              direct_path = (
                  dependency
                  / "nix-support"
                  / "stage-a-direct-dependencies"
              )
              direct_dependencies = (
                  direct_path.read_text(encoding="utf-8").splitlines()
                  if direct_path.is_file()
                  else []
              )
              if len(direct_dependencies) != len(set(direct_dependencies)):
                  raise SystemExit(
                      f"duplicate direct semantic dependencies: {dependency}"
                  )
              pending.extend(
                  pathlib.Path(path)
                  for path in direct_dependencies
                  if path
              )
          if len(closure_ids) != len(set(closure_ids)):
              raise SystemExit("target bundle closure has duplicate node identities")
          for module, olean in sorted(modules.items()):
              os.symlink(olean, module_overlay / f"{module}.olean")

          nodes = [
              json.loads(path.read_text(encoding="utf-8"))
              for path in sorted(source.glob("*.json"))
          ]
          node_ids = [node.get("id") for node in nodes]
          if len(node_ids) != len(set(node_ids)):
              raise SystemExit("target bundle contains duplicate node provenance")
          target_nodes = json.loads(sys.argv[8])
          if set(node_ids) != set(target_nodes):
              raise SystemExit("target bundle provenance does not match target nodes")
          if not set(target_nodes).issubset(closure_ids):
              raise SystemExit("target bundle roots are absent from semantic closure")
          audit_config = json.loads(sys.argv[6])
          audit = None
          if audit_config is not None:
              matching_outputs = [
                  output
                  for node in nodes
                  for output in node.get("outputs", [])
                  if output.get("module") == audit_config["module"]
              ]
              if len(matching_outputs) != 1:
                  raise SystemExit(
                      "target axiom audit module is absent or ambiguous"
                  )
              declaration = audit_config["declaration"]
              inventory = matching_outputs[0].get("axiom_audit", {})
              inventories = inventory.get("inventories", {})
              observed = inventories.get(declaration)
              if observed is None:
                  local_declaration = declaration.rsplit(".", 1)[-1]
                  matching_declarations = [
                      value
                      for name, value in inventories.items()
                      if name == local_declaration
                      or name.endswith(f".{local_declaration}")
                  ]
                  if len(matching_declarations) > 1:
                      raise SystemExit(
                          "target axiom audit declaration is ambiguous"
                      )
                  if matching_declarations:
                      observed = matching_declarations[0]
              if observed is None:
                  raise SystemExit(
                      "target axiom audit declaration was not emitted by Lean"
                  )
              approved = audit_config["approved_axioms"]
              unexpected = sorted(set(observed) - set(approved))
              audit = {
                  "format": "stage-a-lean-target-axiom-audit-v1",
                  "status": "checked" if not unexpected else "rejected",
                  "module": audit_config["module"],
                  "declaration": declaration,
                  "lean_trust": 0,
                  "approved_axioms": approved,
                  "observed_axioms": observed,
                  "unexpected_axioms": unexpected,
              }
              pathlib.Path(sys.argv[7]).write_text(
                  json.dumps(audit, indent=2, sort_keys=True) + "\n",
                  encoding="utf-8",
              )
              if unexpected:
                  raise SystemExit("target theorem depends on unapproved axioms")
          pathlib.Path(sys.argv[4]).write_text(
              json.dumps({
                  "format": "stage-a-lean-target-bundle-v2",
                  "lean_trust": 0,
                  "lean_version": sys.argv[5],
                  "axiom_audit": audit,
                  "target_nodes": target_nodes,
                  "closure_nodes": sorted(closure_ids),
                  "nodes": nodes,
              }, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
          PY
        '';
    graphSmokeMetadata = {
      format = "stage-a-lean-graph-smoke-v1";
      status = "ready";
      lean_trust = graph.lean.trust;
      graph_sha256 = builtins.hashString "sha256" (builtins.toJSON graph);
      content_addressed = contentAddressed;
      bundle_content_addressed = bundleContentAddressed;
      module_count = builtins.length (builtins.attrNames graph.modules);
      node_count = builtins.length graph.nodes;
      target_nodes = selectedTargetNodes;
      modules = builtins.attrNames graph.modules;
      nodes = map (node: {
        inherit (node)
          id
          modules
          dependencies
          resource_class
          estimated_memory_mb
          ;
      }) graph.nodes;
    };
    graphSmokeResult =
      pkgs.runCommand "stage-a-lean-graph-smoke"
        {
          preferLocalBuild = true;
          allowSubstitutes = true;
          passthru.graphManifest = graphSmokeMetadata;
        }
        ''
          mkdir -p "$out"
          cat > "$out/graph-smoke.json" <<'JSON'
          ${builtins.toJSON graphSmokeMetadata}
          JSON
        '';
  in
  assert builtins.elem graph.format [
    "stage-a-lean-module-graph-v1"
    "stage-a-lean-module-graph-v2"
  ];
  assert graph.lean.trust == 0;
  assert builtins.length graph.nodes > 0;
  assert graphNodeIdsUnique;
  assert graphModuleImportsValid;
  assert graphModuleOwnershipValid;
  assert graphNodeDependenciesValid;
  assert graphNodeResourcesValid;
  assert graphNodeSemanticIdentitiesValid;
  assert
    builtins.length effectiveActiveNodeIds == builtins.length (lib.unique effectiveActiveNodeIds);
  assert builtins.all (node: builtins.hasAttr node nodeById) effectiveActiveNodeIds;
  assert prebuiltNodesValid;
  assert activeDependenciesAvailable;
  assert graphCheckedArtifactManifestValid;
  assert graphNodeArtifactMetadataValid;
  assert !standalone || (standaloneModules != [ ] && standaloneImportsValid);
  assert standaloneBuildPacksValid;
  assert
    !standalone
    || (prepared == null && graphFile == null && preparedManifest == null && artifactManifest == null);
  assert
    !standalone
    || builtins.length standaloneModules == builtins.length (builtins.attrNames standaloneModuleSet);
  assert standalone || (effectiveGraphFile != null && sourceRoot != null);
  assert builtins.length selectedTargetNodes == builtins.length (lib.unique selectedTargetNodes);
  assert targetAxiomAuditValid;
  assert targetAxiomAudit == null || targetBundle;
  assert builtins.all (node: builtins.hasAttr node nodeDrvs) selectedTargetNodes;
  assert graphSmoke || selectedTargetNodes != [ ] || acceptanceReady;
  assert selectedTargetNodes != [ ] || effectivePreparedManifest != null;
  if graphSmoke then
    graphSmokeResult
  else if selectedTargetNodes != [ ] then
    if targetBundle then selectedTargetBundle else selectedNodeResults
  else
    pkgs.runCommand "stage-a-relational-proof-audit"
      (
        {
          outputs = [
            "out"
            "verdict"
          ];
          nativeBuildInputs = [
            pkgs.lean4
            pkgs.python3
            pkgs.coreutils
          ];
          preferLocalBuild = false;
          allowSubstitutes = true;
          requiredSystemFeatures = [ "large-memory" ];
        }
        // lib.optionalAttrs contentAddressed { __contentAddressed = true; }
      )
      ''
        mkdir -p "$out/proof-node-roots" "$verdict" final-lean-path/StageA
        ulimit -s unlimited 2>/dev/null || true
        ${pkgs.python3}/bin/python3 - \
          "${rootSemantic}" "$out/proof-node-roots" \
          final-lean-path/StageA "$out/node-provenance.json" \
          "$out/dependency-view.json" <<'PY'
        import hashlib
        import json
        import os
        import pathlib
        import sys

        root = pathlib.Path(sys.argv[1])
        roots = pathlib.Path(sys.argv[2])
        module_overlay = pathlib.Path(sys.argv[3])
        provenance_path = pathlib.Path(sys.argv[4])
        dependency_view_path = pathlib.Path(sys.argv[5])
        pending = [root]
        ordered = []
        visited = set()
        modules = {}
        interfaces = []
        while pending:
            dependency = pending.pop(0).resolve()
            key = str(dependency)
            if key in visited:
                continue
            visited.add(key)
            stage_a = dependency / "StageA"
            interface_path = dependency / "interface.json"
            if not stage_a.is_dir() or not interface_path.is_file():
                raise SystemExit(
                    f"malformed semantic Lean dependency {dependency}"
                )
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            if interface.get("format") != "stage-a-lean-semantic-interface-v1":
                raise SystemExit(
                    f"unsupported semantic Lean interface {interface_path}"
                )
            declared_outputs = interface.get("outputs")
            if not isinstance(declared_outputs, list):
                raise SystemExit(
                    f"semantic Lean interface omits outputs: {interface_path}"
                )
            for output in declared_outputs:
                module = output.get("module")
                olean = stage_a / f"{module}.olean"
                if (
                    not isinstance(module, str)
                    or not olean.is_file()
                    or output.get("olean_bytes") != olean.stat().st_size
                    or output.get("olean_sha256")
                        != hashlib.sha256(olean.read_bytes()).hexdigest()
                ):
                    raise SystemExit(
                        f"semantic Lean interface output mismatch: {interface_path}"
                    )
                prior = modules.get(module)
                if prior is not None and prior != olean.resolve():
                    raise SystemExit(
                        f"conflicting semantic Lean module StageA.{module}"
                    )
                modules[module] = olean.resolve()
            ordered.append(dependency)
            interfaces.append(interface)
            direct_path = (
                dependency
                / "nix-support"
                / "stage-a-direct-dependencies"
            )
            direct_dependencies = (
                direct_path.read_text(encoding="utf-8").splitlines()
                if direct_path.is_file()
                else []
            )
            if len(direct_dependencies) != len(set(direct_dependencies)):
                raise SystemExit(
                    f"duplicate direct semantic dependencies: {dependency}"
                )
            pending.extend(
                pathlib.Path(path)
                for path in direct_dependencies
                if path
            )

        for module, source in sorted(modules.items()):
            target = module_overlay / f"{module}.olean"
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(source, target)
        for index, dependency in enumerate(ordered):
            os.symlink(dependency, roots / f"{index:06d}")
        node_ids = [interface.get("id") for interface in interfaces]
        if (
            any(not isinstance(node_id, str) or not node_id for node_id in node_ids)
            or len(node_ids) != len(set(node_ids))
        ):
            raise SystemExit("semantic Lean closure has invalid node identities")
        provenance_path.write_text(
            json.dumps({
                "format": "stage-a-lean-node-provenance-v1",
                "nodes": interfaces,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        dependency_view_path.write_text(
            json.dumps({
                "format": "stage-a-lean-root-dependency-view-v2",
                "archive_bytes": 0,
                "materialized_oleans": 0,
                "node_count": len(interfaces) - 1,
                "reference_count": len(interfaces),
                "root_node": interfaces[0]["id"],
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
        export LEAN_PATH="$PWD/final-lean-path"
        cp ${auditSource} StageARelationalAudit.lean
        ${pkgs.lean4}/bin/lean -j 2 --trust=0 \
          -o "$out/StageARelationalAudit.olean" \
          StageARelationalAudit.lean \
          > >(tee "$out/lean.stdout") \
          2> >(tee "$out/lean.stderr" >&2)

        EXPECTED_THEOREM=${lib.escapeShellArg selectedAuditTheorem} \
        CANONICAL_PROPOSITION_PROFILE=${lib.escapeShellArg canonicalAuditProfile} \
        APPROVED_AXIOMS=${lib.escapeShellArg approvedAxioms} \
          ${pkgs.python3}/bin/python3 - \
            "$out/lean.stdout" "$out/audit.json" <<'PY'
        import json
        import os
        import pathlib
        import re
        import sys

        stdout = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        theorem = os.environ["EXPECTED_THEOREM"]
        canonical_profile = os.environ["CANONICAL_PROPOSITION_PROFILE"]
        approved = json.loads(os.environ["APPROVED_AXIOMS"])
        typed_witness = "StageA.FinalTheoremAudit.typedFinalTheorem"
        match = re.search(
            rf"'{re.escape(typed_witness)}' depends on axioms:\s*\[(.*?)\]",
            stdout,
            re.DOTALL,
        )
        if match:
            observed = [item.strip() for item in match.group(1).split(",") if item.strip()]
        elif f"'{typed_witness}' does not depend on any axioms" in stdout:
            observed = []
        else:
            raise SystemExit("Lean typed final-theorem audit did not emit an axiom inventory")
        unexpected = sorted(set(observed) - set(approved))
        payload = {
            "format": "stage-a-relational-lean-audit-v1",
            "status": "checked" if not unexpected else "rejected",
            "theorem": theorem,
            "typed_witness": typed_witness,
            "proposition_type_checked": True,
            "canonical_proposition_profile": canonical_profile,
            "lean_trust": 0,
            "approved_axioms": approved,
            "observed_axioms": observed,
            "unexpected_axioms": unexpected,
        }
        pathlib.Path(sys.argv[2]).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if unexpected:
            raise SystemExit("final theorem depends on unapproved axioms")
        PY

        cp "${effectiveGraphFile}" "$out/module-graph.json"
        cp "${effectivePreparedManifest}" "$out/prepared-proof.json"
        ${lib.optionalString graphV2 ''
          cp "${effectiveArtifactManifest}" "$out/artifact-manifest.json"
        ''}
        cp "$out/audit.json" "$verdict/audit.json"
        cp "$out/module-graph.json" "$verdict/module-graph.json"
        cp "$out/prepared-proof.json" "$verdict/prepared-proof.json"
        cp "$out/node-provenance.json" "$verdict/node-provenance.json"
        cp "$out/dependency-view.json" "$verdict/dependency-view.json"
        ${lib.optionalString graphV2 ''
          cp "$out/artifact-manifest.json" "$verdict/artifact-manifest.json"
        ''}

        ${pkgs.python3}/bin/python3 - "$verdict" <<'PY'
        import hashlib
        import json
        import pathlib
        import sys

        verdict = pathlib.Path(sys.argv[1])
        files = {}
        for path in sorted(verdict.iterdir()):
            if path.name == "verdict.json":
                continue
            files[path.name] = {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        audit = json.loads((verdict / "audit.json").read_text(encoding="utf-8"))
        provenance = json.loads(
            (verdict / "node-provenance.json").read_text(encoding="utf-8")
        )
        nodes = provenance.get("nodes", [])
        root_semantic_id = (
            nodes[0].get("semantic_id")
            if isinstance(nodes, list) and nodes and isinstance(nodes[0], dict)
            else None
        )
        payload = {
            "format": "stage-a-relational-proof-verdict-v1",
            "status": audit.get("status"),
            "theorem": audit.get("theorem"),
            "lean_trust": audit.get("lean_trust"),
            "root_semantic_id": root_semantic_id,
            "files": files,
        }
        (verdict / "verdict.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        referenced = [
            path.name
            for path in verdict.iterdir()
            if path.is_file() and b"/nix/store/" in path.read_bytes()
        ]
        if referenced:
            raise SystemExit(
                "compact proof verdict retained Nix store references: "
                + ", ".join(sorted(referenced))
            )
        PY
      ''
