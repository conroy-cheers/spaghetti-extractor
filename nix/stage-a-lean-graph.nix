{ pkgs
, prepared ? null
, graphFile ? null
, preparedManifest ? null
, artifactManifest ? null
, sourceRoot ? prepared
, standaloneSourceRoot ? null
, standaloneModules ? []
, standaloneModuleResources ? {}
, targetNode ? null
, targetNodes ? []
, targetBundle ? false
, targetAxiomAudit ? null
, graphSmoke ? false
, contentAddressed ? false
, measureResources ? false
}:

let
  lib = pkgs.lib;
  standalone = standaloneSourceRoot != null;
  standaloneSource = module: standaloneSourceRoot + "/${module}.lean";
  standaloneImports = module:
    lib.unique (lib.filter (dependency: dependency != null) (map
      (line:
        let matched = builtins.match
          "^import StageA\\.([A-Za-z0-9_]+)$" line;
        in if matched == null then null else builtins.head matched)
      (lib.splitString "\n" (builtins.readFile (standaloneSource module)))));
  standaloneModuleSet = builtins.listToAttrs (map (module: {
    name = module;
    value = true;
  }) standaloneModules);
  standaloneImportsValid = builtins.all (module:
    builtins.all (dependency: builtins.hasAttr dependency standaloneModuleSet)
      (standaloneImports module)
  ) standaloneModules;
  standaloneGraph = {
    format = "stage-a-lean-module-graph-v1";
    lean.trust = 0;
    modules = builtins.listToAttrs (map (module:
      let sourceSha256 = builtins.hashFile "sha256" (standaloneSource module);
      in {
        name = module;
        value = {
          source = "${module}.lean";
          source_sha256 = sourceSha256;
          imports = standaloneImports module;
        };
      }
    ) standaloneModules);
    nodes = map (module:
      let
        sourceSha256 = builtins.hashFile "sha256" (standaloneSource module);
        resources = standaloneModuleResources.${module} or {
          resource_class = "light";
          estimated_memory_mb = 512;
        };
      in {
        id = module;
        modules = [ module ];
        dependencies = lib.sort builtins.lessThan (standaloneImports module);
        inherit (resources) resource_class estimated_memory_mb;
        source_sha256 = builtins.hashString "sha256" sourceSha256;
      }
    ) standaloneModules;
  };
  effectiveGraphFile =
    if graphFile != null then graphFile
    else if prepared != null then prepared + "/module-graph.json"
    else null;
  effectivePreparedManifest =
    if preparedManifest != null then preparedManifest
    else if prepared != null then prepared + "/prepared-proof.json"
    else null;
  effectiveArtifactManifest =
    if artifactManifest != null then artifactManifest
    else if prepared != null && builtins.pathExists (prepared + "/artifact-manifest.json")
      then prepared + "/artifact-manifest.json"
    else null;
  graph = if standalone then standaloneGraph else
    builtins.fromJSON (builtins.readFile effectiveGraphFile);
  graphV2 = graph.format == "stage-a-lean-module-graph-v2";
  checkedArtifactManifest =
    if graphV2 then builtins.fromJSON (builtins.readFile effectiveArtifactManifest)
    else null;
  moduleSources = lib.mapAttrs (module: metadata:
    builtins.path {
      path = (if standalone then standaloneSourceRoot else sourceRoot)
        + "/${metadata.source}";
      name = "stage-a-${module}.lean";
    }
  ) graph.modules;

  sourceChecks = node:
    lib.concatMapStringsSep "\n" (module:
      let metadata = graph.modules.${module};
      in "${metadata.source_sha256}  ${moduleSources.${module}}"
    ) node.modules;

  nodeById = builtins.listToAttrs (map (node: {
    name = node.id;
    value = node;
  }) graph.nodes);
  nodeIds = map (node: node.id) graph.nodes;
  assignedModules = lib.concatMap (node: node.modules) graph.nodes;
  moduleOwners = builtins.listToAttrs (lib.concatMap (node:
    map (module: {
      name = module;
      value = node.id;
    }) node.modules
  ) graph.nodes);
  graphNodeIdsUnique = builtins.length nodeIds
    == builtins.length (lib.unique nodeIds);
  graphModuleImportsValid = builtins.all (module:
    graph.modules.${module} ? imports
    && builtins.isList graph.modules.${module}.imports
    && builtins.all (dependency: builtins.hasAttr dependency graph.modules)
      graph.modules.${module}.imports
  ) (builtins.attrNames graph.modules);
  graphModuleOwnershipValid =
    builtins.length assignedModules
      == builtins.length (lib.unique assignedModules)
    && lib.sort builtins.lessThan assignedModules
      == builtins.attrNames graph.modules;
  graphNodeDependenciesValid = graphModuleImportsValid
    && graphModuleOwnershipValid
    && builtins.all (node:
      let expected = lib.sort builtins.lessThan (lib.unique (lib.filter
        (dependency: dependency != node.id)
        (lib.concatMap (module:
          map (dependency: moduleOwners.${dependency})
            graph.modules.${module}.imports
        ) node.modules)));
      in node.dependencies == expected
    ) graph.nodes;
  graphNodeResourcesValid = builtins.all (node:
    builtins.elem node.resource_class [
      "light"
      "medium"
      "large-memory"
      "high-memory"
    ]
    && builtins.isInt node.estimated_memory_mb
    && node.estimated_memory_mb > 0
  ) graph.nodes;
  checkedArtifactIds =
    if graphV2 then map (artifact: artifact.identity.artifact_id)
      checkedArtifactManifest.artifacts
    else [];
  graphCheckedArtifactManifestValid = !graphV2 || (
    effectiveArtifactManifest != null
    && checkedArtifactManifest.format == "stage-a-checked-artifact-manifest-v1"
    && graph.artifacts.checked_manifest.path == "artifact-manifest.json"
    && builtins.hashFile "sha256" effectiveArtifactManifest
      == graph.artifacts.checked_manifest.sha256
    && checkedArtifactManifest.authoritative
      == graph.artifacts.checked_manifest.authoritative
    && builtins.length checkedArtifactIds
      == builtins.length (lib.unique checkedArtifactIds)
  );
  graphNodeArtifactMetadataValid = builtins.all (node:
    if !graphV2 then true else
      builtins.isString node.kind
      && node.kind != ""
      && builtins.isString node.stable_key
      && node.stable_key != ""
      && builtins.isString node.checker_version
      && node.checker_version == "stage-a-checked-artifact-checkers-v1"
      && builtins.isList node.artifact_ids
      && builtins.all (artifact:
        builtins.elem artifact checkedArtifactIds) node.artifact_ids
  ) graph.nodes;

  nodeDrvs = lib.fix (self:
    builtins.listToAttrs (map (node:
      let
        dependencies = map (dependency: self.${dependency}) node.dependencies;
        dependencyArgs = lib.escapeShellArgs (map toString dependencies);
        metadata = builtins.toJSON ({
          format = "stage-a-lean-node-result-v1";
          id = node.id;
          inherit (node) modules dependencies resource_class estimated_memory_mb source_sha256;
        } // lib.optionalAttrs graphV2 {
          inherit (node) kind stable_key artifact_ids checker_version;
        });
      in {
        name = node.id;
        value = pkgs.runCommand
          (lib.strings.sanitizeDerivationName "stage-a-lean-${node.id}")
          ({
            nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.coreutils ]
              ++ lib.optionals measureResources [ pkgs.time ];
            preferLocalBuild = false;
            allowSubstitutes = true;
            requiredSystemFeatures =
              if node.resource_class == "high-memory" then [
                "big-parallel"
                # The builders file gives genuinely exceptional modules a
                # dedicated one-slot lane.
                "benchmark"
              ] else lib.optionals
                (node.resource_class == "large-memory") [
                  "big-parallel"
                  # Proof-heavy but bounded modules use a separate two-slot
                  # lane instead of serializing behind exceptional modules.
                  "large-memory"
                ];
          } // lib.optionalAttrs contentAddressed { __contentAddressed = true; })
          ''
            mkdir -p "$out/StageA" "$out/logs" source/StageA deps/StageA
            ulimit -s unlimited 2>/dev/null || true
            cat > source-hashes <<'HASHES'
            ${sourceChecks node}
            HASHES
            sha256sum --check --strict source-hashes
            : > inherited-olean-index
            : > inherited-node-result-index
            link_dependency() {
              dependency_file="$1"
              destination="deps/StageA/$(basename "$dependency_file")"
              if [ -e "$destination" ]; then
                if [ "$(readlink -f "$destination")" != "$(readlink -f "$dependency_file")" ]; then
                  echo "conflicting dependency module: $(basename "$dependency_file")" >&2
                  exit 1
                fi
              else
                ln -s "$dependency_file" "$destination"
              fi
            }
            for dependency in ${dependencyArgs}; do
              for dependency_file in "$dependency"/StageA/*; do
                link_dependency "$dependency_file"
                readlink -f "$dependency_file" >> inherited-olean-index
              done
              if [ -s "$dependency/inherited-olean-index" ]; then
                while IFS= read -r dependency_file; do
                  link_dependency "$dependency_file"
                  printf '%s\n' "$dependency_file" >> inherited-olean-index
                done < "$dependency/inherited-olean-index"
              fi
              readlink -f "$dependency/module-result.json" >> inherited-node-result-index
              if [ -s "$dependency/inherited-node-result-index" ]; then
                cat "$dependency/inherited-node-result-index" >> inherited-node-result-index
              fi
            done
            sort -u inherited-olean-index > "$out/inherited-olean-index"
            sort -u inherited-node-result-index > "$out/inherited-node-result-index"
            export LEAN_PATH="$PWD/deps"
            export LC_ALL=C
            ${lib.concatMapStringsSep "\n" (module:
              ''cp "${moduleSources.${module}}" "source/StageA/${module}.lean"''
            ) node.modules}
            ${if builtins.length node.modules == 1 then
              let
                module = builtins.head node.modules;
                leanJobs = if builtins.elem node.resource_class [
                  "large-memory"
                  "high-memory"
                ] then "1" else "2";
              in ''
                ${lib.optionalString measureResources ''
                  ${pkgs.time}/bin/time -v \
                    -o "$out/logs/${module}.resource" \
                ''}lean -j ${leanJobs} --trust=0 \
                  -R source \
                  -o "deps/StageA/${module}.olean" \
                  "source/StageA/${module}.lean" \
                  > >(tee "$out/logs/${module}.stdout") \
                  2> >(tee "$out/logs/${module}.stderr" >&2)
              ''
            else ''
              compile_jobs="$NIX_BUILD_CORES"
              if [ "$compile_jobs" -eq 0 ]; then
                compile_jobs="$(nproc)"
              fi
              ${lib.optionalString (builtins.elem node.resource_class [
                "large-memory"
                "high-memory"
              ]) ''
                # Nix already schedules several independent graph nodes per
                # builder. Memory-heavy proof modules are kept sequential
                # inside each derivation so the scheduler lane remains the only
                # source of machine-level concurrency.
                compile_jobs=1
              ''}
              printf '%s\n' ${lib.escapeShellArgs node.modules} | \
                xargs -r -P "$compile_jobs" -n 1 bash -c '
                  module="$1"
                  ${lib.optionalString measureResources ''
                    ${pkgs.time}/bin/time -v \
                      -o "$out/logs/$module.resource" \
                  ''}lean -j 1 --trust=0 \
                    -R source \
                    -o "deps/StageA/$module.olean" \
                    "source/StageA/$module.lean" \
                    > >(tee "$out/logs/$module.stdout") \
                    2> >(tee "$out/logs/$module.stderr" >&2)
                ' _
            ''}
            ${lib.concatMapStringsSep "\n" (module: ''
              cp "deps/StageA/${module}.olean" "$out/StageA/${module}.olean"
              cp "source/StageA/${module}.lean" "$out/StageA/${module}.lean"
            '') node.modules}
            cat > "$out/module-result.json" <<'JSON'
            ${metadata}
            JSON
            python3 - "$out/module-result.json" "$out/StageA" "$out/logs" <<'PY'
            import hashlib
            import json
            import pathlib
            import re
            import sys

            result_path = pathlib.Path(sys.argv[1])
            stage_a = pathlib.Path(sys.argv[2])
            logs = pathlib.Path(sys.argv[3])
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            outputs = []
            for path in sorted(stage_a.glob("*.olean")):
                module = path.stem
                source = (stage_a / f"{module}.lean").read_text(encoding="utf-8")
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
            PY
          '';
      }
    ) graph.nodes));

  rootNode = nodeById.${graph.final_node};
  rootDependencyPaths = map (dependency: nodeDrvs.${dependency}) rootNode.dependencies;
  rootDependencyArgs = lib.escapeShellArgs (map toString rootDependencyPaths);
  rootMetadata = builtins.toJSON {
    format = "stage-a-lean-node-result-v1";
    inherit (rootNode) id modules dependencies resource_class estimated_memory_mb source_sha256;
  };
  rootDependencyPack = pkgs.runCommand "stage-a-relational-root-dependencies"
    ({
      nativeBuildInputs = [ pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    } // lib.optionalAttrs contentAddressed { __contentAddressed = true; })
    ''
      mkdir -p staging/StageA staging/node-results "$out"
      : > olean-paths
      : > node-result-paths
      for dependency in ${rootDependencyArgs}; do
        for dependency_file in "$dependency"/StageA/*.olean; do
          readlink -f "$dependency_file" >> olean-paths
        done
        if [ -s "$dependency/inherited-olean-index" ]; then
          cat "$dependency/inherited-olean-index" >> olean-paths
        fi
        readlink -f "$dependency/module-result.json" >> node-result-paths
        if [ -s "$dependency/inherited-node-result-index" ]; then
          cat "$dependency/inherited-node-result-index" >> node-result-paths
        fi
      done
      while IFS= read -r dependency_file; do
        destination="staging/StageA/$(basename "$dependency_file")"
        if [ -e "$destination" ] && ! cmp -s "$destination" "$dependency_file"; then
          echo "conflicting root dependency module: $(basename "$dependency_file")" >&2
          exit 1
        fi
        cp -L "$dependency_file" "$destination"
      done < <(sort -u olean-paths)
      node_index=0
      while IFS= read -r result_file; do
        cp "$result_file" "staging/node-results/$node_index.json"
        node_index=$((node_index + 1))
      done < <(sort -u node-result-paths)
      tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
        --zstd -cf "$out/dependencies.tar.zst" -C staging StageA node-results
      python3 - "$out/pack.json" "$out/dependencies.tar.zst" "$node_index" <<'PY'
      import hashlib
      import json
      import pathlib
      import sys

      archive = pathlib.Path(sys.argv[2])
      payload = {
          "format": "stage-a-lean-root-dependency-pack-v1",
          "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
          "archive_bytes": archive.stat().st_size,
          "node_count": int(sys.argv[3]),
      }
      pathlib.Path(sys.argv[1]).write_text(
          json.dumps(payload, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
      PY
    '';
  supportedAuditTheorems = [
    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
  ];
  selectedAuditTheorem = graph.expected_final_theorem;
  acceptanceNodeSteps = graph.acceptance.node_steps or null;
  acceptanceNodeStepsValid = builtins.isList acceptanceNodeSteps
    && builtins.all (step:
      builtins.isAttrs step && step ? kind && builtins.isString step.kind
    ) acceptanceNodeSteps;
  parameterizedEnvironment = acceptanceNodeStepsValid && builtins.any (step:
      builtins.elem step.kind [
        "external_call"
        "external_protocol"
        "external_jump"
        "external_terminate"
      ]
    ) acceptanceNodeSteps;
  parameterizedProtocolEnvironment = acceptanceNodeStepsValid
    && builtins.any (step: step.kind == "external_protocol") acceptanceNodeSteps;
  ordinaryCanonicalResult = originalProgram: candidateProgram: ''
    PE32RawProgramsObservationallyEquivalent staticProofContext
      relationalProductGraph productInvariantTable
      relationalProductReachabilityEvidence productControlProfile consoleLaunch
      ${originalProgram} ${candidateProgram}
  '';
  linkedCanonicalResult = originalProgram: candidateProgram: ''
    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext
      relationalProductGraph productInvariantTable
      relationalProductReachabilityEvidence linkedProductControlProfile consoleLaunch
      ${originalProgram} ${candidateProgram}
  '';
  ordinaryCanonicalType =
    if parameterizedProtocolEnvironment then ''
      forall (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
        (originalProtocolEnvironment candidateProtocolEnvironment :
          WorldExternalProtocolEnvironment),
        ExternalEnvironmentRefines staticProofContext externalCallSites
            originalEnvironment candidateEnvironment ->
          WorldExternalProtocolEnvironmentsRefine staticProofContext
              relationalProductGraph productInvariantTable
              relationalProductReachabilityEvidence productControlProfile
              protocolCallbackTargets externalCallSites
              originalProtocolEnvironment candidateProtocolEnvironment ->
            ${ordinaryCanonicalResult
              "(originalWorldProgram originalEnvironment originalProtocolEnvironment)"
              "(candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)"}
    '' else if parameterizedEnvironment then ''
      forall (originalEnvironment candidateEnvironment : WorldExternalEnvironment),
        ExternalEnvironmentRefines staticProofContext externalCallSites
            originalEnvironment candidateEnvironment ->
          ${ordinaryCanonicalResult
            "(originalWorldProgram originalEnvironment)"
            "(candidateWorldProgram candidateEnvironment)"}
    '' else ordinaryCanonicalResult "originalWorldProgram" "candidateWorldProgram";
  linkedCanonicalType =
    if parameterizedProtocolEnvironment then
      throw "linked final-theorem audit does not support protocol environments"
    else if parameterizedEnvironment then ''
      forall (originalEnvironment candidateEnvironment : WorldExternalEnvironment),
        ExternalEnvironmentRefines staticProofContext externalCallSites
            originalEnvironment candidateEnvironment ->
          ${linkedCanonicalResult
            "(originalWorldProgram originalEnvironment)"
            "(candidateWorldProgram candidateEnvironment)"}
    '' else linkedCanonicalResult "originalWorldProgram" "candidateWorldProgram";
  canonicalAuditType =
    if selectedAuditTheorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
    then ordinaryCanonicalType
    else if selectedAuditTheorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
    then linkedCanonicalType
    else throw "unsupported Stage A final theorem for typed audit";
  canonicalAuditProfile =
    (if selectedAuditTheorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
     then "linked-raw-pe32" else "raw-pe32")
    + (if parameterizedProtocolEnvironment then "-stateful-protocol"
       else if parameterizedEnvironment then "-external-environment"
       else "-closed");
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
  selectedTargetNodes =
    if targetNode != null then [ targetNode ] else targetNodes;
  targetAxiomAuditValid = targetAxiomAudit == null || (
    builtins.isAttrs targetAxiomAudit
    && targetAxiomAudit ? module
    && builtins.isString targetAxiomAudit.module
    && targetAxiomAudit ? declaration
    && builtins.isString targetAxiomAudit.declaration
    && targetAxiomAudit ? approved_axioms
    && builtins.isList targetAxiomAudit.approved_axioms
    && builtins.all builtins.isString targetAxiomAudit.approved_axioms
    && builtins.length targetAxiomAudit.approved_axioms
      == builtins.length (lib.unique targetAxiomAudit.approved_axioms)
  );
  targetAxiomAuditJson = builtins.toJSON targetAxiomAudit;
  ordinaryAcceptanceReady =
    acceptanceNodeStepsValid
    && graph.acceptance.status == "ready"
    && graph.acceptance.required_theorem == selectedAuditTheorem
    && graph.acceptance.theorem == graph.expected_final_theorem
    && graph.expected_final_theorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent";
  linkedAcceptance = graph.acceptance.linked_acceptance or null;
  linkedAcceptanceReady =
    acceptanceNodeStepsValid
    && !parameterizedProtocolEnvironment
    && graph.acceptance.status == "ready"
    && graph.acceptance.required_theorem == selectedAuditTheorem
    && graph.acceptance.theorem == selectedAuditTheorem
    && linkedAcceptance != null
    && linkedAcceptance.status == "ready"
    && linkedAcceptance.theorem == selectedAuditTheorem
    && selectedAuditTheorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked";
  acceptanceReady = builtins.elem selectedAuditTheorem supportedAuditTheorems
    && (if selectedAuditTheorem
          == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
        then ordinaryAcceptanceReady
        else linkedAcceptanceReady);
  selectedNodeResults = map (node:
    let source = nodeDrvs.${node};
    in pkgs.runCommand
      (lib.strings.sanitizeDerivationName "stage-a-lean-${node}-detached")
      ({
        nativeBuildInputs = [ pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      } // lib.optionalAttrs contentAddressed { __contentAddressed = true; })
      ''
        mkdir -p "$out/StageA" "$out/logs"
        cp -L "${source}"/StageA/*.lean "$out/StageA/"
        cp -L "${source}"/StageA/*.olean "$out/StageA/"
        cp -L "${source}"/logs/* "$out/logs/"
        cp "${source}/module-result.json" "$out/module-result.json"
      ''
  ) selectedTargetNodes;
  selectedTargetPaths = map (node: nodeDrvs.${node}) selectedTargetNodes;
  selectedTargetArgs = lib.escapeShellArgs (map toString selectedTargetPaths);
  selectedTargetBundle = pkgs.runCommand "stage-a-lean-target-bundle"
    ({
      nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    } // lib.optionalAttrs contentAddressed { __contentAddressed = true; })
    ''
      mkdir -p "$out/StageA" "$out/logs" "$out/node-results"
      node_index=0
      for source in ${selectedTargetArgs}; do
        for source_file in "$source"/StageA/*.lean "$source"/StageA/*.olean; do
          destination="$out/StageA/$(basename "$source_file")"
          if [ -e "$destination" ] && ! cmp -s "$destination" "$source_file"; then
            echo "conflicting target-bundle module: $(basename "$source_file")" >&2
            exit 1
          fi
          cp -L "$source_file" "$destination"
        done
        for log_file in "$source"/logs/*; do
          destination="$out/logs/$(basename "$log_file")"
          if [ -e "$destination" ] && ! cmp -s "$destination" "$log_file"; then
            echo "conflicting target-bundle log: $(basename "$log_file")" >&2
            exit 1
          fi
          cp -L "$log_file" "$destination"
        done
        result_name="$(printf '%06d.json' "$node_index")"
        cp "$source/module-result.json" "$out/node-results/$result_name"
        node_index=$((node_index + 1))
      done
      lean_version="$(lean --version | head -n 1)"
      python3 - "$out/node-results" "$out/bundle.json" "$lean_version" \
        ${lib.escapeShellArg targetAxiomAuditJson} "$out/axiom-audit.json" <<'PY'
      import json
      import pathlib
      import sys

      source = pathlib.Path(sys.argv[1])
      nodes = [
          json.loads(path.read_text(encoding="utf-8"))
          for path in sorted(source.glob("*.json"))
      ]
      node_ids = [node.get("id") for node in nodes]
      if len(node_ids) != len(set(node_ids)):
          raise SystemExit("target bundle contains duplicate node provenance")
      audit_config = json.loads(sys.argv[4])
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
          observed = inventory.get("inventories", {}).get(declaration)
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
          pathlib.Path(sys.argv[5]).write_text(
              json.dumps(audit, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
          if unexpected:
              raise SystemExit("target theorem depends on unapproved axioms")
      pathlib.Path(sys.argv[2]).write_text(
          json.dumps({
              "format": "stage-a-lean-target-bundle-v1",
              "lean_trust": 0,
              "lean_version": sys.argv[3],
              "axiom_audit": audit,
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
    module_count = builtins.length (builtins.attrNames graph.modules);
    node_count = builtins.length graph.nodes;
    target_nodes = selectedTargetNodes;
    modules = builtins.attrNames graph.modules;
    nodes = map (node: {
      inherit (node) id modules dependencies resource_class estimated_memory_mb;
    }) graph.nodes;
  };
  graphSmokeResult = pkgs.runCommand "stage-a-lean-graph-smoke"
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
assert graphCheckedArtifactManifestValid;
assert graphNodeArtifactMetadataValid;
assert !standalone || (standaloneModules != [] && standaloneImportsValid);
assert !standalone
  || builtins.length standaloneModules
    == builtins.length (lib.unique standaloneModules);
assert standalone || (effectiveGraphFile != null && sourceRoot != null);
assert builtins.length selectedTargetNodes
  == builtins.length (lib.unique selectedTargetNodes);
assert targetAxiomAuditValid;
assert targetAxiomAudit == null || targetBundle;
assert builtins.all (node: builtins.hasAttr node nodeDrvs) selectedTargetNodes;
assert graphSmoke || selectedTargetNodes != [] || acceptanceReady;
if graphSmoke then graphSmokeResult else if selectedTargetNodes != [] then
  if targetBundle then selectedTargetBundle else selectedNodeResults
else
pkgs.runCommand "stage-a-relational-proof-audit"
  ({
    nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  } // lib.optionalAttrs contentAddressed { __contentAddressed = true; })
  ''
    mkdir -p "$out" "$out/logs" deps source/StageA
    ulimit -s unlimited 2>/dev/null || true
    tar --zstd -xf ${rootDependencyPack}/dependencies.tar.zst -C deps
    export LEAN_PATH="$PWD/deps"
    cat > root-source-hashes <<'HASHES'
    ${sourceChecks rootNode}
    HASHES
    sha256sum --check --strict root-source-hashes
    ${lib.concatMapStringsSep "\n" (module: ''
      cp "${moduleSources.${module}}" "source/StageA/${module}.lean"
      lean -j 2 --trust=0 \
        -R source \
        -o "deps/StageA/${module}.olean" \
        "source/StageA/${module}.lean" \
        > >(tee "$out/logs/${module}.stdout") \
        2> >(tee "$out/logs/${module}.stderr" >&2)
    '') rootNode.modules}
    cat > deps/root-module-result.json <<'JSON'
    ${rootMetadata}
    JSON
    python3 - deps/root-module-result.json deps/StageA "$out/logs" source/StageA ${lib.escapeShellArg (builtins.toJSON rootNode.modules)} <<'PY'
    import hashlib
    import json
    import pathlib
    import re
    import sys

    result_path = pathlib.Path(sys.argv[1])
    stage_a = pathlib.Path(sys.argv[2])
    logs = pathlib.Path(sys.argv[3])
    sources = pathlib.Path(sys.argv[4])
    modules = json.loads(sys.argv[5])
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    outputs = []
    for module in modules:
        olean = stage_a / f"{module}.olean"
        stdout_path = logs / f"{module}.stdout"
        stderr_path = logs / f"{module}.stderr"
        source = (sources / f"{module}.lean").read_text(encoding="utf-8")
        combined = "\n".join((
            stdout_path.read_text(encoding="utf-8"),
            stderr_path.read_text(encoding="utf-8"),
        ))
        requested = re.findall(
            r"(?m)^\s*#print\s+axioms\s+([A-Za-z0-9_'.]+)\s*$", source
        )
        parsed = {}
        for declaration, axioms in re.findall(
            r"'([^']+)' depends on axioms:\s*\[(.*?)\]", combined, re.DOTALL
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
        outputs.append({
            "module": module,
            "olean_sha256": hashlib.sha256(olean.read_bytes()).hexdigest(),
            "olean_bytes": olean.stat().st_size,
            "compile_stdout": f"logs/{module}.stdout",
            "compile_stderr": f"logs/{module}.stderr",
            "compile_stdout_sha256": hashlib.sha256(
                stdout_path.read_bytes()
            ).hexdigest(),
            "compile_stderr_sha256": hashlib.sha256(
                stderr_path.read_bytes()
            ).hexdigest(),
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
    PY
    cp ${auditSource} StageARelationalAudit.lean
    lean -j 2 --trust=0 \
      -o "$out/StageARelationalAudit.olean" \
      StageARelationalAudit.lean \
      > >(tee "$out/lean.stdout") \
      2> >(tee "$out/lean.stderr" >&2)

    EXPECTED_THEOREM=${lib.escapeShellArg selectedAuditTheorem} \
    CANONICAL_PROPOSITION_PROFILE=${lib.escapeShellArg canonicalAuditProfile} \
    APPROVED_AXIOMS=${lib.escapeShellArg approvedAxioms} \
      python3 - "$out/lean.stdout" "$out/audit.json" <<'PY'
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

    cp deps/root-module-result.json deps/node-results/root.json
    python3 - deps/node-results "$out/node-provenance.json" <<'PY'
    import json
    import pathlib
    import sys

    source = pathlib.Path(sys.argv[1])
    nodes = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(source.glob("*.json"))
    ]
    payload = {
        "format": "stage-a-lean-node-provenance-v1",
        "nodes": nodes,
    }
    pathlib.Path(sys.argv[2]).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY
    cp ${rootDependencyPack}/pack.json "$out/dependency-pack.json"
    cp "${effectiveGraphFile}" "$out/module-graph.json"
    cp "${effectivePreparedManifest}" "$out/prepared-proof.json"
    ${lib.optionalString graphV2 ''
      cp "${effectiveArtifactManifest}" "$out/artifact-manifest.json"
    ''}
  ''
