{ pkgs
, prepared ? null
, graphFile ? null
, preparedManifest ? null
, sourceRoot ? prepared
, standaloneSourceRoot ? null
, standaloneModules ? []
, targetNode ? null
, targetNodes ? []
, targetBundle ? false
}:

let
  lib = pkgs.lib;
  standalone = standaloneSourceRoot != null;
  standaloneSource = module: standaloneSourceRoot + "/${module}.lean";
  standaloneImports = module:
    lib.filter (dependency: dependency != null) (map
      (line:
        let matched = builtins.match
          "^import StageA\\.([A-Za-z0-9_]+)$" line;
        in if matched == null then null else builtins.head matched)
      (lib.splitString "\n" (builtins.readFile (standaloneSource module))));
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
      let sourceSha256 = builtins.hashFile "sha256" (standaloneSource module);
      in {
        id = module;
        modules = [ module ];
        dependencies = standaloneImports module;
        resource_class = "light";
        estimated_memory_mb = 512;
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
  graph = if standalone then standaloneGraph else
    builtins.fromJSON (builtins.readFile effectiveGraphFile);
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

  nodeDrvs = lib.fix (self:
    builtins.listToAttrs (map (node:
      let
        dependencies = map (dependency: self.${dependency}) node.dependencies;
        dependencyArgs = lib.escapeShellArgs (map toString dependencies);
        metadata = builtins.toJSON {
          format = "stage-a-lean-node-result-v1";
          id = node.id;
          inherit (node) modules dependencies resource_class estimated_memory_mb source_sha256;
        };
      in {
        name = node.id;
        value = pkgs.runCommand
          (lib.strings.sanitizeDerivationName "stage-a-lean-${node.id}")
          {
            nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.coreutils ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          ''
            mkdir -p "$out/StageA" source/StageA deps/StageA
            ulimit -s unlimited
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
            ${lib.concatMapStringsSep "\n" (module:
              ''cp "${moduleSources.${module}}" "source/StageA/${module}.lean"''
            ) node.modules}
            ${if builtins.length node.modules == 1 then
              let module = builtins.head node.modules; in ''
                lean -j 2 \
                  -R source \
                  -o "deps/StageA/${module}.olean" \
                  "source/StageA/${module}.lean"
              ''
            else ''
              compile_jobs="$NIX_BUILD_CORES"
              if [ "$compile_jobs" -eq 0 ]; then
                compile_jobs="$(nproc)"
              fi
              printf '%s\n' ${lib.escapeShellArgs node.modules} | \
                xargs -r -P "$compile_jobs" -n 1 bash -c '
                  module="$1"
                  lean -j 1 \
                    -R source \
                    -o "deps/StageA/$module.olean" \
                    "source/StageA/$module.lean"
                ' _
            ''}
            ${lib.concatMapStringsSep "\n" (module: ''
              cp "deps/StageA/${module}.olean" "$out/StageA/${module}.olean"
              cp "source/StageA/${module}.lean" "$out/StageA/${module}.lean"
            '') node.modules}
            cat > "$out/module-result.json" <<'JSON'
            ${metadata}
            JSON
            python3 - "$out/module-result.json" "$out/StageA" <<'PY'
            import hashlib
            import json
            import pathlib
            import sys

            result_path = pathlib.Path(sys.argv[1])
            stage_a = pathlib.Path(sys.argv[2])
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            payload["outputs"] = [
                {
                    "module": path.stem,
                    "olean_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "olean_bytes": path.stat().st_size,
                }
                for path in sorted(stage_a.glob("*.olean"))
            ]
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
    {
      nativeBuildInputs = [ pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
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
  auditSource = pkgs.writeText "StageARelationalAudit.lean" ''
    import StageA.${graph.root_module}

    #check ${graph.expected_final_theorem}
    #print axioms ${graph.expected_final_theorem}
  '';
  approvedAxioms = builtins.toJSON graph.approved_axioms;
  selectedTargetNodes =
    if targetNode != null then [ targetNode ] else targetNodes;
  acceptanceReady =
    graph.acceptance.status == "ready"
    && graph.acceptance.theorem == graph.expected_final_theorem
    && graph.expected_final_theorem
      == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent";
  selectedNodeResults = map (node:
    let source = nodeDrvs.${node};
    in pkgs.runCommand
      (lib.strings.sanitizeDerivationName "stage-a-lean-${node}-detached")
      {
        nativeBuildInputs = [ pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out/StageA"
        cp -L "${source}"/StageA/*.lean "$out/StageA/"
        cp -L "${source}"/StageA/*.olean "$out/StageA/"
        cp "${source}/module-result.json" "$out/module-result.json"
      ''
  ) selectedTargetNodes;
  selectedTargetPaths = map (node: nodeDrvs.${node}) selectedTargetNodes;
  selectedTargetArgs = lib.escapeShellArgs (map toString selectedTargetPaths);
  selectedTargetBundle = pkgs.runCommand "stage-a-lean-target-bundle"
    {
      nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    ''
      mkdir -p "$out/StageA" "$out/node-results"
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
        result_name="$(printf '%06d.json' "$node_index")"
        cp "$source/module-result.json" "$out/node-results/$result_name"
        node_index=$((node_index + 1))
      done
      lean_version="$(lean --version | head -n 1)"
      python3 - "$out/node-results" "$out/bundle.json" "$lean_version" <<'PY'
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
      pathlib.Path(sys.argv[2]).write_text(
          json.dumps({
              "format": "stage-a-lean-target-bundle-v1",
              "lean_trust": 0,
              "lean_version": sys.argv[3],
              "nodes": nodes,
          }, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
      PY
    '';
in
assert graph.format == "stage-a-lean-module-graph-v1";
assert graph.lean.trust == 0;
assert builtins.length graph.nodes > 0;
assert !standalone || (standaloneModules != [] && standaloneImportsValid);
assert !standalone
  || builtins.length standaloneModules
    == builtins.length (lib.unique standaloneModules);
assert standalone || (effectiveGraphFile != null && sourceRoot != null);
assert builtins.length selectedTargetNodes
  == builtins.length (lib.unique selectedTargetNodes);
assert builtins.all (node: builtins.hasAttr node nodeDrvs) selectedTargetNodes;
assert selectedTargetNodes != [] || acceptanceReady;
if selectedTargetNodes != [] then
  if targetBundle then selectedTargetBundle else selectedNodeResults
else
pkgs.runCommand "stage-a-relational-proof-audit"
  {
    nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  ''
    mkdir -p "$out" deps source/StageA
    ulimit -s unlimited
    tar --zstd -xf ${rootDependencyPack}/dependencies.tar.zst -C deps
    export LEAN_PATH="$PWD/deps"
    cat > root-source-hashes <<'HASHES'
    ${sourceChecks rootNode}
    HASHES
    sha256sum --check --strict root-source-hashes
    ${lib.concatMapStringsSep "\n" (module: ''
      cp "${moduleSources.${module}}" "source/StageA/${module}.lean"
      lean -j 2 \
        -R source \
        -o "deps/StageA/${module}.olean" \
        "source/StageA/${module}.lean"
    '') rootNode.modules}
    cat > deps/root-module-result.json <<'JSON'
    ${rootMetadata}
    JSON
    python3 - deps/root-module-result.json deps/StageA ${lib.escapeShellArg (builtins.toJSON rootNode.modules)} <<'PY'
    import hashlib
    import json
    import pathlib
    import sys

    result_path = pathlib.Path(sys.argv[1])
    stage_a = pathlib.Path(sys.argv[2])
    modules = json.loads(sys.argv[3])
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["outputs"] = [
        {
            "module": module,
            "olean_sha256": hashlib.sha256(
                (stage_a / f"{module}.olean").read_bytes()
            ).hexdigest(),
            "olean_bytes": (stage_a / f"{module}.olean").stat().st_size,
        }
        for module in modules
    ]
    result_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY
    cp ${auditSource} StageARelationalAudit.lean
    lean -j 2 --trust=0 \
      -o "$out/StageARelationalAudit.olean" \
      StageARelationalAudit.lean \
      > "$out/lean.stdout" \
      2> "$out/lean.stderr"

    EXPECTED_THEOREM=${lib.escapeShellArg graph.expected_final_theorem} \
    APPROVED_AXIOMS=${lib.escapeShellArg approvedAxioms} \
      python3 - "$out/lean.stdout" "$out/audit.json" <<'PY'
    import json
    import os
    import pathlib
    import re
    import sys

    stdout = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    theorem = os.environ["EXPECTED_THEOREM"]
    approved = json.loads(os.environ["APPROVED_AXIOMS"])
    match = re.search(r"depends on axioms:\s*\[(.*?)\]", stdout, re.DOTALL)
    if match:
        observed = [item.strip() for item in match.group(1).split(",") if item.strip()]
    elif "does not depend on any axioms" in stdout:
        observed = []
    else:
        raise SystemExit("Lean axiom audit did not emit a parseable inventory")
    unexpected = sorted(set(observed) - set(approved))
    payload = {
        "format": "stage-a-relational-lean-audit-v1",
        "status": "checked" if not unexpected else "rejected",
        "theorem": theorem,
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
  ''
