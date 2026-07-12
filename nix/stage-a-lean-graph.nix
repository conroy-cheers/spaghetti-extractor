{ pkgs, prepared }:

let
  lib = pkgs.lib;
  graph = builtins.fromJSON (builtins.readFile (prepared + "/module-graph.json"));

  sourceChecks = node:
    lib.concatMapStringsSep "\n" (module:
      let metadata = graph.modules.${module};
      in "${metadata.source_sha256}  ${prepared}/${metadata.source}"
    ) node.modules;

  nodeById = builtins.listToAttrs (map (node: {
    name = node.id;
    value = node;
  }) graph.nodes);

  dependencyClosure = node:
    lib.unique (lib.concatMap (dependency:
      [ dependency ] ++ dependencyClosure nodeById.${dependency}
    ) node.dependencies);

  nodeDrvs = lib.fix (self:
    builtins.listToAttrs (map (node:
      let
        dependencies = map (dependency: self.${dependency}) (dependencyClosure node);
        dependencyArgs = lib.escapeShellArgs (map toString dependencies);
        modules = lib.escapeShellArgs node.modules;
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
            cat > source-hashes <<'HASHES'
            ${sourceChecks node}
            HASHES
            sha256sum --check --strict source-hashes
            for dependency in ${dependencyArgs}; do
              for dependency_file in "$dependency"/StageA/*; do
                ln -s "$dependency_file" "deps/StageA/$(basename "$dependency_file")"
              done
            done
            export LEAN_PATH="$PWD/deps"
            for module in ${modules}; do
              cp "${prepared}/lean/StageA/$module.lean" "source/StageA/$module.lean"
              lean \
                -R source \
                -o "deps/StageA/$module.olean" \
                "source/StageA/$module.lean"
              cp "deps/StageA/$module.olean" "$out/StageA/$module.olean"
              cp "source/StageA/$module.lean" "$out/StageA/$module.lean"
            done
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
  nonRootNodes = builtins.filter (node: node.id != graph.final_node) graph.nodes;
  nonRootNodePaths = map (node: nodeDrvs.${node.id}) nonRootNodes;
  nonRootNodeArgs = lib.escapeShellArgs (map toString nonRootNodePaths);
  rootModules = lib.escapeShellArgs rootNode.modules;
  rootMetadata = builtins.toJSON {
    format = "stage-a-lean-node-result-v1";
    inherit (rootNode) id modules dependencies resource_class estimated_memory_mb source_sha256;
  };
  rootDependencyPack = pkgs.runCommand "stage-a-relational-root-dependencies"
    {
      nativeBuildInputs = [ pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
      preferLocalBuild = true;
      allowSubstitutes = true;
    }
    ''
      mkdir -p staging/StageA staging/node-results "$out"
      node_index=0
      for dependency in ${nonRootNodeArgs}; do
        cp -L "$dependency"/StageA/*.olean staging/StageA/
        cp "$dependency/module-result.json" "staging/node-results/$node_index.json"
        node_index=$((node_index + 1))
      done
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
in
assert graph.format == "stage-a-lean-module-graph-v1";
assert graph.lean.trust == 0;
assert builtins.length graph.nodes > 0;
pkgs.runCommand "stage-a-relational-proof-audit"
  {
    nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.gnutar pkgs.zstd pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  ''
    mkdir -p "$out" deps source/StageA
    tar --zstd -xf ${rootDependencyPack}/dependencies.tar.zst -C deps
    export LEAN_PATH="$PWD/deps"
    cat > root-source-hashes <<'HASHES'
    ${sourceChecks rootNode}
    HASHES
    sha256sum --check --strict root-source-hashes
    for module in ${rootModules}; do
      cp "${prepared}/lean/StageA/$module.lean" "source/StageA/$module.lean"
      lean \
        -R source \
        -o "deps/StageA/$module.olean" \
        "source/StageA/$module.lean"
    done
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
    lean --trust=0 \
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
    cp "${prepared}/module-graph.json" "$out/module-graph.json"
    cp "${prepared}/prepared-proof.json" "$out/prepared-proof.json"
  ''
