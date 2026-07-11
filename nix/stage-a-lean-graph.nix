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
            nativeBuildInputs = [ pkgs.lean4 pkgs.coreutils ];
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
          '';
      }
    ) graph.nodes));

  allNodePaths = map (node: nodeDrvs.${node.id}) graph.nodes;
  allNodeArgs = lib.escapeShellArgs (map toString allNodePaths);
  auditSource = pkgs.writeText "StageARelationalAudit.lean" ''
    import StageA.${graph.root_module}

    #check ${graph.expected_final_theorem}
    #print axioms ${graph.expected_final_theorem}
  '';
  nodeStorePaths = builtins.toJSON {
    format = "stage-a-lean-node-store-paths-v1";
    nodes = map (node: {
      id = node.id;
      out_path = toString nodeDrvs.${node.id};
      inherit (node) resource_class estimated_memory_mb source_sha256;
    }) graph.nodes;
  };
  approvedAxioms = builtins.toJSON graph.approved_axioms;
in
assert graph.format == "stage-a-lean-module-graph-v1";
assert graph.lean.trust == 0;
assert builtins.length graph.nodes > 0;
pkgs.runCommand "stage-a-relational-proof-audit"
  {
    nativeBuildInputs = [ pkgs.lean4 pkgs.python3 pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  ''
    mkdir -p "$out" deps/StageA
    for dependency in ${allNodeArgs}; do
      for dependency_file in "$dependency"/StageA/*; do
        ln -s "$dependency_file" "deps/StageA/$(basename "$dependency_file")"
      done
    done
    export LEAN_PATH="$PWD/deps"
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

    cat > "$out/node-store-paths.json" <<'JSON'
    ${nodeStorePaths}
    JSON
    cp "${prepared}/module-graph.json" "$out/module-graph.json"
    cp "${prepared}/prepared-proof.json" "$out/prepared-proof.json"
  ''
