# Compact Lean evaluator for small Stage A round-trip proof graphs.
#
# This preserves the proof and audit boundary of stage-a-lean-graph.nix while
# compiling one selected node closure in one derivation.  It is intended only
# as a scheduling/cache-granularity alternative for tiny generated graphs.
{
  pkgs,
  prepared ? null,
  graphFile ? null,
  preparedManifest ? null,
  sourceRoot ? prepared,
  precompiledKernel ? null,
  targetNodes ? [ ],
  targetBundle ? false,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
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
  graphInput = builtins.path {
    path = effectiveGraphFile;
    name = "stage-a-compact-module-graph.json";
  };
  preparedManifestInput = builtins.path {
    path = effectivePreparedManifest;
    name = "stage-a-compact-prepared-proof.json";
  };
  graph = builtins.fromJSON (builtins.readFile graphInput);

  validRelativePath =
    value:
    builtins.isString value
    && value != ""
    && !lib.hasPrefix "/" value
    && builtins.all (component: component != "" && component != "." && component != "..") (
      lib.splitString "/" value
    );
  moduleSources = lib.mapAttrs (
    module: metadata:
    builtins.path {
      path = sourceRoot + "/${metadata.source}";
      name = "stage-a-${module}.lean";
    }
  ) graph.modules;
  sourceChecks =
    modules:
    lib.concatMapStringsSep "\n" (
      module: "${graph.modules.${module}.source_sha256}  ${moduleSources.${module}}"
    ) modules;

  nodeById = builtins.listToAttrs (
    map (node: {
      name = node.id;
      value = node;
    }) graph.nodes
  );
  nodeIds = map (node: node.id) graph.nodes;
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
  graphNodeIdsUnique = builtins.length nodeIds == builtins.length (lib.unique nodeIds);
  graphModuleSourcesValid = builtins.all (
    module:
    let
      metadata = graph.modules.${module};
    in
    metadata ? source
    && validRelativePath metadata.source
    && metadata ? source_sha256
    && builtins.match "[0-9a-f]{64}" metadata.source_sha256 != null
  ) (builtins.attrNames graph.modules);
  graphModuleImportsValid = builtins.all (
    module:
    graph.modules.${module} ? imports
    && builtins.isList graph.modules.${module}.imports
    && builtins.all (
      dependency: builtins.hasAttr dependency graph.modules
    ) graph.modules.${module}.imports
  ) (builtins.attrNames graph.modules);
  graphModuleOwnershipValid =
    builtins.length assignedModules == builtins.length (lib.unique assignedModules)
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

  selectedTargetNodes = targetNodes;
  positiveMode = selectedTargetNodes == [ ];
  seedNodeIds = if positiveMode then [ graph.final_node ] else selectedTargetNodes;
  expandNodeClosure =
    ids:
    lib.sort builtins.lessThan (
      lib.unique (ids ++ lib.concatMap (id: nodeById.${id}.dependencies) ids)
    );
  closeNodes =
    ids:
    let
      expanded = expandNodeClosure ids;
    in
    if builtins.length expanded == builtins.length ids then expanded else closeNodes expanded;
  closureNodeIds = closeNodes (lib.sort builtins.lessThan seedNodeIds);
  closureNodes = map (id: nodeById.${id}) closureNodeIds;
  closureModules = lib.sort builtins.lessThan (lib.concatMap (node: node.modules) closureNodes);
  closureModuleSet = builtins.listToAttrs (
    map (module: {
      name = module;
      value = true;
    }) closureModules
  );
  closureImportsComplete = builtins.all (
    module:
    builtins.all (
      dependency: builtins.hasAttr dependency closureModuleSet
    ) graph.modules.${module}.imports
  ) closureModules;
  positiveRootValid =
    !positiveMode
    || (
      graph ? root_module
      && builtins.isString graph.root_module
      && builtins.hasAttr graph.root_module closureModuleSet
      && moduleOwners.${graph.root_module} == graph.final_node
    );

  # Kahn ordering gives a deterministic module build and rejects import cycles.
  topologicalModules =
    let
      visit =
        ordered: remaining:
        if remaining == [ ] then
          ordered
        else
          let
            ready = lib.sort builtins.lessThan (
              lib.filter (
                module: builtins.all (dependency: builtins.elem dependency ordered) graph.modules.${module}.imports
              ) remaining
            );
            next = lib.filter (module: !builtins.elem module ready) remaining;
          in
          if ready == [ ] then
            throw "compact Stage A Lean closure contains an import cycle"
          else
            visit (ordered ++ ready) next;
    in
    visit [ ] closureModules;

  closureMetadata = builtins.toJSON {
    nodes = closureNodes;
    selected_nodes = selectedTargetNodes;
    topological_modules = topologicalModules;
  };
  selectedMetadata = builtins.toJSON {
    nodes = map (id: nodeById.${id}) selectedTargetNodes;
  };
  compileSteps = lib.concatMapStringsSep "\n" (module: ''
    module=${lib.escapeShellArg module}
    source="source/StageA/$module.lean"
    output="build/StageA/$module.olean"
    stdout="logs/$module.stdout"
    stderr="logs/$module.stderr"
    ${
      if precompiledKernel != null then
        ''
          if [ -f "${precompiledKernel}/StageA/$module.lean" ] \
              && [ -f "${precompiledKernel}/StageA/$module.olean" ] \
              ${
                lib.concatMapStringsSep " \\\n              && " (
                  dependency: "grep -Fqx ${lib.escapeShellArg dependency} reusable-kernel-modules"
                ) graph.modules.${module}.imports
              } \
              && cmp -s "$source" "${precompiledKernel}/StageA/$module.lean"; then
            cp -L "${precompiledKernel}/StageA/$module.olean" "$output"
            : > "$stdout"
            : > "$stderr"
            printf '%s\n' "$module" >> reusable-kernel-modules
            printf '%s\t%s\n' "$module" precompiled_kernel >> compile-modes.tsv
          else
            lean -j 1 --trust=0 -R source -o "$output" "$source" \
              > >(tee "$stdout") 2> >(tee "$stderr" >&2)
            printf '%s\t%s\n' "$module" compiled >> compile-modes.tsv
          fi
        ''
      else
        ''
          lean -j 1 --trust=0 -R source -o "$output" "$source" \
            > >(tee "$stdout") 2> >(tee "$stderr" >&2)
          printf '%s\t%s\n' "$module" compiled >> compile-modes.tsv
        ''
    }
  '') topologicalModules;

  selectedAuditTheorem = graph.expected_final_theorem or null;
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
  auditSource = pkgs.writeText "StageARelationalCompactAudit.lean" ''
    import StageA.${graph.root_module}

    namespace StageA.FinalTheoremAudit

    open StageA.Formal StageA.Relational StageA.GeneratedRelational

    /-- A fresh proof term at the canonical whole-program proposition. -/
    theorem typedFinalTheorem :
        ${canonicalAuditType} :=
      ${selectedAuditTheorem}

    #check ${selectedAuditTheorem}
    #check typedFinalTheorem
    #print axioms typedFinalTheorem

    end StageA.FinalTheoremAudit
  '';
  approvedAxiomsValid =
    graph ? approved_axioms
    && builtins.isList graph.approved_axioms
    && builtins.all builtins.isString graph.approved_axioms
    && builtins.length graph.approved_axioms == builtins.length (lib.unique graph.approved_axioms);
  approvedAxioms = builtins.toJSON graph.approved_axioms;
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
in
assert effectiveGraphFile != null;
assert effectivePreparedManifest != null;
assert sourceRoot != null;
assert graph.format == "stage-a-lean-module-graph-v1";
assert graph.lean.trust == 0;
assert builtins.length graph.nodes > 0;
assert graphNodeIdsUnique;
assert graphModuleSourcesValid;
assert graphModuleImportsValid;
assert graphModuleOwnershipValid;
assert graphNodeDependenciesValid;
assert approvedAxiomsValid;
assert builtins.length selectedTargetNodes == builtins.length (lib.unique selectedTargetNodes);
assert targetBundle || builtins.length selectedTargetNodes <= 1;
assert builtins.all (node: builtins.hasAttr node nodeById) seedNodeIds;
assert closureImportsComplete;
assert positiveRootValid;
assert !positiveMode || acceptanceReady;
pkgs.runCommand
  (
    if positiveMode then
      "stage-a-relational-compact-proof-audit"
    else
      "stage-a-lean-compact-target-bundle"
  )
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
    // lib.optionalAttrs contentAddressed { __contentAddressed = true; }
  )
  ''
    mkdir -p "$out" source/StageA build/StageA logs node-results
    ulimit -s unlimited 2>/dev/null || true
    cat > source-hashes <<'HASHES'
    ${sourceChecks topologicalModules}
    HASHES
    sha256sum --check --strict source-hashes
    ${lib.concatMapStringsSep "\n" (
      module: ''cp "${moduleSources.${module}}" "source/StageA/${module}.lean"''
    ) topologicalModules}
    : > compile-modes.tsv
    : > reusable-kernel-modules
    export LEAN_PATH="$PWD/build"
    ${compileSteps}
    cat > closure.json <<'JSON'
    ${closureMetadata}
    JSON
    python3 - closure.json source/StageA build/StageA logs compile-modes.tsv node-results <<'PY'
    import hashlib
    import json
    import pathlib
    import re
    import sys

    closure = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    sources = pathlib.Path(sys.argv[2])
    outputs = pathlib.Path(sys.argv[3])
    logs = pathlib.Path(sys.argv[4])
    modes = dict(
        line.rstrip("\n").split("\t", 1)
        for line in pathlib.Path(sys.argv[5]).read_text(encoding="utf-8").splitlines()
    )
    destination = pathlib.Path(sys.argv[6])

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    for index, node in enumerate(closure["nodes"]):
        module_outputs = []
        for module in node["modules"]:
            source = sources / f"{module}.lean"
            olean = outputs / f"{module}.olean"
            stdout_path = logs / f"{module}.stdout"
            stderr_path = logs / f"{module}.stderr"
            combined = "\n".join((
                stdout_path.read_text(encoding="utf-8"),
                stderr_path.read_text(encoding="utf-8"),
            ))
            requested = re.findall(
                r"(?m)^\s*#print\s+axioms\s+([A-Za-z0-9_'.]+)\s*$",
                source.read_text(encoding="utf-8"),
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
            inventories = {
                request: next((
                    axioms for declaration, axioms in parsed.items()
                    if declaration == request or declaration.endswith(f".{request}")
                ), None)
                for request in requested
            }
            module_outputs.append({
                "module": module,
                "olean_sha256": digest(olean),
                "olean_bytes": olean.stat().st_size,
                "compile_mode": modes[module],
                "compile_stdout": f"logs/{module}.stdout",
                "compile_stderr": f"logs/{module}.stderr",
                "compile_stdout_sha256": digest(stdout_path),
                "compile_stderr_sha256": digest(stderr_path),
                "axiom_audit": {
                    "requested": requested,
                    "inventories": inventories,
                    "complete": all(value is not None for value in inventories.values()),
                },
            })
        payload = {
            "format": "stage-a-lean-node-result-v1",
            "id": node["id"],
            "modules": node["modules"],
            "dependencies": node["dependencies"],
            "resource_class": node["resource_class"],
            "estimated_memory_mb": node["estimated_memory_mb"],
            "source_sha256": node["source_sha256"],
            "outputs": module_outputs,
        }
        (destination / f"{index:06d}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    PY

    ${
      if positiveMode then
        ''
          mkdir -p "$out/logs"
          cp logs/* "$out/logs/"
          cp ${auditSource} StageARelationalAudit.lean
          lean -j 1 --trust=0 -o "$out/StageARelationalAudit.olean" \
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
          python3 - node-results "$out/node-provenance.json" <<'PY'
          import json
          import pathlib
          import sys

          source = pathlib.Path(sys.argv[1])
          nodes = [
              json.loads(path.read_text(encoding="utf-8"))
              for path in sorted(source.glob("*.json"))
          ]
          pathlib.Path(sys.argv[2]).write_text(
              json.dumps({
                  "format": "stage-a-lean-node-provenance-v1",
                  "nodes": nodes,
              }, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
          PY
          cp "${graphInput}" "$out/module-graph.json"
          cp "${preparedManifestInput}" "$out/prepared-proof.json"
        ''
      else
        ''
          mkdir -p "$out/StageA" "$out/logs" "$out/node-results"
          cat > selected.json <<'JSON'
          ${selectedMetadata}
          JSON
          python3 - selected.json node-results selected-node-results <<'PY'
          import json
          import pathlib
          import shutil
          import sys

          selected = {
              node["id"] for node in
              json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["nodes"]
          }
          source = pathlib.Path(sys.argv[2])
          destination = pathlib.Path(sys.argv[3])
          destination.mkdir()
          matches = []
          for path in sorted(source.glob("*.json")):
              payload = json.loads(path.read_text(encoding="utf-8"))
              if payload.get("id") in selected:
                  matches.append(path)
          if len(matches) != len(selected):
              raise SystemExit("compact target bundle omits a selected node result")
          for index, path in enumerate(matches):
              shutil.copyfile(path, destination / f"{index:06d}.json")
          PY
          cp selected-node-results/*.json "$out/node-results/"
          ${lib.concatMapStringsSep "\n" (
            id:
            lib.concatMapStringsSep "\n" (module: ''
              cp "source/StageA/${module}.lean" "$out/StageA/${module}.lean"
              cp "build/StageA/${module}.olean" "$out/StageA/${module}.olean"
              cp "logs/${module}.stdout" "$out/logs/${module}.stdout"
              cp "logs/${module}.stderr" "$out/logs/${module}.stderr"
            '') nodeById.${id}.modules
          ) selectedTargetNodes}
          ${lib.optionalString (builtins.length selectedTargetNodes == 1) ''
            cp "$out/node-results/000000.json" "$out/module-result.json"
          ''}
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
        ''
    }
  ''
