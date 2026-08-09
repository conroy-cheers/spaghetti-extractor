{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource,
  spaghettiExtractor,
  kernelCache,
  semanticKernel,
  bochsRunner,
  requirements,
  name,
}:

let
  semanticRequirementsPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = isaPythonSource;
    modules = [
      "spaghetti_extractor.machine_ir_isa_requirements_v2"
    ];
    extraPaths = [ "spaghetti_extractor/lean/StageA" ];
    name = "${name}-semantic-requirements-python-closure";
  };
  # This CA output intentionally excludes the authority input store path. The
  # expensive qualification graph depends on its replayed semantic content.
  semanticRequirements = pkgs.runCommand "${name}-semantic-requirements" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${semanticRequirementsPythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
      ${requirements} "$out/semantic-requirements.json" <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
        build_machine_ir_isa_semantic_requirements_v2,
    )

    source = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    payload = build_machine_ir_isa_semantic_requirements_v2(
        json.loads(source.read_text(encoding="utf-8"))
    )
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-machine-ir-isa-semantic-requirements-v2"
      and .status == "complete"
      and (.semantic_requirements_sha256 | test("^[0-9a-f]{64}$"))
      and (.projection_sha256 | test("^[0-9a-f]{64}$"))
    ' "$out/semantic-requirements.json" >/dev/null
  '';
  mkPhase = args: import ./ca-python-json-phase.nix ({
    inherit pkgs pythonEnv;
    pythonSource = isaPythonSource;
    name = "${name}-${args.derivationSuffix}";
    inherit (args)
      kind
      artifactName
      expectedFormat
      allowedStatuses
      pythonModules
      inputs
      program
      ;
    pythonExtraPaths = args.pythonExtraPaths or [ ];
    extraNativeBuildInputs = args.extraNativeBuildInputs or [ ];
  });
  catalogProposal = mkPhase {
    derivationSuffix = "catalog-proposal";
    kind = "machine-ir-isa-catalog-proposal";
    artifactName = "catalog-proposal.json";
    expectedFormat = "stage-a-side-isa-executable-catalog-proposal-v1";
    allowedStatuses = [ "incomplete_missing_effect_enrichment" ];
    pythonModules = [
      "spaghetti_extractor.machine_ir_isa_catalog_v2"
    ];
    pythonExtraPaths = [ "spaghetti_extractor/lean/StageA" ];
    inputs = {
      requirements = "${semanticRequirements}/semantic-requirements.json";
    };
    program = ''
      from spaghetti_extractor.machine_ir_isa_catalog_v2 import (
          build_machine_ir_isa_catalog_proposal_v2,
      )

      payload = build_machine_ir_isa_catalog_proposal_v2(
          json.loads(inputs["requirements"].read_text(encoding="utf-8"))
      )
      output.write_text(
          json.dumps(payload, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
    '';
  };
  catalogEnrichment = mkPhase {
    derivationSuffix = "catalog-enrichment";
    kind = "machine-ir-isa-catalog-enrichment";
    artifactName = "catalog-enrichment.json";
    expectedFormat = "stage-a-side-isa-executable-catalog-enrichment-v1";
    allowedStatuses = [
      "complete"
      "incomplete_unresolved_encodings"
    ];
    pythonModules = [
      "spaghetti_extractor.isa_catalog_enrichment"
    ];
    pythonExtraPaths = [ "spaghetti_extractor/lean/StageA" ];
    extraNativeBuildInputs = [ pkgs.lean4 ];
    inputs = { proposal = catalogProposal.artifact; };
    program = ''
      from spaghetti_extractor.isa_catalog_enrichment import (
          enrich_side_isa_catalog_with_lean,
      )

      payload = enrich_side_isa_catalog_with_lean(
          json.loads(inputs["proposal"].read_text(encoding="utf-8")),
          timeout_seconds=1800,
      )
      output.write_text(
          json.dumps(payload, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
    '';
  };
  corpusPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.isa_cli" ];
    extraPaths = [ "spaghetti_extractor/lean/StageA" ];
    name = "${name}-corpus-python-closure";
  };
  corpus = pkgs.runCommand "${name}-boundary-corpus" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${corpusPythonSource}/src
    ${pythonEnv}/bin/python3 - \
      ${catalogEnrichment.artifact} "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.isa_cli import generate_isa_corpus

    generate_isa_corpus(
        catalog=pathlib.Path(sys.argv[1]),
        seed=0,
        out=pathlib.Path(sys.argv[2]),
    )
    PY
    jq -e '
      .format == "stage-a-generated-isa-corpus-manifest-v1"
      and .trust.proof_authority == false
      and .trust.closes_stage_a_proof == false
    ' "$out/manifest.json" >/dev/null
  '';
  qualificationGraph = import ./stage-a-isa-qualification-graph.nix {
    inherit
      pkgs
      pythonEnv
      spaghettiExtractor
      kernelCache
      semanticKernel
      bochsRunner
      ;
    pythonSource = isaPythonSource;
    leanShardCount = 32;
    name = "${name}-oracle";
    corpus = "${corpus}/corpus.json";
    generatedCorpus = "${corpus}/generated-corpus.json";
    requirements = null;
  };
  selectionAuthority = mkPhase {
    derivationSuffix = "selection-authority";
    kind = "machine-ir-isa-selection-authority";
    artifactName = "selection-authority.json";
    expectedFormat = "stage-a-binary-isa-kernel-selection-authority-v1";
    allowedStatuses = [ "qualified" "incomplete" "violated" ];
    pythonModules = [
      "spaghetti_extractor.machine_ir_isa_selection_v2"
    ];
    inputs = {
      inherit requirements;
      qualification = "${qualificationGraph.qualification}/qualification.json";
    };
    program = ''
      from spaghetti_extractor.machine_ir_isa_selection_v2 import (
          build_machine_ir_isa_selection_authority_v2,
      )

      payload = build_machine_ir_isa_selection_authority_v2(
          requirements=json.loads(
              inputs["requirements"].read_text(encoding="utf-8")
          ),
          qualification=json.loads(
              inputs["qualification"].read_text(encoding="utf-8")
          ),
      )
      output.write_text(
          json.dumps(payload, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
    '';
  };
in
{
  inherit
    semanticRequirements
    catalogProposal
    catalogEnrichment
    corpus
    qualificationGraph
    selectionAuthority
    ;
  aggregate = selectionAuthority.derivation;
}
