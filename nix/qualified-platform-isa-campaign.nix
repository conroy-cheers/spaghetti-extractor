# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  kernelCache,
  semanticKernel,
  isaFormInventory,
  bochsRunner,
  namePrefix ? "spaghetti-extractor",
}:

let
  preparation = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-qualified-platform-isa-preparation-v1";
    kind = "qualified-platform-isa-preparation";
    artifactName = "catalog-enrichment.json";
    expectedFormat =
      "spaghetti-extractor-side-isa-executable-catalog-enrichment-v1";
    allowedStatuses = [ "complete" "incomplete_unresolved_encodings" ];
    pythonModules = [
      "spaghetti_extractor.qualified_platform.isa_campaign"
      "spaghetti_extractor.qualified_platform.isa_form_replay"
    ];
    pythonExtraPaths = [ "spaghetti_extractor/lean/SpaghettiExtractor/ISA" ];
    extraNativeBuildInputs = [ pkgs.lean4 ];
    phaseRole = "developer";
    inputs = {
      semantic_kernel = semanticKernel;
      isa_form_inventory = isaFormInventory;
    };
    program = ''
      from spaghetti_extractor.qualified_platform.isa_campaign import (
          write_qualified_platform_isa_campaign_preparation_v1,
      )

      write_qualified_platform_isa_campaign_preparation_v1(
          inventory_path=inputs["isa_form_inventory"],
          semantic_kernel_path=inputs["semantic_kernel"],
          out=output,
      )
    '';
  };
  corpus = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-qualified-platform-isa-corpus-v1";
    kind = "qualified-platform-isa-corpus";
    artifactName = "manifest.json";
    expectedFormat = "spaghetti-extractor-generated-isa-corpus-manifest-v1";
    allowedStatuses = [ ];
    pythonModules = [ "spaghetti_extractor.isa.cli" ];
    pythonExtraPaths = [ "spaghetti_extractor/lean/SpaghettiExtractor/ISA" ];
    phaseRole = "authority";
    inputs = { catalog = preparation.artifact; };
    program = ''
      from spaghetti_extractor.isa.cli import generate_isa_corpus

      generate_isa_corpus(
          catalog=inputs["catalog"],
          seed=0,
          out=output.parent,
      )
      import json
      manifest = json.loads(output.read_text(encoding="utf-8"))
      if manifest.get("trust", {}).get("proof_authority") is not False:
          raise SystemExit("generated ISA corpus claimed proof authority")
    '';
  };
  qualificationGraph = import ./isa-qualification-graph.nix {
    inherit
      pkgs
      pythonEnv
      kernelCache
      semanticKernel
      bochsRunner
      ;
    name = "${namePrefix}-qualified-platform-isa";
    corpus = "${corpus.derivation}/corpus.json";
    generatedCorpus = "${corpus.derivation}/generated-corpus.json";
    requirements = null;
    leanShardCount = 32;
  };
in
{
  inherit qualificationGraph;
  inherit (preparation) manifest phasePythonSource;
  preparation = preparation.derivation;
  corpus = corpus.derivation;
  proposal = "${preparation.derivation}/catalog-proposal.json";
  enrichment = preparation.artifact;
  replay = "${preparation.derivation}/isa-form-replay.json";
  qualificationCertificate =
    "${qualificationGraph.qualification}/qualification-certificate.json";
  fullQualification =
    "${qualificationGraph.qualification}/qualification.json";
  aggregate = qualificationGraph.bundle;
}
