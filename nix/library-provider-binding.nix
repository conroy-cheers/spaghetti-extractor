# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  name,
  linkedSemanticModule,
  releaseHypotheses,
  checkedIsland,
  behaviorPack,
  catalogSearchIndex,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv name;
    kind = "library-provider-binding";
    artifactName = "component-machine-binding-intent-v1.json";
    expectedFormat =
      "spaghetti-extractor-component-machine-binding-intent-v1";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.libraries.component_v5"
    ];
    phaseRole = "authority";
    inputs = {
      linked_semantic_module = linkedSemanticModule;
      release_hypotheses = releaseHypotheses;
      checked_island = checkedIsland;
      behavior_pack = behaviorPack;
      catalog_search_index = catalogSearchIndex;
    };
    program = ''
      from spaghetti_extractor.libraries.component_v5 import (
          build_checked_library_provider_binding_v1,
      )

      build_checked_library_provider_binding_v1(
          linked_semantic_module=(
              inputs["linked_semantic_module"] /
              "linked-semantic-module.json"
          ),
          release_hypotheses=inputs["release_hypotheses"],
          checked_island=inputs["checked_island"],
          behavior_pack=inputs["behavior_pack"],
          catalog_search_index=inputs["catalog_search_index"],
          out_dir=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  bindingIntent = phase.artifact;
  interfacePackage = "${phase.derivation}/interface";
  checkedIsland = "${phase.derivation}/checked-library-island-v1.json";
}
