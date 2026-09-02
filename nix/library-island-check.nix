# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  name,
  targetId,
  linkedSemanticModule,
  releaseHypotheses,
  islandId,
  adoptionIntent,
  behaviorPack,
  catalogSearchIndex,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv name;
    kind = "checked-library-island-v1";
    artifactName = "checked-library-island.json";
    expectedFormat = "spaghetti-extractor-checked-library-island-v1";
    allowedStatuses = [ "complete" "incomplete" "violated" ];
    pythonModules = [ "spaghetti_extractor.libraries.v4_activation" ];
    phaseRole = "authority";
    inputs = {
      linked_semantic_module = linkedSemanticModule;
      release_hypotheses = releaseHypotheses;
      adoption_intent = adoptionIntent;
      behavior_pack = behaviorPack;
      catalog_search_index = catalogSearchIndex;
    };
    program = ''
      from spaghetti_extractor.libraries.v4_activation import (
          check_library_island_v1,
      )

      check_library_island_v1(
          target_id=${builtins.toJSON targetId},
          linked_semantic_module=(
              inputs["linked_semantic_module"] / "linked-semantic-module.json"
          ),
          release_hypotheses=inputs["release_hypotheses"],
          island_id=${builtins.toJSON islandId},
          adoption_intent=inputs["adoption_intent"],
          implementation=inputs["behavior_pack"],
          catalog_search_index=inputs["catalog_search_index"],
          out=output,
      )
    '';
  };
in
phase.derivation
