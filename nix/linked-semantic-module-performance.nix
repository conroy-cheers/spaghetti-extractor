# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  semanticObject,
  behavioralRoots,
  original,
  canonical,
  namePrefix,
  maximumWorklistSteps ? 1000000,
  maximumCpuMilliseconds ? 30000,
  maximumPreparedLinkMilliseconds ? 5000,
}:

assert builtins.isInt maximumWorklistSteps && maximumWorklistSteps > 0;
assert builtins.isInt maximumCpuMilliseconds && maximumCpuMilliseconds > 0;
assert builtins.isInt maximumPreparedLinkMilliseconds
  && maximumPreparedLinkMilliseconds > 0;

import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-linked-semantic-module-performance-check";
  kind = "linked-semantic-module-performance";
  artifactName = "semantic-link-performance.json";
  expectedFormat = "spaghetti-extractor-semantic-link-performance-v2";
  allowedStatuses = [ ];
  pythonModules = [ "spaghetti_extractor.semantic_link.benchmark" ];
  phaseRole = "developer";
  inputs = {
    semantic_object = semanticObject;
    behavioral_roots = behavioralRoots;
    inherit original canonical;
  };
  program = ''
    import argparse
    from spaghetti_extractor.semantic_link.benchmark import (
        check_semantic_link_performance,
    )

    check_semantic_link_performance(argparse.Namespace(
        semantic_object=inputs["semantic_object"],
        behavioral_roots=inputs["behavioral_roots"],
        original=inputs["original"],
        canonical=inputs["canonical"],
        maximum_worklist_steps=${toString maximumWorklistSteps},
        maximum_cpu_milliseconds=${toString maximumCpuMilliseconds},
        maximum_prepared_link_milliseconds=${toString maximumPreparedLinkMilliseconds},
        observations=output,
    ))
  '';
}
