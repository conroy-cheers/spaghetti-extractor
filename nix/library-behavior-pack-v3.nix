# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  name,
  implementation,
  interfaceIntent,
  sourcePackage,
  qualification,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv name;
    kind = "reusable-library-behavior-pack-v3";
    artifactName = "behavior-pack.json";
    expectedFormat = "spaghetti-extractor-reusable-library-behavior-pack-v3";
    allowedStatuses = [ "checked" ];
    pythonModules = [
      "spaghetti_extractor.libraries.behavior_pack_v3"
    ];
    phaseRole = "authority";
    inputs = {
      inherit implementation qualification;
      interface_intent = interfaceIntent;
      source_package = sourcePackage;
    };
    program = ''
      from spaghetti_extractor.libraries.behavior_pack_v3 import (
          build_reusable_library_behavior_pack_v3,
      )

      build_reusable_library_behavior_pack_v3(
          implementation=inputs["implementation"],
          interface_intent=inputs["interface_intent"],
          source_package=inputs["source_package"],
          qualification=inputs["qualification"],
          out_dir=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest;
  behaviorPack = phase.derivation;
  artifact = phase.artifact;
}
