# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  namePrefix,
  componentId,
  linkedSemanticModule,
  bindingIntent,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${componentId}-component-semantic-slice-v2";
    kind = "component-semantic-slice-v2";
    artifactName = "semantic-slice-v2.json";
    expectedFormat = "spaghetti-extractor-semantic-slice-v2";
    allowedStatuses = [ ];
    pythonModules = [
      "spaghetti_extractor.components.work_package_v6"
    ];
    phaseRole = "proposal";
    inputs = {
      linked_semantic_module = linkedSemanticModule;
      binding_intent = bindingIntent;
    };
    program = ''
      from spaghetti_extractor.components.work_package_v6 import (
          write_component_semantic_slice_v2,
      )

      write_component_semantic_slice_v2(
          linked_semantic_module=inputs["linked_semantic_module"],
          binding_intent=inputs["binding_intent"],
          out=output,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  semanticSlice = phase.artifact;
}
