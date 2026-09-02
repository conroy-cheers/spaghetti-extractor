# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  namePrefix,
  componentId,
  interfacePackage,
  bindingIntent,
  linkedSemanticModule,
  behavioralCPackage,
  sourcePackage ? null,
  proofClassification ? "machine_overlay",
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${componentId}-component-work-package-v6";
    kind = "component-work-package-v6";
    artifactName = "component-work-package-v6.json";
    expectedFormat = "spaghetti-extractor-component-work-package-v6";
    allowedStatuses = [ "ready" ];
    pythonModules = [
      "spaghetti_extractor.components.work_package_v6"
    ];
    phaseRole = "proposal";
    inputs = (pkgs.lib.optionalAttrs (sourcePackage != null) {
      source_package = sourcePackage;
    }) // {
      interface_package = interfacePackage;
      binding_intent = bindingIntent;
      linked_semantic_module = linkedSemanticModule;
      behavioral_c_package = behavioralCPackage;
    };
    program = ''
      from spaghetti_extractor.components.work_package_v6 import (
          build_component_work_package_v6,
      )

      build_component_work_package_v6(
          component_id=${builtins.toJSON componentId},
          interface_package=inputs["interface_package"],
          binding_intent=inputs["binding_intent"],
          linked_semantic_module=inputs["linked_semantic_module"],
          behavioral_c_package=inputs["behavioral_c_package"],
          source_package=inputs.get("source_package"),
          proof_classification=${builtins.toJSON proofClassification},
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  package = phase.derivation;
  workPackage = phase.artifact;
  semanticSlice = "${phase.derivation}/semantic-slice-v2.json";
}
