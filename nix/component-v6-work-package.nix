# spaghetti-extractor-python-role: proposal
args@{
  pkgs,
  pythonEnv,
  namePrefix,
  componentId,
  interfacePackage,
  bindingIntent ? null,
  linkedSemanticModule,
  behavioralCPackage ? null,
  sourcePackage ? null,
  proofClassification ? "machine_overlay",
  callerDefinition ? null,
  exactSlice ? null,
  bisimulationIntent ? null,
  relationIntent ? null,
}:

assert bindingIntent != null || callerDefinition != null;
assert (behavioralCPackage != null && exactSlice == null)
  || (behavioralCPackage == null && exactSlice != null && callerDefinition != null);
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
    }) // pkgs.lib.optionalAttrs (callerDefinition != null) {
      caller_definition = callerDefinition;
    } // pkgs.lib.optionalAttrs (bindingIntent != null) {
      binding_intent = bindingIntent;
    } // pkgs.lib.optionalAttrs (behavioralCPackage != null) {
      behavioral_c_package = behavioralCPackage;
    } // pkgs.lib.optionalAttrs (exactSlice != null) {
      exact_c_slice = exactSlice;
    } // pkgs.lib.optionalAttrs (bisimulationIntent != null) {
      bisimulation_intent = bisimulationIntent;
    } // pkgs.lib.optionalAttrs (relationIntent != null) {
      relation_intent = relationIntent;
    } // {
      interface_package = interfacePackage;
      linked_semantic_module = linkedSemanticModule;
    };
    program = ''
      import json
      from spaghetti_extractor.components.work_package_v6 import (
          build_component_work_package_v6,
      )

      build_component_work_package_v6(
          component_id=${builtins.toJSON componentId},
          interface_package=inputs["interface_package"],
          binding_intent=inputs.get("binding_intent"),
          linked_semantic_module=inputs["linked_semantic_module"],
          behavioral_c_package=inputs.get("behavioral_c_package"),
          exact_c_slice=inputs.get("exact_c_slice"),
          bisimulation_intent=inputs.get("bisimulation_intent"),
          relation_intent=inputs.get("relation_intent"),
          source_package=inputs.get("source_package"),
          proof_classification=${builtins.toJSON proofClassification},
          caller_definition=${if callerDefinition == null then "None" else ''json.loads(inputs["caller_definition"].read_text())''},
          out=output.parent,
      )
    '';
  };
in
{
  withCallerDefinition = definition: import ./component-v6-work-package.nix
    (args // { callerDefinition = definition; });
  inherit (phase) derivation manifest artifact;
  package = phase.derivation;
  workPackage = phase.artifact;
  semanticSlice = "${phase.derivation}/semantic-slice-v2.json";
}
