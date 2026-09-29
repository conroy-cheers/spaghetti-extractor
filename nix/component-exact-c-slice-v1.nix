# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  componentId,
  transferPlan,
  bindingIntent,
  dependencyBindingIntents ? { },
  bisimulationIntent ? null,
  summaryEntryRvas ? [ ],
  namePrefix,
}:

assert builtins.isList summaryEntryRvas && builtins.all
  (rva: builtins.isInt rva && rva >= 0 && rva < 4294967296) summaryEntryRvas;
let
  dependencyIds = builtins.sort builtins.lessThan (
    builtins.attrNames dependencyBindingIntents
  );
  dependencyInputs = builtins.foldl' (result: dependencyId:
    result // {
      "dependency_binding_${dependencyId}" =
        dependencyBindingIntents.${dependencyId};
    }
  ) { } dependencyIds;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${componentId}-component-exact-c-slice-v1";
    kind = "component-exact-c-slice-v1";
    artifactName = "component-exact-c-slice-v1.json";
    expectedFormat = "spaghetti-extractor-component-exact-c-slice-v1";
    allowedStatuses = [ ];
    pythonModules = [
      "spaghetti_extractor.components.component_exact_c_slice"
    ];
    phaseRole = "candidate";
    inputs = ({
      transfer_plan = transferPlan;
      binding_intent = bindingIntent;
    } // dependencyInputs // pkgs.lib.optionalAttrs (bisimulationIntent != null) {
      bisimulation_intent = bisimulationIntent;
    });
    program = ''
      from spaghetti_extractor.components.component_exact_c_slice import (
          materialize_component_exact_c_slice_v1,
      )

      materialize_component_exact_c_slice_v1(
          transfer_plan=inputs["transfer_plan"],
          binding_intent=inputs["binding_intent"],
          dependency_binding_intents={
              component_id: inputs[f"dependency_binding_{component_id}"]
              for component_id in ${builtins.toJSON dependencyIds}
          },
          bisimulation_intent=inputs.get("bisimulation_intent"),
          summary_entry_rvas=${builtins.toJSON summaryEntryRvas},
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  exactCSlice = phase.artifact;
}
