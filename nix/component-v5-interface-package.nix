# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  componentId,
  intent,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${componentId}-component-interface-v5";
    kind = "component-interface-v5";
    artifactName = "component-interface-intent-v1.json";
    expectedFormat = "spaghetti-extractor-component-interface-intent-v1";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.components.interface_package_v5"
    ];
    phaseRole = "authority";
    inputs.interface_intent = intent;
    program = ''
      import json

      from spaghetti_extractor.components.interface_package_v5 import (
          ComponentInterfaceIntentV1,
          write_component_interface_package_v5,
      )

      intent = ComponentInterfaceIntentV1.parse(
          json.loads(inputs["interface_intent"].read_text(encoding="utf-8"))
      )
      if intent.component_id != ${builtins.toJSON componentId}:
          raise SystemExit("component interface intent identity is stale")
      write_component_interface_package_v5(output.parent, intent)
    '';
  };
in
{
  inherit (phase) derivation manifest;
  intent = phase.artifact;
  interface = "${phase.derivation}/portable-component-interface-v5.json";
  schema = "${phase.derivation}/boundary-schema-v1.json";
  operations = "${phase.derivation}/operations";
}
