# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  intent,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-component-lifting-intent-v1";
    kind = "component-lifting-intent-v1";
    artifactName = "component-lifting-intent-v1.json";
    expectedFormat = "spaghetti-extractor-component-lifting-intent-v1";
    allowedStatuses = [ ];
    pythonModules = [ "spaghetti_extractor.components.lifting_intent" ];
    phaseRole = "authority";
    inputs.intent = intent;
    program = ''
      import json

      from spaghetti_extractor.components.lifting_intent import (
          ComponentLiftingIntentV1,
      )
      from spaghetti_extractor.util import write_json

      parsed = ComponentLiftingIntentV1.parse(json.loads(
          inputs["intent"].read_text(encoding="utf-8")
      ))
      write_json(output, parsed.to_payload())
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  validatedIntent = phase.artifact;
}
