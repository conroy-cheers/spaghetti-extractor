# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  root,
  kind,
}:

let
  format = if kind == "interface"
    then "spaghetti-extractor-component-interface-index-v5"
    else if kind == "machine_binding"
    then "spaghetti-extractor-component-machine-binding-index-v5"
    else throw "unsupported component V5 index kind ${kind}";
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-component-${kind}-index-v5";
    kind = "component-${kind}-index-v5";
    artifactName = "component-${kind}-index-v5.json";
    expectedFormat = format;
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [ "spaghetti_extractor.components.indexes_v5" ];
    phaseRole = "authority";
    inputs = { inherit root; };
    program = ''
      from spaghetti_extractor.components.indexes_v5 import (
          load_component_intent_index_v5,
      )
      from spaghetti_extractor.util import write_json

      index = load_component_intent_index_v5(
          inputs["root"] / "index.json",
          kind=${builtins.toJSON kind},
      )
      write_json(output, index.to_payload())
    '';
  };
in
{
  inherit (phase) derivation manifest;
  index = phase.artifact;
}
