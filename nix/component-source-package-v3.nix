# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  componentId,
  sourceIntent,
  sourceRoot,
}:

let
  lib = pkgs.lib;
  pin = relative: builtins.path {
    path = sourceRoot + "/${relative}";
    name = "${componentId}-${lib.replaceStrings [ "/" ] [ "-" ] relative}";
  };
  files = builtins.listToAttrs (map (relative: {
    name = relative;
    value = toString (pin relative);
  }) sourceIntent.files);
  sharedInputs = builtins.listToAttrs (map (relative: {
    name = relative;
    value = toString (pin relative);
  }) sourceIntent.shared_inputs);
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${componentId}-component-source-package-v3";
    kind = "component-source-package-v3";
    artifactName = "source-package.json";
    expectedFormat = "spaghetti-extractor-component-source-package-v3";
    allowedStatuses = [ ];
    pythonModules = [ "spaghetti_extractor.components.source" ];
    phaseRole = "authority";
    inputs = files // sharedInputs;
    program = ''
      from spaghetti_extractor.components.source import (
          build_component_source_package,
      )

      build_component_source_package(
          lift_unit_id=${builtins.toJSON componentId},
          files={key: inputs[key] for key in ${builtins.toJSON sourceIntent.files}},
          shared_inputs={
              key: inputs[key]
              for key in ${builtins.toJSON sourceIntent.shared_inputs}
          },
          operation_symbols=${builtins.toJSON sourceIntent.operation_symbols},
          out_dir=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest;
  package = phase.derivation;
  artifact = phase.artifact;
}
