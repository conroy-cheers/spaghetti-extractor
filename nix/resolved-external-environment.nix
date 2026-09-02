# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  intent,
  moduleInterface,
  profilePacks,
  interfacePacks ? [ ],
  boundaryIntents ? { },
  boundaryPackages ? { },
  staticAuthority ? { },
}:

let
  lib = pkgs.lib;
  indexed = prefix: values: lib.imap0 (index: value: {
    name = "${prefix}_${lib.fixedWidthNumber 3 index}";
    inherit value;
  }) values;
  runtimeInputs = indexed "runtime" profilePacks;
  interfaceInputs = indexed "interface" interfacePacks;
  boundaryInputs = lib.imap0 (index: subject: {
    name = "boundary_${lib.fixedWidthNumber 3 index}";
    value = boundaryPackages.${subject};
    inherit subject;
  }) (builtins.attrNames boundaryPackages);
  boundaryIntentInputs = lib.imap0 (index: subject: {
    name = "boundary_intent_${lib.fixedWidthNumber 3 index}";
    value = boundaryIntents.${subject};
    inherit subject;
  }) (builtins.attrNames boundaryIntents);
  authorityInputs = lib.imap0 (index: authorityName: {
    name = "authority_${lib.fixedWidthNumber 3 index}";
    value = staticAuthority.${authorityName};
    inherit authorityName;
  }) (builtins.attrNames staticAuthority);
  inputAttrs = builtins.listToAttrs (
    map (row: { inherit (row) name value; })
      (runtimeInputs ++ interfaceInputs ++ boundaryIntentInputs
        ++ boundaryInputs ++ authorityInputs)
  ) // {
    environment_intent = intent;
    module_interface = "${moduleInterface}/module-interface.json";
  };
  namesFor = key: rows: builtins.listToAttrs (map (row: {
    name = row.${key};
    value = row.name;
  }) rows);
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-resolved-external-environment-v1";
    kind = "resolved-external-environment";
    artifactName = "resolved-external-environment.json";
    expectedFormat = "spaghetti-extractor-resolved-external-environment-v1";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [ "spaghetti_extractor.external.environment" ];
    phaseRole = "authority";
    inputs = inputAttrs;
    program = ''
      from spaghetti_extractor.external.environment import (
          write_resolved_external_environment,
      )

      runtime_names = ${builtins.toJSON (map (row: row.name) runtimeInputs)}
      interface_names = ${builtins.toJSON (map (row: row.name) interfaceInputs)}
      boundary_names = ${builtins.toJSON (namesFor "subject" boundaryInputs)}
      boundary_intent_names = ${builtins.toJSON (namesFor "subject" boundaryIntentInputs)}
      authority_names = ${builtins.toJSON (namesFor "authorityName" authorityInputs)}
      write_resolved_external_environment(
          intent_path=inputs["environment_intent"],
          module_interface_path=inputs["module_interface"],
          runtime_profile_packs=[inputs[name] for name in runtime_names],
          interface_profile_packs=[inputs[name] for name in interface_names],
          boundary_intent_paths={
              subject: inputs[name]
              for subject, name in boundary_intent_names.items()
          },
          boundary_packages={
              subject: inputs[name]
              for subject, name in boundary_names.items()
          },
          static_authority_paths={
              name: inputs[input_name]
              for name, input_name in authority_names.items()
          },
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
}
