# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  namePrefix,
  environmentId,
  profilePacks,
  interfacePacks ? [ ],
  launchProfile,
  boundaryIntents ? { },
  processTermination ? null,
  targetAbi ? "pe32-i686-mingw32",
  targetDataLayout ? "pe32-ilp32-v1",
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
    value = boundaryIntents.${subject};
    inherit subject;
  }) (builtins.attrNames boundaryIntents);
  inputAttrs = builtins.listToAttrs (
    map (row: { inherit (row) name value; })
      (runtimeInputs ++ interfaceInputs ++ boundaryInputs)
  ) // {
    launch = launchProfile;
  };
  boundaryNames = builtins.listToAttrs (map (row: {
    name = row.subject;
    value = row.name;
  }) boundaryInputs);
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-external-environment-intent-v1";
    kind = "external-environment-intent";
    artifactName = "external-environment-intent.json";
    expectedFormat = "spaghetti-extractor-external-environment-intent-v1";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.external.environment" ];
    phaseRole = "authority";
    inputs = inputAttrs;
    program = ''
      from spaghetti_extractor.external.environment import (
          write_external_environment_intent,
      )

      runtime_names = ${builtins.toJSON (map (row: row.name) runtimeInputs)}
      interface_names = ${builtins.toJSON (map (row: row.name) interfaceInputs)}
      boundary_names = ${builtins.toJSON boundaryNames}
      write_external_environment_intent(
          environment_id=${builtins.toJSON environmentId},
          runtime_profile_packs=[inputs[name] for name in runtime_names],
          interface_profile_packs=[inputs[name] for name in interface_names],
          launch_profile=inputs["launch"],
          boundary_intents={
              subject: inputs[name]
              for subject, name in boundary_names.items()
          },
          process_termination=json.loads(
              ${builtins.toJSON (builtins.toJSON processTermination)}
          ),
          target_abi=${builtins.toJSON targetAbi},
          target_data_layout=${builtins.toJSON targetDataLayout},
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest;
  intent = phase.artifact;
  analysisProjection = "${phase.derivation}/analysis-projection.json";
}
