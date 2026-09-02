# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  qualifiedPlatform,
  campaigns,
  namePrefix ? "spaghetti-extractor",
}:

assert builtins.isAttrs campaigns;
assert builtins.length (builtins.attrNames campaigns) >= 2;

let
  lib = pkgs.lib;
  campaignIds = builtins.sort builtins.lessThan (builtins.attrNames campaigns);
  fields = [ "requirements" "qualification" "selection-certificate" ];
  inputName = campaignId: field:
    "${lib.replaceStrings [ "." ] [ "-" ] campaignId}-${field}";
  campaignInputs = builtins.listToAttrs (lib.concatMap (campaignId:
    map (field: {
      name = inputName campaignId field;
      value = campaigns.${campaignId}.${field};
    }) fields
  ) campaignIds);
  campaignIndex = builtins.listToAttrs (map (campaignId: {
    name = campaignId;
    value = {
      requirements = inputName campaignId "requirements";
      qualification = inputName campaignId "qualification";
      selection_certificate = inputName campaignId "selection-certificate";
    };
  }) campaignIds);
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-qualified-platform-migration-parity-v1";
    kind = "qualified-platform-migration-parity";
    artifactName = "qualified-platform-migration-parity.json";
    expectedFormat =
      "spaghetti-extractor-qualified-platform-migration-parity-v1";
    allowedStatuses = [ "complete" "violated" ];
    pythonModules = [
      "spaghetti_extractor.qualified_platform.migration_parity"
    ];
    phaseRole = "developer";
    inputs = campaignInputs // { qualified_platform = qualifiedPlatform; };
    program = ''
      from spaghetti_extractor.qualified_platform.migration_parity import (
          write_qualified_platform_migration_parity_v1,
      )

      campaign_index = json.loads(
          ${builtins.toJSON (builtins.toJSON campaignIndex)}
      )
      write_qualified_platform_migration_parity_v1(
          platform_path=inputs["qualified_platform"],
          campaigns={
              campaign_id: {
                  field: inputs[input_name]
                  for field, input_name in paths.items()
              }
              for campaign_id, paths in campaign_index.items()
          },
          out=output,
      )
    '';
  };
in
{
  inherit (phase) derivation artifact manifest phasePythonSource;
  parity = phase.artifact;
}
