# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  namePrefix,
  machineImportProfiles,
}:

let
  lib = pkgs.lib;
  profileInputs = builtins.listToAttrs (lib.imap0 (index: profile: {
    name = "profile_${toString index}";
    value = profile;
  }) machineImportProfiles);
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-machine-import-profile-bundle-v1";
    kind = "machine-import-profile-bundle-v1";
    artifactName = "profile.json";
    expectedFormat = "spaghetti-extractor-static-machine-import-profile-v2";
    allowedStatuses = [ ];
    pythonModules = [
      "spaghetti_extractor.external.machine_import_profiles"
    ];
    phaseRole = "candidate";
    inputs = profileInputs;
    program = ''
      from spaghetti_extractor.external.machine_import_profiles import (
          load_machine_import_profile_set,
          materialize_v2_profile_contract,
      )
      from spaghetti_extractor.util import write_json

      selected = load_machine_import_profile_set(
          [inputs[name] for name in sorted(inputs)]
      )
      write_json(output, {
          "format": "spaghetti-extractor-static-machine-import-profile-v2",
          "id": ${builtins.toJSON "${namePrefix}-machine-import-profile-bundle-v1"},
          "provenance": {
              "kind": "resolved_machine_import_profile_graph_v1",
              "source_profiles": [
                  {"id": profile.profile_id, "sha256": profile.sha256}
                  for profile in selected.profiles
              ],
          },
          "machine_import_call_contracts": [
              materialize_v2_profile_contract(contract)
              for contract in selected.contracts
          ],
      })
    '';
  };
in
phase.derivation
