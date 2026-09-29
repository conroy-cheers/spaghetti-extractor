# spaghetti-extractor-python-role: authority
{ pkgs, pythonEnv, abiProfile, effectProfile, name ? "spaghetti-extractor-machine-import-effect-profile" }:
let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv name;
    kind = "machine-import-effect-profile";
    artifactName = "machine-import-profile.json";
    expectedFormat = "spaghetti-extractor-static-machine-import-profile-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.external.machine_import_effect_profile" ];
    phaseRole = "authority";
    inputs = { abi_profile = abiProfile; effect_profile = effectProfile; };
    program = ''
      from spaghetti_extractor.external.machine_import_effect_profile import compose_native_callthrough_profile
      compose_native_callthrough_profile(
          abi_profile=inputs["abi_profile"], effect_profile=inputs["effect_profile"], out=output)
    '';
  };
in phase.derivation
