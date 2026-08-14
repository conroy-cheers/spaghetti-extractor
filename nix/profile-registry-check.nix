# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  pythonSource,
  profiles,
}:

let
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "authority";
    inherit pkgs;
    modules = [ "spaghetti_extractor.profiles.registry" ];
    name = "spaghetti-extractor-profile-registry-python-closure";
  };
in
pkgs.runCommand "spaghetti-extractor-profile-registry-check" {
  nativeBuildInputs = [ pythonEnv ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONPATH=${phaseSource}/src
  python - ${profiles} "$out" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.profiles.registry import validate_profile_inventory

  registry = validate_profile_inventory(pathlib.Path(sys.argv[1]))
  output = pathlib.Path(sys.argv[2])
  output.mkdir(parents=True)
  (output / "profile-registry.json").write_text(
      json.dumps({
          "format": "spaghetti-extractor-checked-profile-registry-v1",
          "status": "pass",
          "profiles": [
              {
                  "path": item.registration.path,
                  "role": item.registration.role,
                  "validator_id": item.registration.validator_id,
              }
              for item in registry.profiles
          ],
      }, indent=2, sort_keys=True) + "\n",
      encoding="utf-8",
  )
  PY
''
