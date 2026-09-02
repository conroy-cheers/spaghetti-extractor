{ pkgs, pythonEnv }:

let
  environment = import ../external-environment-intent.nix {
    inherit pkgs pythonEnv;
    namePrefix = "spaghetti-extractor-external-environment-fixture";
    environmentId = "fixture-win32";
    profilePacks = [
      ../../profiles/pe32-msvcrt-machine-runtime-v1.json
    ];
    interfacePacks = [ ];
    launchProfile =
      ../../profiles/pe32-win32-console-launch-assumptions-v1.json;
    boundaryIntents = { };
    processTermination = {
      dll = "msvcrt.dll";
      symbol = "exit";
    };
  };
in
pkgs.runCommand "spaghetti-extractor-external-environment-check" {
  nativeBuildInputs = [ pkgs.jq ];
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-external-environment-intent-v1" and
    .status == "complete" and .id == "fixture-win32" and
    (.profile_packs.runtime | length) == 1 and
    .runtime_support_policy.process_termination.symbol == "exit" and
    (.intent_sha256 | test("^[0-9a-f]{64}$"))
  ' ${environment.intent} >/dev/null
  jq -e '
    .format == "spaghetti-extractor-external-environment-analysis-projection-v1" and
    .authority == "none" and
    (.projection_sha256 | test("^[0-9a-f]{64}$"))
  ' ${environment.analysisProjection} >/dev/null
  touch "$out"
''
