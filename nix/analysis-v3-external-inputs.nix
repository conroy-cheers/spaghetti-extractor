{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  binary,
  machineIr,
  binaryIdentity,
  machineImportProfiles ? [ ],
  launchProfileTemplate ? null,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";
assert builtins.isString binaryIdentity && binaryIdentity != "";
assert builtins.isList machineImportProfiles;

let
  lib = pkgs.lib;
  adapterPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_a_external_inputs_v3" ];
    name = "${name}-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  profileArguments = lib.concatMapStringsSep " " (
    profile: "--profile ${lib.escapeShellArg (toString profile)}"
  ) machineImportProfiles;
  launchArgument = lib.optionalString (launchProfileTemplate != null) (
    "--launch-template ${lib.escapeShellArg (toString launchProfileTemplate)}"
  );
  derivation = pkgs.runCommand name (
    {
      nativeBuildInputs = [ pythonEnv ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    // caAttrs
  ) ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export PYTHONPATH=${adapterPythonSource}/src

    ${pythonEnv}/bin/python3 -m spaghetti_extractor.stage_a_external_inputs_v3 \
      --binary ${lib.escapeShellArg (toString binary)} \
      --machine-ir ${lib.escapeShellArg (toString machineIr)} \
      --binary-identity ${lib.escapeShellArg binaryIdentity} \
      ${profileArguments} \
      ${launchArgument} \
      --out "$out"
  '';
  metadata = builtins.fromJSON (builtins.readFile "${derivation}/metadata.json");
in
assert metadata.format == "spaghetti-extractor-external-input-adapter-v3";
assert metadata.binary.identity == binaryIdentity;
{
  inherit derivation metadata;
  externalProfiles = {
    artifact = "${derivation}/external-profiles";
    expectedKind = metadata.external_profiles.artifact_kind;
    expectedRecordIds = metadata.external_profiles.record_ids;
  };
  launchRoots = {
    artifact = "${derivation}/launch-roots";
    expectedKind = metadata.launch_roots.artifact_kind;
    expectedRecordIds = metadata.launch_roots.record_ids;
  };
}
