{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  machineIrManifest,
  launchRoots,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  adapterPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.authority_inputs.standard_evidence" ];
    name = "${name}-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
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

    ${pythonEnv}/bin/python3 -m spaghetti_extractor.authority_inputs.standard_evidence \
      --machine-ir-manifest ${lib.escapeShellArg (toString machineIrManifest)} \
      --launch-roots ${lib.escapeShellArg (toString launchRoots)} \
      --out "$out"
  '';
  metadata = builtins.fromJSON (builtins.readFile "${derivation}/metadata.json");
in
assert metadata.format == "spaghetti-extractor-standard-evidence-v3";
{
  inherit derivation metadata;
  targetHints = {
    artifact = "${derivation}/target-hints";
    expectedKind = metadata.target_hints.artifact_kind;
    expectedRecordIds = metadata.target_hints.record_ids;
  };
  inductiveInputs = {
    artifact = "${derivation}/inductive-inputs";
    expectedKind = metadata.inductive_inputs.artifact_kind;
    expectedRecordIds = metadata.inductive_inputs.record_ids;
  };
}
