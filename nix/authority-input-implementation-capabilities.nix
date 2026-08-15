# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  semanticIndex,
  isaQualification,
  capabilityAnalysis,
  namePrefix,
  capabilityId ? "machine-ir-fallback-v3",
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "authority";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.authority_inputs.implementation_capabilities"
    ];
    name = "${namePrefix}-implementation-capabilities-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-implementation-capabilities-v3" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${phasePythonSource}/src

  ${pythonEnv}/bin/python3 -m \
    spaghetti_extractor.authority_inputs.implementation_capabilities \
    --machine-ir ${machineIr}/machine-ir.jsonl \
    --machine-ir-manifest ${machineIr}/machine-ir-manifest.json \
    --semantic-index ${semanticIndex} \
    --isa-qualification ${isaQualification} \
    --capability-analysis \
      ${capabilityAnalysis}/fallback-capability-analysis.json \
    --capability-id ${lib.escapeShellArg capabilityId} \
    --out "$out"

  jq -e '
    .format == "spaghetti-extractor-fallback-engine-capability-manifest-v3" and
    (.status == "complete" or .status == "incomplete" or .status == "violated") and
    (.implementation_sha256 | test("^[0-9a-f]{64}$")) and
    .coverage.projected_units <= .coverage.required_units and
    (.built_files | length) == 0 and
    (.package.capability_analysis_sha256 | test("^[0-9a-f]{64}$")) and
    (.issues | type == "array")
  ' "$out/engine-capability-manifest.json" >/dev/null
''
