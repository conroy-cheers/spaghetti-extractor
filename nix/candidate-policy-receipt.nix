# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  namePrefix,
  machineIr,
  machineIrManifest,
  fallbackCapabilityAnalysis,
  activationPlan,
  structuralArtifacts,
}:

let
  lib = pkgs.lib;
  expectedFamilies = [
    "callbacks"
    "exceptional_transitions"
    "external_sites"
    "inductive_authority"
    "parametric_summaries"
    "root_closure"
    "semantic_index"
    "target_certificates"
  ];
  pythonClosure = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.policy_gates" ];
    name = "${namePrefix}-structural-policy-python-closure";
  };
  artifactJson = builtins.toJSON
    (lib.mapAttrs (_: value: toString value) structuralArtifacts);
in
assert lib.assertMsg
  (builtins.attrNames structuralArtifacts == expectedFamilies)
  "structural policy requires exactly the canonical checked artifact families";
pkgs.runCommand "${namePrefix}-structural-executable-receipt-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${pythonClosure}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${lib.escapeShellArg artifactJson} \
    ${fallbackCapabilityAnalysis}/fallback-capability-analysis.json \
    ${activationPlan}/activation-plan.json \
    ${machineIr} \
    ${machineIrManifest} \
    "$out/structural-executable.json" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.candidate.policy_gates import (
      build_structural_executable_receipt,
      write_policy_receipt,
  )

  artifacts, fallback, activation, machine_ir, manifest, output = sys.argv[1:]
  receipt = build_structural_executable_receipt(
      artifacts={
          key: pathlib.Path(value)
          for key, value in json.loads(artifacts).items()
      },
      fallback_capability_analysis=pathlib.Path(fallback),
      activation_plan=pathlib.Path(activation),
      machine_ir=pathlib.Path(machine_ir),
      machine_ir_manifest=pathlib.Path(manifest),
  )
  write_policy_receipt(pathlib.Path(output), receipt)
  PY
  jq -e '
    .format == "spaghetti-extractor-structural-executable-v1" and
    (.status == "complete" or .status == "incomplete") and
    (.executable == (.status == "complete")) and
    (.release_accepted | not) and
    (.bindings.machine_ir_sha256 | test("^[0-9a-f]{64}$")) and
    (.bindings.machine_ir_manifest_sha256 | test("^[0-9a-f]{64}$")) and
    (.families | length) == 9
  ' "$out/structural-executable.json" >/dev/null
''
