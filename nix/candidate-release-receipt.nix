# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  namePrefix,
  structuralReceipt,
  isaQualification,
  candidateBinary,
  componentReleaseGate,
}:

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.policy_gates" ];
    name = "${namePrefix}-release-policy-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-release-acceptance-receipt-v1" {
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
    ${structuralReceipt}/structural-executable.json \
    ${isaQualification} \
    ${candidateBinary} \
    ${componentReleaseGate}/component-hybrid-release-gate-v1.json \
    "$out/release-acceptance.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.candidate.policy_gates import (
      build_release_acceptance_receipt,
      write_policy_receipt,
  )

  structural, isa, candidate, component_gate, output = sys.argv[1:]
  receipt = build_release_acceptance_receipt(
      structural_receipt=pathlib.Path(structural),
      isa_qualification=pathlib.Path(isa),
      candidate_binary=pathlib.Path(candidate),
      component_release_gate=pathlib.Path(component_gate),
  )
  write_policy_receipt(pathlib.Path(output), receipt)
  PY
  jq -e '
    .format == "spaghetti-extractor-release-acceptance-v1" and
    (.status == "complete" or .status == "incomplete") and
    .executable and
    (.release_accepted == (.status == "complete")) and
    (.bindings.candidate_sha256 | test("^[0-9a-f]{64}$"))
  ' "$out/release-acceptance.json" >/dev/null
''
