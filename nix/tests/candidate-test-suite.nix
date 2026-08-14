{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  authorityGate = pkgs.runCommand
    "spaghetti-extractor-candidate-test-fixture-authority-gate"
    { __contentAddressed = true; }
    ''
      mkdir -p "$out"
      cat > "$out/authority-gate.json" <<'JSON'
      {
        "format": "spaghetti-extractor-final-authority-gate-v3",
        "fixture_only": true,
        "status": "complete",
        "authorizing": true
      }
      JSON
    '';
  candidateBinary =
    "${context.tools.minimalImportCall}/minimal-import-call.exe";
  candidateTest = import ../candidate-test-suite.nix {
    inherit pkgs candidateBinary authorityGate;
    inherit (context) pythonEnv;
    pythonSource = context.sources.fullSource;
    id = "minimal-import-call";
    configurationId = "fixture";
    namePrefix = "spaghetti-extractor-candidate-test-constructor";
    suite = ./fixtures/candidate-test-suite/functional-suite.json;
  };
in
pkgs.runCommand "spaghetti-extractor-candidate-test-suite-check" {
  nativeBuildInputs = [ pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  receipt=${candidateTest.aggregate}/candidate-test-receipt.json
  report=${candidateTest.aggregate}/functional-suite/functional-report.json
  jq -e '
    .format == "spaghetti-extractor-candidate-test-receipt-v1" and
    .status == "pass" and
    .policy.candidate_only and
    (.policy.original_binary_executed | not) and
    .policy.final_authority_required_before_execution and
    .policy.headless_wine_required and
    .case_ids == ["writes-expected-output"]
  ' "$receipt" >/dev/null
  jq -e '
    .format == "stage-b-functional-report-v1" and
    .status == "pass" and
    .counts == {"cases": 1, "failed": 0, "passed": 1} and
    (.oracle.original_runtime_observations | not)
  ' "$report" >/dev/null
  mkdir -p "$out"
  ln -s ${candidateTest.aggregate} "$out/candidate-test"
''
