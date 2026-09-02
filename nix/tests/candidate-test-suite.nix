{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  candidateBinary =
    "${context.tools.minimalImportCall}/minimal-import-call.exe";
  nativeRealization = pkgs.runCommand
    "spaghetti-extractor-candidate-test-fixture-native-realization"
    { nativeBuildInputs = [ pkgs.coreutils ]; __contentAddressed = true; }
    ''
      mkdir -p "$out"
      candidate_sha256="$(sha256sum ${candidateBinary} | cut -d ' ' -f 1)"
      cat > "$out/native-realization.json" <<JSON
      {
        "format": "spaghetti-extractor-native-realization-v2",
        "status": "complete",
        "ready_for_observation": true,
        "blockers": [],
        "candidate": {
          "filename": "minimal-import-call.exe",
          "sha256": "$candidate_sha256"
        }
      }
      JSON
    '';
  candidateTest = import ../candidate-test-suite.nix {
    inherit pkgs candidateBinary nativeRealization;
    inherit (context) pythonEnv;
    pythonSource = context.sources.fullSource;
    id = "minimal-import-call";
    configurationId = "fixture";
    namePrefix = "spaghetti-extractor-candidate-test-constructor";
    suite = ./fixtures/candidate-test-suite/candidate-suite.json;
  };
in
pkgs.runCommand "spaghetti-extractor-candidate-test-suite-check" {
  nativeBuildInputs = [ pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  receipt=${candidateTest.aggregate}/candidate-test-receipt.json
  report=${candidateTest.aggregate}/test-results/candidate-test-report.json
  jq -e '
    .format == "spaghetti-extractor-candidate-test-receipt-v1" and
    .status == "pass" and
    .policy.candidate_only and
    (.policy.original_binary_executed | not) and
    .policy.native_realization_required_before_execution and
    .policy.headless_wine_required and
    .case_ids == ["writes-expected-output"]
  ' "$receipt" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-candidate-test-report-v1" and
    .status == "pass" and
    .counts == {"cases": 1, "failed": 0, "passed": 1} and
    (.oracle.original_runtime_observations | not)
  ' "$report" >/dev/null
  mkdir -p "$out"
  ln -s ${candidateTest.aggregate} "$out/candidate-test"
''
