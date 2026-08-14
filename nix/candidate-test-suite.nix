{
  pkgs,
  pythonEnv,
  pythonSource,
  id,
  configurationId,
  namePrefix,
  suite,
  candidateBinary,
  authorityGate,
  timeoutSeconds ? 30,
  stripStderrLineRegexes ? [ ],
}:

let
  lib = pkgs.lib;
  suitePayload = builtins.fromJSON (builtins.readFile suite);
  suiteId = suitePayload.suite_id or null;
  caseIds = map (row: row.id) suitePayload.cases;
  wine = pkgs.wineWow64Packages.stableFull;
  runner = pkgs.writeShellApplication {
    name = "spaghetti-extractor-headless-wine-candidate";
    runtimeInputs = [ wine pkgs.xvfb-run pkgs.coreutils pkgs.bash ];
    text = ''
      set -euo pipefail
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      mkdir -p "$HOME"
      # shellcheck disable=SC2016
      exec xvfb-run -a -s '-screen 0 1280x720x24' ${pkgs.bash}/bin/bash -eu -c '
        wineboot -u >/dev/null 2>&1
        set +e
        wine "$1" "''${@:2}"
        status=$?
        set -e
        wineserver -w >/dev/null 2>&1 || true
        exit "$status"
      ' sh ${lib.escapeShellArg (toString candidateBinary)} "$@"
    '';
  };
  suiteResult = import ./stage-b-functional-suite.nix {
    inherit pkgs pythonEnv pythonSource suite caseIds timeoutSeconds
      stripStderrLineRegexes;
    namePrefix = "${namePrefix}-${id}";
    inherit candidateBinary authorityGate;
    candidateCommand = [
      "${runner}/bin/spaghetti-extractor-headless-wine-candidate"
    ];
  };
  aggregate = pkgs.runCommand "${namePrefix}-${id}-candidate-test-receipt-v1" {
    nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    jq -e '
      .format == "spaghetti-extractor-final-authority-gate-v3" and
      .status == "complete" and .authorizing
    ' ${authorityGate}/authority-gate.json >/dev/null
    test -f ${suiteResult.aggregate}/functional-report.json
    test -s ${candidateBinary}
    mkdir -p "$out"
    ln -s ${suiteResult.aggregate} "$out/functional-suite"
    candidate_sha256="$(sha256sum ${candidateBinary} | cut -d ' ' -f 1)"
    authority_sha256="$(sha256sum ${authorityGate}/authority-gate.json | cut -d ' ' -f 1)"
    report_sha256="$(sha256sum ${suiteResult.aggregate}/functional-report.json | cut -d ' ' -f 1)"
    suite_sha256="$(sha256sum ${suite} | cut -d ' ' -f 1)"
    jq -n \
      --arg format spaghetti-extractor-candidate-test-receipt-v1 \
      --arg id ${lib.escapeShellArg id} \
      --arg configuration_id ${lib.escapeShellArg configurationId} \
      --arg suite_id ${lib.escapeShellArg suiteId} \
      --arg candidate_sha256 "$candidate_sha256" \
      --arg authority_gate_sha256 "$authority_sha256" \
      --arg suite_sha256 "$suite_sha256" \
      --arg report_sha256 "$report_sha256" \
      --argjson case_ids ${lib.escapeShellArg (builtins.toJSON caseIds)} '
      {
        format: $format,
        status: "pass",
        id: $id,
        configuration_id: $configuration_id,
        suite_id: $suite_id,
        case_ids: $case_ids,
        bindings: {
          candidate_sha256: $candidate_sha256,
          authority_gate_sha256: $authority_gate_sha256,
          suite_sha256: $suite_sha256,
          functional_report_sha256: $report_sha256
        },
        policy: {
          candidate_only: true,
          original_binary_executed: false,
          final_authority_required_before_execution: true,
          headless_wine_required: true,
          divergence_class: "stage-a-or-candidate-toolchain-red-flag"
        }
      }
    ' > "$out/candidate-test-receipt.json"
  '';
in
assert lib.assertMsg (builtins.isString id && id != "")
  "candidate test suite id must be non-empty";
assert lib.assertMsg (suiteId == id)
  "candidate test suite key must equal suite_id";
assert lib.assertMsg (builtins.isList caseIds && caseIds != [ ])
  "candidate test suite must contain cases";
assert lib.assertMsg (builtins.length caseIds == builtins.length (lib.unique caseIds))
  "candidate test case ids must be unique";
{
  _type = "spaghetti-extractor-candidate-test-suite-v1";
  inherit id suiteId configurationId caseIds aggregate runner suite;
  cases = suiteResult.byName;
  functionalAggregate = suiteResult.aggregate;
}
