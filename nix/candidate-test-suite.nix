# spaghetti-extractor-python-role: operator
{
  pkgs,
  pythonEnv,
  pythonSource,
  id,
  configurationId,
  namePrefix,
  suite,
  candidateBinary,
  nativeRealization,
  runtimeData ? null,
  timeoutSeconds ? 30,
  stripStderrLineRegexes ? [ ],
}:

let
  lib = pkgs.lib;
  suitePayload = builtins.fromJSON (builtins.readFile suite);
  suiteId = suitePayload.suite_id or null;
  caseIds = map (row: row.id) suitePayload.cases;
  wine = pkgs.wineWow64Packages.stableFull;
  headlessWayland = import ./headless-wayland.nix { inherit pkgs; };
  executionGate = import ./ca-json-receipt-gate.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${id}-native-realization-execution-gate";
    kind = "native-realization-execution";
    artifact = "${nativeRealization}/native-realization.json";
    artifactName = "native-realization.json";
    expectedFormat = "spaghetti-extractor-native-realization-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.native_realization.receipt_v2" ];
    phaseRole = "candidate";
    inputs.native_realization = nativeRealization;
    program = ''
      from spaghetti_extractor.native_realization.receipt_v2 import (
          NativeRealizationV2,
      )

      realization = NativeRealizationV2.load(artifact_path)
      if (
          realization.payload["ready_for_observation"] is not True
          or realization.payload["blockers"]
      ):
          fail("native realization is not ready for execution")
    '';
  };
  checkedRuntimeData = pkgs.runCommand "${namePrefix}-${id}-runtime-data-v1" {
    nativeBuildInputs = [ pkgs.coreutils pkgs.findutils ];
    __contentAddressed = true;
  } ''
    set -euo pipefail
    mkdir -p "$out"
    ${lib.optionalString (runtimeData != null) ''
      cp -a ${runtimeData}/. "$out/"
    ''}
    while IFS= read -r -d $'\0' path; do
      magic="$(head -c 2 "$path" | od -An -tx1 | tr -d ' \n')"
      if [ "$magic" = 4d5a ]; then
        echo "candidate runtime data contains a forbidden PE binary: $path" >&2
        exit 1
      fi
    done < <(find "$out" -type f -print0)
  '';
  runner = pkgs.writeShellApplication {
    name = "spaghetti-extractor-headless-wine-candidate";
    runtimeInputs = [ wine headlessWayland pkgs.coreutils pkgs.bash ];
    text = ''
      set -euo pipefail
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      work="$TMPDIR/candidate-work"
      mkdir -p "$HOME" "$work"
      cp -a ${checkedRuntimeData}/. "$work/"
      chmod -R u+w "$work"
      cd "$work"
      # shellcheck disable=SC2016
      exec spaghetti-headless-wayland ${pkgs.bash}/bin/bash -eu -c '
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
  suiteResult = import ./candidate-test-aggregate.nix {
    inherit pkgs pythonEnv pythonSource suite caseIds timeoutSeconds
      stripStderrLineRegexes;
    namePrefix = "${namePrefix}-${id}";
    inherit candidateBinary nativeRealization;
    candidateCommand = [
      "${runner}/bin/spaghetti-extractor-headless-wine-candidate"
    ];
  };
  aggregate = pkgs.runCommand "${namePrefix}-${id}-candidate-test-receipt-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    execution_gate=${executionGate.receipt}
    test -f ${suiteResult.aggregate}/candidate-test-report.json
    test -s ${candidateBinary}
    mkdir -p "$out"
    ln -s ${suiteResult.aggregate} "$out/test-results"
    candidate_sha256="$(sha256sum ${candidateBinary} | cut -d ' ' -f 1)"
    expected_candidate_sha256="$(jq -r '.candidate.sha256' "$execution_gate")"
    test "$candidate_sha256" = "$expected_candidate_sha256"
    native_realization_sha256="$(sha256sum "$execution_gate" | cut -d ' ' -f 1)"
    report_sha256="$(sha256sum ${suiteResult.aggregate}/candidate-test-report.json | cut -d ' ' -f 1)"
    suite_sha256="$(sha256sum ${suite} | cut -d ' ' -f 1)"
    jq -n \
      --arg format spaghetti-extractor-candidate-test-receipt-v1 \
      --arg id ${lib.escapeShellArg id} \
      --arg configuration_id ${lib.escapeShellArg configurationId} \
      --arg suite_id ${lib.escapeShellArg suiteId} \
      --arg candidate_sha256 "$candidate_sha256" \
      --arg native_realization_sha256 "$native_realization_sha256" \
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
          native_realization_sha256: $native_realization_sha256,
          suite_sha256: $suite_sha256,
          candidate_test_report_sha256: $report_sha256
        },
        policy: {
          candidate_only: true,
          original_binary_executed: false,
          native_realization_required_before_execution: true,
          headless_wine_required: true,
          divergence_class: "spaghetti-extractor-or-candidate-toolchain-red-flag"
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
assert lib.assertMsg
  (suitePayload.format or null == "spaghetti-extractor-candidate-test-suite-v1")
  "candidate test suite format is unsupported";
{
  _type = "spaghetti-extractor-candidate-test-suite-v1";
  inherit id suiteId configurationId caseIds aggregate runner suite checkedRuntimeData;
  cases = suiteResult.byName;
  functionalAggregate = suiteResult.aggregate;
}
