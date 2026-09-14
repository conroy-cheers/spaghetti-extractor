# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  suite,
  caseIds,
  candidateBinary,
  candidateCommand,
  timeoutSeconds ? 30,
  stripStderrLineRegexes ? [ ],
  nativeBuildInputs ? [ ],
  nativeRealization,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.candidate.functional"
      "spaghetti_extractor.native_realization.receipt_v2"
    ];
    name = "${namePrefix}-functional-python-closure";
  };
  cases = map (id: { inherit id; }) caseIds;
  commandSpec = pkgs.writeText
    "${namePrefix}-candidate-command.json"
    (builtins.toJSON candidateCommand);
  stripSpec = pkgs.writeText
    "${namePrefix}-strip-stderr.json"
    (builtins.toJSON stripStderrLineRegexes);
  commonAttrs = {
    nativeBuildInputs = [ pythonEnv pkgs.coreutils ] ++ nativeBuildInputs;
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };
  mkCase = case:
    pkgs.runCommand
      "${namePrefix}-${lib.strings.sanitizeDerivationName case.id}"
      commonAttrs
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export LC_ALL=C.UTF-8
        export SOURCE_DATE_EPOCH=1
        export PYTHONPATH=${phasePythonSource.pythonPath}
        ${pythonEnv}/bin/python3 - \
          ${nativeRealization}/native-realization.json <<'PY'
        import pathlib
        import sys

        from spaghetti_extractor.native_realization.receipt_v2 import (
            NativeRealizationV2,
        )

        realization = NativeRealizationV2.load(pathlib.Path(sys.argv[1]))
        if (
            realization.payload["status"] != "complete"
            or realization.payload["ready_for_observation"] is not True
            or realization.payload["blockers"]
        ):
            raise SystemExit("native realization is not ready for execution")
        PY
        expected_candidate_sha256="$(${pkgs.jq}/bin/jq -r \
          '.candidate.sha256' ${nativeRealization}/native-realization.json)"
        actual_candidate_sha256="$(${pkgs.coreutils}/bin/sha256sum \
          ${candidateBinary} | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)"
        test "$expected_candidate_sha256" = "$actual_candidate_sha256"
        mkdir -p "$out"
        ${pythonEnv}/bin/python3 - \
          ${suite} \
          ${lib.escapeShellArg case.id} \
          ${candidateBinary} \
          ${commandSpec} \
          ${stripSpec} \
          "$out" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.candidate.functional import (
            run_candidate_test_case,
        )

        run_candidate_test_case(
            suite=pathlib.Path(sys.argv[1]),
            case_id=sys.argv[2],
            candidate_binary=pathlib.Path(sys.argv[3]),
            candidate_command=tuple(json.loads(pathlib.Path(sys.argv[4]).read_text())),
            strip_stderr_line_regexes=tuple(
                json.loads(pathlib.Path(sys.argv[5]).read_text())
            ),
            timeout_seconds=${toString timeoutSeconds},
            out=pathlib.Path(sys.argv[6]),
        )
        PY
        if ! ${pkgs.jq}/bin/jq -e '.status == "pass"' \
          "$out/candidate-test-case-report.json" >/dev/null; then
          ${pkgs.jq}/bin/jq . "$out/candidate-test-case-report.json" >&2
          ${pkgs.coreutils}/bin/cat "$out/artifacts/${case.id}/candidate.stdout" >&2
          ${pkgs.coreutils}/bin/cat "$out/artifacts/${case.id}/candidate.stderr" >&2
          exit 1
        fi
      '';
  caseDerivations = map mkCase cases;
  caseArgs = lib.concatMapStringsSep " "
    (case: lib.escapeShellArg (toString case))
    caseDerivations;
  aggregate = pkgs.runCommand "${namePrefix}-aggregate"
    (commonAttrs // { nativeBuildInputs = commonAttrs.nativeBuildInputs ++ [ pkgs.jq ]; })
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${phasePythonSource.pythonPath}
      ${pythonEnv}/bin/python3 - ${suite} "$out" ${caseArgs} <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.candidate.functional import (
          aggregate_candidate_test_cases,
      )

      aggregate_candidate_test_cases(
          suite=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
          case_reports=[pathlib.Path(value) for value in sys.argv[3:]],
      )
      PY
      ${pkgs.jq}/bin/jq -e \
        --argjson expected ${toString (builtins.length cases)} '
        .format == "spaghetti-extractor-candidate-test-report-v1" and
        .status == "pass" and
        (.oracle.original_runtime_observations | not) and
        .counts.cases == $expected and .counts.passed == $expected and
        .counts.failed == 0 and (.cases | length) == $expected
      ' "$out/candidate-test-report.json" >/dev/null
    '';
in
assert builtins.isString namePrefix && namePrefix != "";
assert builtins.isList caseIds && builtins.length caseIds > 0;
assert builtins.all (id: builtins.isString id && id != "") caseIds;
assert builtins.isList candidateCommand && builtins.length candidateCommand > 0;
assert lib.isDerivation nativeRealization;
assert builtins.all
  (case: builtins.isAttrs case && case ? id && builtins.isString case.id && case.id != "")
  cases;
assert builtins.length caseIds == builtins.length (lib.unique caseIds);
{
  inherit aggregate;
  cases = caseDerivations;
  byName = builtins.listToAttrs (
    lib.imap0 (index: case: {
      name = case.id;
      value = builtins.elemAt caseDerivations index;
    }) cases
  );
}
