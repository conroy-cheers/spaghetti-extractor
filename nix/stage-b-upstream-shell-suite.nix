{
  pkgs,
  namePrefix,
  targetName,
  suiteId,
  suiteName,
  sourceRevision,
  candidateBinary,
  runner,
  tests,
  environment ? { },
  nativeBuildInputs ? [ ],
}:

let
  lib = pkgs.lib;
  testIds = map (test: test.id) tests;
  validTest =
    test:
    builtins.isAttrs test
    && test ? id
    && builtins.isString test.id
    && test.id != ""
    && test ? script
    && (builtins.isPath test.script || builtins.isString test.script);
  exportsFor =
    values:
    lib.concatMapStringsSep "\n" (
      name: "export ${name}=${lib.escapeShellArg (toString values.${name})}"
    ) (builtins.attrNames values);
  mkCase =
    test:
    let
      expectedExit = test.expectedExit or 0;
      caseEnvironment = environment // (test.environment or { });
    in
    pkgs.runCommand "${namePrefix}-${test.id}"
      {
        nativeBuildInputs = [
          pkgs.bash
          pkgs.coreutils
          pkgs.jq
        ] ++ nativeBuildInputs;
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export HOME="$TMPDIR/home"
        export XDG_CACHE_HOME="$TMPDIR/cache"
        export TMPDIR="$TMPDIR/tmp"
        ${pkgs.coreutils}/bin/mkdir -p \
          "$HOME" "$XDG_CACHE_HOME" "$TMPDIR" "$out" work
        ${exportsFor caseEnvironment}
        ${pkgs.coreutils}/bin/cp \
          ${lib.escapeShellArg (toString test.script)} work/test.sh
        ${pkgs.coreutils}/bin/chmod u+x work/test.sh
        cd work
        set +e
        ${runner} ./test.sh > "$out/runner.stdout" 2> "$out/runner.stderr"
        result=$?
        set -e
        status=fail
        if [ "$result" -eq ${toString expectedExit} ]; then
          status=pass
        fi
        script_sha256="$(${pkgs.coreutils}/bin/sha256sum test.sh | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)"
        candidate_sha256="$(${pkgs.coreutils}/bin/sha256sum ${candidateBinary} | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)"
        ${pkgs.jq}/bin/jq -n \
          --arg format stage-b-upstream-shell-case-report-v1 \
          --arg id ${lib.escapeShellArg test.id} \
          --arg status "$status" \
          --arg target_name ${lib.escapeShellArg targetName} \
          --arg suite_id ${lib.escapeShellArg suiteId} \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg source_script ${lib.escapeShellArg (toString test.script)} \
          --arg script_sha256 "$script_sha256" \
          --arg candidate_sha256 "$candidate_sha256" \
          --arg runner ${lib.escapeShellArg (toString runner)} \
          --arg environment_sha256 ${lib.escapeShellArg (builtins.hashString "sha256" (builtins.toJSON caseEnvironment))} \
          --argjson environment_keys ${lib.escapeShellArg (builtins.toJSON (builtins.attrNames caseEnvironment))} \
          --argjson expected_exit ${toString expectedExit} \
          --argjson actual_exit "$result" \
          '{
            format: $format,
            id: $id,
            status: $status,
            target_name: $target_name,
            suite_id: $suite_id,
            source_revision: $source_revision,
            executes_original_binary: false,
            source_script: $source_script,
            script_sha256: $script_sha256,
            candidate_binary_sha256: $candidate_sha256,
            runner: $runner,
            environment_sha256: $environment_sha256,
            environment_keys: $environment_keys,
            expected_exit: $expected_exit,
            actual_exit: $actual_exit
          }' > "$out/case-report.json"
        if [ "$status" != pass ]; then
          ${pkgs.coreutils}/bin/cat "$out/runner.stdout" >&2
          ${pkgs.coreutils}/bin/cat "$out/runner.stderr" >&2
          echo "upstream case ${test.id} exited $result, expected ${toString expectedExit}" >&2
          exit 1
        fi
      '';
  cases = map mkCase tests;
  caseArgs = lib.concatMapStringsSep " " (
    case: lib.escapeShellArg "${case}/case-report.json"
  ) cases;
  aggregate = pkgs.runCommand "${namePrefix}-aggregate"
    {
      nativeBuildInputs = [ pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      ${pkgs.coreutils}/bin/mkdir -p "$out/cases"
      jq -s \
        --arg target_name ${lib.escapeShellArg targetName} \
        --arg suite_id ${lib.escapeShellArg suiteId} \
        --arg suite_name ${lib.escapeShellArg suiteName} \
        --arg source_revision ${lib.escapeShellArg sourceRevision} '
        {
          format: "stage-b-upstream-shell-suite-report-v1",
          status: (if all(.[]; .status == "pass") then "pass" else "fail" end),
          target_name: $target_name,
          suite_id: $suite_id,
          suite_name: $suite_name,
          suite_scope: "full",
          upstream_suite: true,
          source_revision: $source_revision,
          executes_original_binary: false,
          oracle: {
            kind: "upstream_test_scripts",
            original_runtime_observations: false
          },
          counts: {
            cases: length,
            passed: (map(select(.status == "pass")) | length),
            failed: (map(select(.status != "pass")) | length)
          },
          cases: sort_by(.id)
        }
      ' ${caseArgs} > "$out/upstream-suite-report.json"
      jq -e \
        --argjson expected ${toString (builtins.length tests)} '
        .status == "pass" and .suite_scope == "full" and
        (.executes_original_binary | not) and
        (.oracle.original_runtime_observations | not) and
        .counts.cases == $expected and .counts.passed == $expected and
        .counts.failed == 0 and (.cases | length) == $expected
      ' "$out/upstream-suite-report.json" >/dev/null
      ${lib.concatStringsSep "\n" (lib.imap0 (index: test: ''
        ${pkgs.coreutils}/bin/ln -s ${builtins.elemAt cases index} \
          "$out/cases/${test.id}"
      '') tests)}
    '';
in
assert builtins.isString namePrefix && namePrefix != "";
assert builtins.isString targetName && targetName != "";
assert builtins.isString suiteId && suiteId != "";
assert builtins.isString suiteName && suiteName != "";
assert builtins.isString sourceRevision && sourceRevision != "";
assert builtins.length tests > 0;
assert builtins.all validTest tests;
assert builtins.length testIds == builtins.length (lib.unique testIds);
{
  inherit cases aggregate;
  byName = builtins.listToAttrs (
    lib.imap0 (index: test: {
      name = test.id;
      value = builtins.elemAt cases index;
    }) tests
  );
}
