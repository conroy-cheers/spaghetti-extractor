{
  pkgs,
  mingw32,
  jqPackage,
  jqSource,
  oniguruma,
  sourceRoot,
  pythonEnv,
  functionalPythonSource,
}:

let
  source = pkgs.lib.fileset.toSource {
    root = sourceRoot;
    fileset = pkgs.lib.fileset.unions [
      (sourceRoot + "/jq_cli.c")
    ];
  };
  candidate = mingw32.stdenv.mkDerivation {
    pname = "stage-b-jq-idiomatic-candidate";
    version = "1.8.1";
    src = source;
    dontConfigure = true;
    dontFixup = true;
    strictDeps = true;
    __contentAddressed = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -municode \
        -I${jqPackage}/include \
        jq_cli.c \
        -L${jqPackage}/lib -ljq \
        -L${oniguruma.lib}/lib -lonig \
        -o jq.exe
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/runtime"
      cp jq.exe "$out/candidate.exe"
      cp ${jqPackage}/bin/*.dll "$out/runtime/"
      cp "$out/candidate.exe" "$out/runtime/jq.exe"
      sha256sum "$out/candidate.exe" | cut -d ' ' -f 1 > "$out/candidate.sha256"
      runHook postInstall
    '';
  };
  testLauncherSource = pkgs.writeText "stage-b-jq-test-launcher.c" ''
    #include <stdlib.h>
    #include <wchar.h>
    #include <windows.h>

    static int append_char(wchar_t *command, size_t capacity, size_t *length,
                           wchar_t value) {
      if (*length + 1 >= capacity) {
        return 0;
      }
      command[(*length)++] = value;
      command[*length] = L'\0';
      return 1;
    }

    static int append_repeated(wchar_t *command, size_t capacity,
                               size_t *length, wchar_t value, size_t count) {
      while (count-- > 0) {
        if (!append_char(command, capacity, length, value)) {
          return 0;
        }
      }
      return 1;
    }

    static int append_argument(wchar_t *command, size_t capacity,
                               size_t *length, const wchar_t *argument) {
      int quoted = argument[0] == L'\0' || wcspbrk(argument, L" \t\n\v\"") != NULL;
      size_t backslashes = 0;

      if (quoted && !append_char(command, capacity, length, L'\"')) {
        return 0;
      }
      for (const wchar_t *cursor = argument; *cursor != L'\0'; ++cursor) {
        if (*cursor == L'\\') {
          ++backslashes;
        } else if (*cursor == L'\"') {
          if (!append_repeated(command, capacity, length, L'\\',
                               backslashes * 2 + 1) ||
              !append_char(command, capacity, length, L'\"')) {
            return 0;
          }
          backslashes = 0;
        } else {
          if (!append_repeated(command, capacity, length, L'\\', backslashes) ||
              !append_char(command, capacity, length, *cursor)) {
            return 0;
          }
          backslashes = 0;
        }
      }
      if (!append_repeated(command, capacity, length, L'\\',
                           quoted ? backslashes * 2 : backslashes)) {
        return 0;
      }
      return !quoted || append_char(command, capacity, length, L'\"');
    }

    int wmain(int argc, wchar_t **argv) {
      const wchar_t *home = _wgetenv(L"SPAGHETTI_JQ_TEST_HOME");
      const wchar_t *userprofile =
          _wgetenv(L"SPAGHETTI_JQ_TEST_USERPROFILE");
      PROCESS_INFORMATION process = {0};
      STARTUPINFOW startup = {.cb = sizeof(startup)};
      wchar_t *command;
      size_t capacity = 1;
      size_t length = 0;
      DWORD exit_code;

      if (argc < 2) {
        return 125;
      }
      if (home != NULL && _wputenv_s(L"HOME", home) != 0) {
        return 126;
      }
      if (userprofile != NULL &&
          _wputenv_s(L"USERPROFILE", userprofile) != 0) {
        return 126;
      }
      for (int index = 1; index < argc; ++index) {
        capacity += 2 * wcslen(argv[index]) + 3;
      }
      command = calloc(capacity, sizeof(*command));
      if (command == NULL) {
        return 127;
      }
      for (int index = 1; index < argc; ++index) {
        if ((index > 1 && !append_char(command, capacity, &length, L' ')) ||
            !append_argument(command, capacity, &length, argv[index])) {
          free(command);
          return 127;
        }
      }
      if (!CreateProcessW(argv[1], command, NULL, NULL, TRUE, 0, NULL, NULL,
                          &startup, &process)) {
        free(command);
        return 128;
      }
      free(command);
      WaitForSingleObject(process.hProcess, INFINITE);
      if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
        exit_code = 129;
      }
      CloseHandle(process.hThread);
      CloseHandle(process.hProcess);
      return (int)exit_code;
    }
  '';
  testLauncher = mingw32.stdenv.mkDerivation {
    pname = "stage-b-jq-test-launcher";
    version = "1";
    dontUnpack = true;
    dontConfigure = true;
    dontFixup = true;
    strictDeps = true;
    __contentAddressed = true;
    buildPhase = ''
      $CC -std=c11 -O2 -Wall -Wextra -municode \
        ${testLauncherSource} -o launcher.exe
    '';
    installPhase = ''
      mkdir -p "$out"
      cp launcher.exe "$out/launcher.exe"
    '';
  };
  smoke = pkgs.runCommand "stage-b-jq-idiomatic-smoke-v1"
    {
      nativeBuildInputs = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.wineWow64Packages.stable
        pkgs.xvfb-run
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export XDG_CACHE_HOME="$TMPDIR/cache"
      mkdir -p "$HOME" "$XDG_CACHE_HOME" "$out"
      cp -R ${candidate}/runtime "$TMPDIR/runtime"
      chmod -R u+w "$TMPDIR/runtime"
      cd "$TMPDIR/runtime"

      xvfb-run -a wineboot -u >/dev/null 2>&1
      printf '{"answer":42}\n' | \
        xvfb-run -a wine ./jq.exe -c '.answer' > actual.json 2> actual.err
      if [ -s actual.err ]; then
        cat actual.err >&2
      fi
      printf '42\r\n' > expected.json
      diff -u expected.json actual.json
      test ! -s actual.err

      xvfb-run -a wine ./jq.exe --version > version.actual 2> version.err
      printf 'jq-1.8.1\r\n' > version.expected
      diff -u version.expected version.actual
      test ! -s version.err

      xvfb-run -a wine ./jq.exe -n -c --arg name spaghetti \
        '{name:$name}' > arg.actual 2> arg.err
      printf '{"name":"spaghetti"}\r\n' > arg.expected
      diff -u arg.expected arg.actual
      test ! -s arg.err

      printf '%s\n' pass > "$out/status"
    '';
  candidateRunner = pkgs.writeShellScript "stage-b-jq-idiomatic-runner" ''
    set -euo pipefail
    converted=()
    for argument in "$@"; do
      if [ "''${argument#/}" != "$argument" ] && [ -e "$argument" ]; then
        converted+=("$(winepath -w "$argument")")
      else
        converted+=("$argument")
      fi
    done
    if [ -n "''${HOME:-}" ] && [ "''${HOME#/}" != "$HOME" ]; then
      export SPAGHETTI_JQ_TEST_HOME="$(winepath -w "$HOME")"
    fi
    if [ -n "''${USERPROFILE:-}" ] &&
       [ "''${USERPROFILE#/}" != "$USERPROFILE" ]; then
      export SPAGHETTI_JQ_TEST_USERPROFILE="$(winepath -w "$USERPROFILE")"
    fi
    candidate_path="$(winepath -w ${candidate}/runtime/jq.exe)"
    exec wine ${testLauncher}/launcher.exe "$candidate_path" \
      "''${converted[@]}"
  '';
  functionalRunner = pkgs.writeShellApplication {
    name = "jq";
    runtimeInputs = [
      pkgs.wineWow64Packages.stable
      pkgs.xvfb-run
    ];
    text = ''
      set -euo pipefail
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export XDG_CACHE_HOME="$TMPDIR/cache"
      mkdir -p "$HOME" "$XDG_CACHE_HOME"
      if [ ! -e "$WINEPREFIX/.spaghetti-extractor-ready" ]; then
        xvfb-run -a wineboot -u >/dev/null 2>&1
        touch "$WINEPREFIX/.spaghetti-extractor-ready"
      fi
      set +e
      xvfb-run -a ${candidateRunner} "$@"
      result=$?
      set -e
      wineserver -k
      wineserver -w
      exit "$result"
    '';
  };
  functionalSuiteDag = import ./stage-b-functional-suite.nix {
    inherit pkgs pythonEnv;
    pythonSource = functionalPythonSource;
    namePrefix = "stage-b-jq-idiomatic-functional-v1";
    suite = sourceRoot + "/functional-suite.json";
    caseIds = [
      "identity"
      "field-projection"
      "null-input"
      "string-argument"
      "json-argument"
      "raw-slurp"
      "raw-output"
      "ascii-output"
      "streaming-parser"
      "string-positionals"
      "json-positionals"
      "exit-status-false"
      "exit-status-empty"
      "raw-output-zero"
      "json-sequence"
    ];
    candidateBinary = "${candidate}/candidate.exe";
    candidateCommand = [ "${functionalRunner}/bin/jq" ];
    stripStderrLineRegexes = [
      "^X connection to .* broken \\(explicit kill or server shutdown\\)\\.$"
      "^XIO:  fatal IO error [0-9]+ .* on X server "
      "^\\s+after [0-9]+ requests \\([0-9]+ known processed\\) with [0-9]+ events remaining\\.$"
    ];
  };
  functionalSuite = functionalSuiteDag.aggregate;
  targetUname = pkgs.writeShellScriptBin "uname" ''
    if [ "$#" -eq 0 ] || [ "$1" = "-s" ]; then
      printf '%s\n' MINGW32_NT
    else
      exec ${pkgs.coreutils}/bin/uname "$@"
    fi
  '';
  upstreamTestNames = [
    "mantest"
    "jqtest"
    "shtest"
    "utf8test"
    "base64test"
    "uritest"
    "onigtest"
    "manonigtest"
  ];
  mkUpstreamTest = testName:
    pkgs.runCommand "stage-b-jq-idiomatic-upstream-${testName}-v1"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.gnutar
          pkgs.wineWow64Packages.stable
          pkgs.xvfb-run
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export HOME="$TMPDIR/home"
        export WINEPREFIX="$TMPDIR/wine"
        export WINEDEBUG=-all
        export WINEDLLOVERRIDES="mscoree,mshtml="
        export XDG_CACHE_HOME="$TMPDIR/cache"
        export TRACE_TESTS=
        mkdir -p "$HOME" "$XDG_CACHE_HOME" "$out"
        tar -xf ${jqSource} -C "$TMPDIR"
        source_dir="$(find "$TMPDIR" -maxdepth 1 -type d -name 'jq-*' -print -quit)"
        test -n "$source_dir"
        ln -s ${candidateRunner} "$source_dir/jq"
        cd "$source_dir"
        set +e
        xvfb-run -a sh -c '
          wineboot -u >/dev/null 2>&1
          export PATH="$3/bin:$PATH"
          jq_extra_args=
          if [ "$2" = utf8test ]; then
            jq_extra_args=-b
          fi
          JQ="$1/jq $jq_extra_args" sh -x "$1/tests/$2"
        ' sh "$source_dir" ${testName} ${targetUname} \
          > "$TMPDIR/test.stdout" 2> "$TMPDIR/test.stderr"
        result=$?
        set -e
        cp "$TMPDIR/test.stdout" "$out/stdout"
        cp "$TMPDIR/test.stderr" "$out/stderr"
        if [ "$result" -ne 0 ]; then
          cat "$TMPDIR/test.stdout" >&2
          cat "$TMPDIR/test.stderr" >&2
          exit "$result"
        fi
        candidate_sha256="$(sha256sum ${candidate}/candidate.exe | cut -d ' ' -f 1)"
        script_sha256="$(sha256sum "$source_dir/tests/${testName}" | cut -d ' ' -f 1)"
        jq -n \
          --arg format stage-b-upstream-shell-case-report-v1 \
          --arg id ${testName} \
          --arg status pass \
          --arg target_name jq \
          --arg suite_id jq-1.8.1-upstream-tests \
          --arg source_revision jq-1.8.1 \
          --arg source_script "tests/${testName}" \
          --arg script_sha256 "$script_sha256" \
          --arg candidate_sha256 "$candidate_sha256" \
          --arg runner ${candidateRunner} '
          {
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
            expected_exit: 0,
            actual_exit: 0
          }
        ' > "$out/case-report.json"
        printf '%s\n' pass > "$out/status"
      '';
  upstreamTests = builtins.listToAttrs (
    map (testName: {
      name = testName;
      value = mkUpstreamTest testName;
    }) upstreamTestNames
  );
  upstreamCaseArgs = pkgs.lib.concatMapStringsSep " "
    (testName: "${upstreamTests.${testName}}/case-report.json")
    upstreamTestNames;
  upstreamSuite = pkgs.runCommand
    "stage-b-jq-idiomatic-upstream-suite-v1"
    {
      nativeBuildInputs = [ pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      mkdir -p "$out/cases"
      jq -s '
        {
          format: "stage-b-upstream-shell-suite-report-v1",
          status: (if all(.[]; .status == "pass") then "pass" else "fail" end),
          target_name: "jq",
          suite_id: "jq-1.8.1-upstream-tests",
          suite_name: "jq 1.8.1 complete upstream test families",
          suite_scope: "full",
          upstream_suite: true,
          source_revision: "jq-1.8.1",
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
      ' ${upstreamCaseArgs} > "$out/upstream-suite-report.json"
      jq -e '
        .status == "pass" and .suite_scope == "full" and
        (.executes_original_binary | not) and
        (.oracle.original_runtime_observations | not) and
        .counts.cases == 8 and .counts.passed == 8 and .counts.failed == 0 and
        (.cases | length) == 8
      ' "$out/upstream-suite-report.json" >/dev/null
      ${pkgs.lib.concatMapStringsSep "\n" (testName: ''
        ln -s ${upstreamTests.${testName}} "$out/cases/${testName}"
      '') upstreamTestNames}
    '';
in
{
  inherit candidate smoke functionalSuite functionalSuiteDag upstreamTests upstreamSuite;
}
