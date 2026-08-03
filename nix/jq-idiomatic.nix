{
  pkgs,
  mingw32,
  jqPackage,
  jqSource,
  oniguruma,
  sourceRoot,
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
    #include <process.h>
    #include <stdlib.h>
    #include <wchar.h>

    int wmain(int argc, wchar_t **argv) {
      const wchar_t *home = _wgetenv(L"SPAGHETTI_JQ_TEST_HOME");
      if (argc < 2) {
        return 125;
      }
      if (home != NULL && _wputenv_s(L"HOME", home) != 0) {
        return 126;
      }
      return (int)_wspawnv(_P_WAIT, argv[1], (const wchar_t *const *)(argv + 1));
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
    candidate_path="$(winepath -w ${candidate}/runtime/jq.exe)"
    exec wine ${testLauncher}/launcher.exe "$candidate_path" \
      "''${converted[@]}"
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
          JQ="$1/jq" sh -x "$1/tests/$2"
        ' sh "$source_dir" ${testName} > "$TMPDIR/test.stdout" 2> "$TMPDIR/test.stderr"
        result=$?
        set -e
        cp "$TMPDIR/test.stdout" "$out/stdout"
        cp "$TMPDIR/test.stderr" "$out/stderr"
        if [ "$result" -ne 0 ]; then
          cat "$TMPDIR/test.stdout" >&2
          cat "$TMPDIR/test.stderr" >&2
          exit "$result"
        fi
        printf '%s\n' pass > "$out/status"
      '';
  upstreamTests = builtins.listToAttrs (
    map (testName: {
      name = testName;
      value = mkUpstreamTest testName;
    }) upstreamTestNames
  );
in
{
  inherit candidate smoke upstreamTests;
}
