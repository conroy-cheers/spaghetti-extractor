{
  pkgs,
  sdk,
  mingw32,
  aarch64Stdenv,
  machineIr,
  authorityGate,
  specification,
  runtimeLock,
  sourceRoot,
  linkedIslands ? null,
}:

let
  source = pkgs.lib.fileset.toSource {
    root = sourceRoot;
    fileset = pkgs.lib.fileset.unions [
      (sourceRoot + "/hello.c")
      (sourceRoot + "/hello.h")
    ];
  };
  sourceBinding = sdk.lifting.sourceProject {
    inherit machineIr specification linkedIslands;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    sourceRoot = source;
  };
  portableBuild = sdk.lifting.portableCProject {
    inherit mingw32 specification runtimeLock source sourceBinding;
    namePrefix = "spaghetti-extractor-gnu-hello-idiomatic";
    version = "2.12.3";
    sourceFiles = [ "hello.c" "hello.h" ];
    compileSources = [ "hello.c" ];
    executableName = "hello.exe";
    portableStdenv = aarch64Stdenv;
  };
  candidate = portableBuild.pe32;
  nativeCandidate = portableBuild.native;
  wineFontsConf = pkgs.writeText "spaghetti-extractor-gnu-hello-wine-fonts.conf" ''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
    <fontconfig>
      <dir>${pkgs.dejavu_fonts}/share/fonts</dir>
      <cachedir prefix="xdg">fontconfig</cachedir>
      <config><rescan><int>0</int></rescan></config>
    </fontconfig>
  '';
  runner = pkgs.writeShellApplication {
    name = "hello";
    runtimeInputs = [
      pkgs.wineWow64Packages.stable
      pkgs.xvfb-run
    ];
    text = ''
      set -euo pipefail
      export WINEPREFIX="''${WINEPREFIX:-$TMPDIR/wine}"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export FONTCONFIG_FILE=${wineFontsConf}
      export XDG_CACHE_HOME="''${XDG_CACHE_HOME:-$TMPDIR/cache}"
      mkdir -p "$WINEPREFIX" "$XDG_CACHE_HOME"
      if [ ! -e "$WINEPREFIX/.spaghetti-extractor-ready" ]; then
        xvfb-run -a wineboot -u >/dev/null 2>&1
        touch "$WINEPREFIX/.spaghetti-extractor-ready"
      fi
      cd ${candidate}/bin
      exec xvfb-run -a wine cmd /d /c hello.exe "$@"
    '';
  };
  functionalSuiteDefinition = import ./tests/functional-suite.nix {
    programName = "hello.exe";
  };
  functionalSuiteSpec = pkgs.writeText
    "gnu-hello-2.12.3-functional-suite.json"
    (builtins.toJSON functionalSuiteDefinition);
  functionalSuiteDag = sdk.lifting.functionalSuite {
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic-functional";
    suite = functionalSuiteSpec;
    caseIds = map (case: case.id) functionalSuiteDefinition.cases;
    candidateBinary = "${candidate}/bin/hello.exe";
    candidateCommand = [ "${runner}/bin/hello" ];
    stripStderrLineRegexes = [
      "^wine: created the configuration directory "
      "^wine: configuration in .* has been updated\\.$"
      "^Fontconfig warning:"
      "^WARNING: radv is not a conformant Vulkan implementation, testing use only\\.$"
      "^X connection to .* broken \\(explicit kill or server shutdown\\)\\.$"
      "^XIO:  fatal IO error [0-9]+ .* on X server "
      "^\\s+after [0-9]+ requests \\([0-9]+ known processed\\) with [0-9]+ events remaining\\.$"
    ];
    inherit authorityGate;
  };
  functionalSuite = functionalSuiteDag.aggregate;
  nativeFunctionalSuiteDefinition = import ./tests/functional-suite.nix {
    programName = "hello";
    eol = "\n";
  };
  nativeFunctionalSuiteSpec = pkgs.writeText
    "gnu-hello-2.12.3-native-functional-suite.json"
    (builtins.toJSON nativeFunctionalSuiteDefinition);
  nativeFunctionalSuiteDag = sdk.lifting.functionalSuite {
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic-native-functional";
    suite = nativeFunctionalSuiteSpec;
    caseIds = map (case: case.id) nativeFunctionalSuiteDefinition.cases;
    candidateBinary = "${nativeCandidate}/bin/hello.exe";
    candidateCommand = [ "${nativeCandidate}/bin/hello.exe" ];
    inherit authorityGate;
  };
  nativeFunctionalSuite = nativeFunctionalSuiteDag.aggregate;
in
{
  inherit
    source
    sourceBinding
    portableBuild
    candidate
    nativeCandidate
    runner
    functionalSuiteDefinition
    functionalSuiteSpec
    functionalSuiteDag
    functionalSuite
    nativeFunctionalSuiteDefinition
    nativeFunctionalSuiteSpec
    nativeFunctionalSuiteDag
    nativeFunctionalSuite
    ;
}
