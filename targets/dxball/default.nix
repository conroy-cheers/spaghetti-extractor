{ pkgs, sdk }:

let
  target = builtins.fromJSON (builtins.readFile ./target.json);
  archive = pkgs.fetchurl {
    name = "dxball-1.09-distributable.zip";
    url = "https://archive.org/download/dxball-19/DXBall19.zip";
    hash = "sha256-ARvV4Ge3rNrGxdbEeqIAmpcb07FSayOGbUsz/ZfdUQ0=";
  };
  wine = pkgs.wineWow64Packages.stableFull;
  installer = pkgs.runCommand "dxball-1.09-installer" {
    nativeBuildInputs = [ pkgs.unzip ];
    __contentAddressed = true;
  } ''
    mkdir -p "$out"
    unzip -j ${archive} DXBall19.EXE -d "$out"
    test "$(sha256sum "$out/DXBall19.EXE" | cut -d ' ' -f 1)" = \
      2472a555ba5cbda459f6c7b9df9e2aebc37eaca2c730e86d31b46a088d81ae77
  '';
  original = pkgs.runCommand "dxball-1.09-original" {
    nativeBuildInputs = [ wine pkgs.xvfb-run ];
    __contentAddressed = true;
  } ''
    export HOME="$TMPDIR/home"
    export WINEPREFIX="$TMPDIR/wine"
    export WINEDEBUG=-all
    export WINEDLLOVERRIDES="mscoree,mshtml="
    mkdir -p "$HOME"
    xvfb-run -a -s '-screen 0 640x480x24' sh -eu -c '
      wineboot -u >/dev/null 2>&1
      wine ${installer}/DXBall19.EXE /s >/dev/null 2>&1
      wineserver -w
    '
    installed="$WINEPREFIX/drive_c/Program Files (x86)/DX-Ball"
    mkdir -p "$out/runtime"
    cp "$installed/DXBall.exe" "$out/DXBall.exe"
    cp -a "$installed/." "$out/runtime/"
    # The installer log contains its wall-clock start time and is not consumed
    # by the game.  Exclude it from this content-addressed runtime fixture.
    rm -f "$out/runtime/INSTALL.LOG"
  '';
  interfaceProfile = sdk.analysis.externalInterfaceProfile {
    spec = "${sdk.profiles}/pe32-mingw-directx-interface-extraction-v1.json";
  };
  runtimeMachineImportProfiles = [
    "${sdk.profiles}/pe32-msvcrt-machine-runtime-v1.json"
    "${sdk.profiles}/pe32-kernel32-runtime-v1.json"
    "${sdk.profiles}/pe32-native-callthrough-runtime-v1.json"
    "${sdk.profiles}/pe32-win32-windowing-runtime-v1.json"
    "${sdk.profiles}/pe32-winmm-runtime-v1.json"
  ];
  workflow = sdk.workflow.pe32 {
    targetId = target.id;
    original = "${original}/DXBall.exe";
    binaryIdentity = "DXBall.exe";
    externalProfile = builtins.head runtimeMachineImportProfiles;
    machineImportProfiles = runtimeMachineImportProfiles;
    externalInterfaceProfiles = [
      "${interfaceProfile}/interface-profile.json"
    ];
    candidateMachineImportProfiles = [
      "${interfaceProfile}/interface-profile.json"
    ];
    libraryAdoptionIntentRoot = ./intent/libraries;
    launchProfileTemplate =
      "${sdk.profiles}/pe32-win32-gui-launch-assumptions-v1.json";
    componentIntent = ./intent/components.json;
    componentReviewRoot = ./intent/reviews;
    componentSourceRoot = ./source;
    namePrefix = "spaghetti-extractor-dxball-1.09";
    maxUnits = 512;
    maxCandidatesPerSeed = 12;
  };
  components = workflow.components;
  boundaries = sdk.lifting.boundarySchema {
    name = "spaghetti-extractor-dxball-1.09";
    spec = ./intent/boundaries.json;
    sources = [ ./source/window-class-boundary.c ];
  };
  runtimeData = pkgs.runCommand "dxball-1.09-candidate-runtime-data" {
    __contentAddressed = true;
  } ''
    mkdir -p "$out"
    cp -a ${original}/runtime/. "$out/"
    rm -f "$out/DXBall.exe"
  '';
  candidateTests = {
    "dxball-default-candidate" = workflow.candidateTestFor {
      id = "dxball-default-candidate";
      configurationId = target.workflow.default_configuration;
      suite = ./tests/candidate-suite.json;
      inherit runtimeData;
      timeoutSeconds = 20;
    };
  };
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow candidateTests;
  inputs = {
    inherit archive installer original;
  };
  profiles.interface = interfaceProfile;
  targetAssets.documentation = [ "intent/libraries/README.md" ];
  targetAssets.boundary_schema = [ "intent/boundaries.json" ];
  targetAssets.boundary_source = [ "source/window-class-boundary.c" ];
  extraArtifacts.boundaries = boundaries;
  checks = {
    component-contract = components.contracts.startup-extended;
    canonical-boundaries = boundaries;
  };
}
