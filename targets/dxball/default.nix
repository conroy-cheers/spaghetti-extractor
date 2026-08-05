{ pkgs, pythonEnv, pythonSource }:

let
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
    test "$(sha256sum "$out/DXBall.exe" | cut -d ' ' -f 1)" = \
      191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f
  '';
  interfaceProfile = import ../../nix/stage-a-external-interface-profile.nix {
    inherit pkgs pythonEnv pythonSource;
    spec = ../../profiles/pe32-mingw-directx-interface-extraction-v1.json;
  };
  analysis = import ../../nix/stage-b-component-analysis.nix {
    inherit pkgs pythonEnv pythonSource;
    original = "${original}/DXBall.exe";
    externalProfile = "${pythonSource}/profiles/pe32-msvcrt-machine-runtime-v1.json";
    externalInterfaceProfiles = [
      "${interfaceProfile}/interface-profile.json"
    ];
    namePrefix = "spaghetti-extractor-dxball-1.09";
    maxUnits = 512;
    maxCandidatesPerSeed = 12;
  };
  inventory = analysis.originalInventory;
in
{
  inherit archive installer original interfaceProfile inventory analysis;
  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource;
    target = ./.;
  };
}
