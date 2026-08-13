{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource ? null,
  spaghettiExtractor ? null,
  isaKernelCache ? null,
  isaSemanticKernel ? null,
  bochsRunner ? null,
  componentProposals ? null,
}:

let
  target = builtins.fromJSON (builtins.readFile ./target.json);
  mingw = pkgs.pkgsCross.mingw32;
  oniguruma = mingw.oniguruma.overrideAttrs (old: {
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  commonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
  originalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${commonCflags}";
  unverifiedOriginal = (mingw.jq.override { inherit oniguruma; }).overrideAttrs (old: {
    pname = "stage-a-jq-original";
    doCheck = false;
    doInstallCheck = false;
    dontStrip = true;
    outputs = [ "out" ];
    buildInputs = (old.buildInputs or [ ]) ++ [ mingw.windows.pthreads ];
    configureFlags = [
      "--prefix=${builtins.placeholder "out"}"
      "--bindir=${builtins.placeholder "out"}/bin"
      "--sbindir=${builtins.placeholder "out"}/bin"
      "--datadir=${builtins.placeholder "out"}/share"
      "--mandir=${builtins.placeholder "out"}/share/man"
    ];
    CFLAGS = originalCflags;
    LDFLAGS = "-Wl,-Map,jq-original.map";
    postFixup = "";
    postInstall = (old.postInstall or "") + ''
      map_path="$(find . -name 'jq-original.map' -print -quit)"
      if [ -z "$map_path" ]; then
        echo "missing jq-original.map" >&2
        exit 1
      fi
      mkdir -p "$out/share/spaghetti-extractor/stage-a-jq-fixtures/original"
      cp "$map_path" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.map"
      cp "$out/bin/jq.exe" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.exe"
    '';
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  original = pkgs.runCommand "spaghetti-extractor-jq-original" {
    __contentAddressed = true;
  } ''
    mkdir -p "$out/bin"
    cp ${unverifiedOriginal}/bin/jq.exe "$out/bin/jq.exe"
    test "$(sha256sum "$out/bin/jq.exe" | cut -d ' ' -f 1)" = \
      ${target.input.expected_sha256}
  '';
  originalPe = "${original}/bin/jq.exe";
  profileSource = pkgs.lib.fileset.toSource {
    root = ../../profiles;
    fileset = ../../profiles;
  };
  analysis = import ../../nix/stage-b-component-analysis.nix {
    inherit pkgs pythonEnv pythonSource;
    original = originalPe;
    externalProfile =
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json";
    namePrefix = "spaghetti-extractor-jq-1.8.1";
  };
  analysisV3 = import ../../nix/analysis-v3-authority.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      isaPythonSource
      spaghettiExtractor
      isaKernelCache
      isaSemanticKernel
      bochsRunner
      ;
    name = "spaghetti-extractor-jq-1.8.1-authority-v3";
    machineIr = "${analysis.machineIr}/machine-ir.jsonl";
    binary = originalPe;
    binaryIdentity = "jq.exe";
    machineImportProfiles = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
    ];
    launchProfileTemplate =
      "${profileSource}/pe32-win32-gui-launch-assumptions-v1.json";
  };
in
{
  inherit original analysis analysisV3;

  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource componentProposals;
    target = ./.;
  };
}
