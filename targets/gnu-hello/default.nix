{ pkgs, pythonEnv, pythonSource }:

let
  mingw = pkgs.pkgsCross.mingw32;
  target = builtins.fromJSON (builtins.readFile ./target.json);
  commonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
  originalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${commonCflags}";
  layoutLdflags = pkgs.lib.concatStringsSep " " [
    "-Wl,--section-start=.data=0x420000"
    "-Wl,--section-start=.rdata=0x421000"
    "-Wl,--section-start=.bss=0x430000"
    "-Wl,--section-start=.edata=0x431000"
    "-Wl,--section-start=.idata=0x432000"
    "-Wl,--section-start=.tls=0x433000"
    "-Wl,--section-start=.reloc=0x434000"
  ];
  original = mingw.hello.overrideAttrs (old: {
    pname = "spaghetti-extractor-gnu-hello-original";
    doCheck = false;
    doInstallCheck = false;
    dontStrip = true;
    outputs = [ "out" ];
    env = (old.env or { }) // {
      CFLAGS = originalCflags;
      LDFLAGS = "${layoutLdflags} -Wl,-Map,hello-original.map";
    };
    postFixup = "";
    postInstall = (old.postInstall or "") + ''
      test "$(sha256sum "$out/bin/hello.exe" | cut -d ' ' -f 1)" = \
        ${target.input.expected_sha256}
    '';
    __contentAddressed = true;
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  originalPe = "${original}/bin/hello.exe";
  profileSource = pkgs.lib.fileset.toSource {
    root = ../../profiles;
    fileset = ../../profiles;
  };
  analysis = import ../../nix/stage-b-component-analysis.nix {
    inherit pkgs pythonEnv pythonSource;
    original = originalPe;
    externalProfile =
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json";
    namePrefix = "spaghetti-extractor-gnu-hello-2.12.3";
  };
  analysisV3 = import ../../nix/analysis-v3-authority.nix {
    inherit pkgs pythonEnv pythonSource;
    name = "spaghetti-extractor-gnu-hello-2.12.3-authority-v3";
    machineIr = "${analysis.machineIr}/machine-ir.jsonl";
    binary = originalPe;
    binaryIdentity = "hello.exe";
    machineImportProfiles = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
    ];
    launchProfileTemplate =
      "${profileSource}/pe32-win32-gui-launch-assumptions-v1.json";
  };
  source = pkgs.lib.fileset.toSource {
    root = ./source/idiomatic;
    fileset = ./source/idiomatic;
  };
in
{
  inherit original analysis analysisV3;

  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource;
    target = ./.;
  };

  idiomaticCandidate = mingw.stdenv.mkDerivation {
    pname = "spaghetti-extractor-gnu-hello-idiomatic";
    version = "2.12.3";
    src = source;
    dontConfigure = true;
    strictDeps = true;
    __contentAddressed = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra hello.c -o hello.exe
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin" "$out/share/spaghetti-extractor/gnu-hello"
      cp hello.exe "$out/bin/hello.exe"
      cp hello.c hello.h "$out/share/spaghetti-extractor/gnu-hello/"
    '';
  };
}
