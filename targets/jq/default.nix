{ pkgs, sdk }:

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
    pname = "spaghetti-extractor-jq-original";
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
      mkdir -p "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original"
      cp "$map_path" "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original/jq.map"
      cp "$out/bin/jq.exe" "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original/jq.exe"
    '';
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  original = unverifiedOriginal;
  originalPe = "${original}/bin/jq.exe";
  profileSource = sdk.profiles;
  workflow = sdk.workflow.pe32 {
    original = originalPe;
    binaryIdentity = "jq.exe";
    externalProfile =
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json";
    machineImportProfiles = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
    ];
    launchProfileTemplate =
      "${profileSource}/pe32-win32-console-launch-assumptions-v1.json";
    componentIntent = ./intent/components.json;
    componentReviewRoot = ./intent/reviews;
    namePrefix = "spaghetti-extractor-jq-1.8.1";
  };
  components = workflow.components;
  candidateTests = {
    "jq-1.8.1-idiomatic-candidate-functional" = workflow.candidateTestFor {
      id = "jq-1.8.1-idiomatic-candidate-functional";
      configurationId = target.workflow.default_configuration;
      suite = ./tests/candidate-suite.json;
      timeoutSeconds = 90;
    };
  };
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow candidateTests;
  inputs.original = original;
  checks = {
    component-contract = components.contracts.operator-whole;
  };
}
