{ pkgs, sdk }:

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
  runtimeProfile = "${sdk.profiles}/pe32-msvcrt-machine-runtime-v1.json";
  workflow = sdk.workflow.pe32 {
    original = originalPe;
    binaryIdentity = "hello.exe";
    externalProfile = runtimeProfile;
    machineImportProfiles = [ runtimeProfile ];
    launchProfileTemplate =
      "${sdk.profiles}/pe32-win32-console-launch-assumptions-v1.json";
    componentIntent = ./intent/components.json;
    componentReviewRoot = ./intent/reviews;
    componentSourceRoot = ./source;
    namePrefix = "spaghetti-extractor-gnu-hello-2.12.3";
  };
  defaultConfiguration = target.workflow.default_configuration;
  components = workflow.components;
  componentRuntime = workflow.componentRuntimeFor defaultConfiguration;
  diagnosticCandidate = workflow.diagnosticCandidates.${defaultConfiguration};
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow;
  inputs.original = original;
  checks = {
    ascii-to-lower-contract = components.contracts.ascii-to-lower;
    ascii-to-lower-evidence = components.evidences.ascii-to-lower;
    ascii-to-lower-qualification = components.qualifications.ascii-to-lower;
    ascii-to-lower-runtime = componentRuntime;
    native-object-package = diagnosticCandidate.nativeObjects.package;
  };
}
