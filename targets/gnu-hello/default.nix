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
    postInstall = old.postInstall or "";
    __contentAddressed = true;
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  originalPe = "${original}/bin/hello.exe";
  runtimeProfile = "${sdk.profiles}/pe32-msvcrt-machine-runtime-v1.json";
  mingwRuntimeCatalog = sdk.lifting.catalogPack {
    name = "mingw-w64-i686-runtime";
    snapshot = {
      id = "mingw-w64-${mingw.windows.mingw_w64.version}";
      target = {
        architecture = "i686";
        object_format = "coff";
        abi = "mingw32-gcc";
      };
    };
    artifacts = [
      {
        id = "libmingw32.a";
        path = "${mingw.windows.mingw_w64}/lib/libmingw32.a";
        familyId = "mingw-w64";
        componentId = "startup-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
      {
        id = "libmingwex.a";
        path = "${mingw.windows.mingw_w64}/lib/libmingwex.a";
        familyId = "mingw-w64";
        componentId = "extended-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
      {
        id = "libmoldname.a";
        path = "${mingw.windows.mingw_w64}/lib/libmoldname.a";
        familyId = "mingw-w64";
        componentId = "legacy-name-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
    ];
  };
  workflow = sdk.workflow.pe32 {
    targetId = target.id;
    original = originalPe;
    binaryIdentity = "hello.exe";
    externalProfile = runtimeProfile;
    machineImportProfiles = [ runtimeProfile ];
    libraryCatalogIndexes = [
      "${mingwRuntimeCatalog}/library-artifact-index.json"
    ];
    libraryAdoptionIntentRoot = ./intent/libraries;
    launchProfileTemplate =
      "${sdk.profiles}/pe32-win32-console-launch-assumptions-v1.json";
    componentIntent = ./intent/components.json;
    componentReviewRoot = ./intent/reviews;
    componentSourceRoot = ./source;
    componentBindingRoot = ./intent/bindings;
    componentInductionRoot = ./intent/induction;
    namePrefix = "spaghetti-extractor-gnu-hello-2.12.3";
  };
  defaultConfiguration = target.workflow.default_configuration;
  components = workflow.components;
  candidateTests = {
    "gnu-hello-default-candidate" = workflow.candidateTestFor {
      id = "gnu-hello-default-candidate";
      configurationId = defaultConfiguration;
      suite = ./tests/candidate-suite.json;
    };
  };
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow candidateTests;
  inputs.original = original;
  targetAssets.documentation = [ "intent/libraries/README.md" ];
  checks = {
    ascii-to-lower-contract = components.contracts.ascii-to-lower;
    ascii-to-lower-machine-binding = components.machineBindingReceipts.ascii-to-lower;
    ascii-to-lower-semantic-contract = components.semanticContracts.ascii-to-lower;
    ascii-to-lower-semantic-refinement = components.refinementReceipts.ascii-to-lower;
    ascii-to-lower-activation = components.activationCheckGates.ascii-to-lower;
    bounded-string-length-contract = components.contracts.bounded-string-length;
    bounded-string-length-machine-binding = components.machineBindingReceipts.bounded-string-length;
    bounded-string-length-semantic-contract = components.semanticContracts.bounded-string-length;
    bounded-string-length-induction = components.inductionPackages.bounded-string-length;
    bounded-string-length-semantic-refinement = components.refinementReceipts.bounded-string-length;
    bounded-string-length-activation = components.activationCheckGates.bounded-string-length;
    last-path-component-contract = components.contracts.last-path-component;
    last-path-component-machine-binding = components.machineBindingReceipts.last-path-component;
    last-path-component-semantic-contract = components.semanticContracts.last-path-component;
    last-path-component-induction = components.inductionPackages.last-path-component;
    last-path-component-semantic-refinement = components.refinementReceipts.last-path-component;
    last-path-component-activation = components.activationCheckGates.last-path-component;
    memory-regions-equal-contract = components.contracts.memory-regions-equal;
    memory-regions-equal-machine-binding = components.machineBindingReceipts.memory-regions-equal;
    memory-regions-equal-semantic-contract = components.semanticContracts.memory-regions-equal;
    memory-regions-equal-semantic-refinement = components.refinementReceipts.memory-regions-equal;
    memory-regions-equal-activation = components.activationCheckGates.memory-regions-equal;
    short-option-classifier-contract = components.contracts.short-option-classifier;
    short-option-classifier-machine-binding = components.machineBindingReceipts.short-option-classifier;
    short-option-classifier-semantic-contract = components.semanticContracts.short-option-classifier;
    short-option-classifier-semantic-refinement = components.refinementReceipts.short-option-classifier;
    short-option-classifier-activation = components.activationCheckGates.short-option-classifier;
    startup-compare-route-contract = components.contracts.startup-compare-route;
    startup-compare-route-machine-binding = components.machineBindingReceipts.startup-compare-route;
    startup-compare-route-semantic-contract = components.semanticContracts.startup-compare-route;
    startup-compare-route-semantic-refinement = components.refinementReceipts.startup-compare-route;
    startup-compare-route-activation = components.activationCheckGates.startup-compare-route;
  };
}
