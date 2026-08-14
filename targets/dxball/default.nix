{ pkgs, sdk }:

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
  analysis = sdk.analysis.component {
    original = "${original}/DXBall.exe";
    externalProfile = builtins.head runtimeMachineImportProfiles;
    additionalMachineImportProfiles = builtins.tail runtimeMachineImportProfiles;
    externalInterfaceProfiles = [
      "${interfaceProfile}/interface-profile.json"
    ];
    launchProfileTemplate =
      "${sdk.profiles}/pe32-win32-gui-launch-assumptions-v1.json";
    namePrefix = "spaghetti-extractor-dxball-1.09";
    maxUnits = 512;
    maxCandidatesPerSeed = 12;
  };
  componentsV2 = sdk.lifting.componentContractsV2 {
    machineIr = analysis.machineIr;
    reconstructionPlan = analysis.reconstructionPlan;
    componentProposals = analysis.componentProposals;
    intent = ./intent/components.json;
    reviewRoot = ./intent/reviews;
    namePrefix = "spaghetti-extractor-dxball-1.09";
  };
  analysisV3 = sdk.analysis.authorityV3 {
    name = "spaghetti-extractor-dxball-1.09-authority-v3";
    machineIr = "${analysis.machineIr}/machine-ir.jsonl";
    binary = "${original}/DXBall.exe";
    binaryIdentity = "DXBall.exe";
    machineImportProfiles = runtimeMachineImportProfiles;
    launchProfileTemplate =
      "${sdk.profiles}/pe32-win32-gui-launch-assumptions-v1.json";
  };
  hybrid = sdk.candidate.hybrid {
    machineIr = analysis.machineIr;
    staticExport = analysis.staticExport;
    staticAuthorityV3 = analysisV3;
    machineImportProfiles = runtimeMachineImportProfiles ++ [
      "${interfaceProfile}/interface-profile.json"
    ];
    namePrefix = "spaghetti-extractor-dxball-1.09";
    allowDeferredPotentialTransfers = false;
  };
  hybridDiagnostic = sdk.candidate.hybrid {
    machineIr = analysis.machineIr;
    staticExport = analysis.staticExport;
    machineImportProfiles = runtimeMachineImportProfiles ++ [
      "${interfaceProfile}/interface-profile.json"
    ];
    namePrefix = "spaghetti-extractor-dxball-1.09-diagnostic";
    candidateMode = "structural-diagnostic";
    allowDeferredPotentialTransfers = true;
    diagnosticFailureTrap = true;
  };
  diagnosticRun = sdk.candidate.headlessDiagnostic {
    namePrefix = "spaghetti-extractor-dxball-1.09";
    candidateBinary = "${hybridDiagnostic.candidate}/candidate.exe";
    nativeEnginePlan =
      "${hybridDiagnostic.nativeEngine}/native-engine-plan.json";
    nativeRuntimePackage = hybridDiagnostic.nativeRuntime;
    runtimeAssets = "${original}/runtime";
    executableName = "DXBall.exe";
    inputKeys = [ "Return" ];
    screenshotAfterSeconds = 15;
  };
  intent = sdk.analysis.targetIntent {
    target = ./.;
  };
in
sdk.target.bundle {
  targetRoot = ./.;
  artifacts = {
    input = {
      archive = archive;
      installer = installer;
      original = original;
    };
    intent = intent.validation;
    profiles.interface = interfaceProfile;
    analysis = {
      inventory = analysis.originalInventory;
      static-export = analysis.staticExport;
      launch-assumptions = analysis.launchAnalysisAssumptions;
      state-machine = analysis.stateMachine;
      machine-ir = analysis.machineIr;
      reconstruction-plan = analysis.reconstructionPlan;
      component-proposals = analysis.componentProposals;
    };
    components = {
      resolution = componentsV2.resolution;
      contracts = componentsV2.contracts;
      source-packages = componentsV2.sourcePackages;
      contract-bundle = componentsV2.bundle;
      configurations = componentsV2.activationPlans;
      source-bundles = componentsV2.sourceBundles;
    };
    authority = {
      final = analysisV3.finalAuthority;
      gate = analysisV3.finalAuthorityGate;
      transition-summaries =
        analysisV3.graph.phases."transition-summaries-v3".derivation;
      graph-metadata = analysisV3.graph.metadata;
      diagnostics = analysisV3.diagnostics;
    };
    hybrid = {
      interpreter = hybrid.interpreter;
      fallback-coverage = hybrid.fallbackCoverageReceipt;
      candidate-authority = hybrid.candidateAuthorityReport;
      native-engine = hybrid.nativeEngine;
      native-runtime = hybrid.nativeRuntime;
      native-objects = hybrid.nativeObjects.package;
      candidate = hybrid.candidate;
    };
    diagnostic = {
      native-engine = hybridDiagnostic.nativeEngine;
      native-runtime = hybridDiagnostic.nativeRuntime;
      candidate = hybridDiagnostic.candidate;
      run = diagnosticRun;
    };
  };
  checks = {
    intent = intent.validation;
    component-resolution = componentsV2.resolution;
    component-contract = componentsV2.contracts.startup-extended;
    component-configuration = componentsV2.activationPlans.startup-extended;
  };
}
