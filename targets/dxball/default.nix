{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource,
  profileSource,
  candidatePythonSource,
  spaghettiExtractor,
  kernelCache,
  semanticKernel,
  bochsRunner,
}:

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
  runtimeMachineImportProfiles = [
    "${profileSource}/profiles/pe32-msvcrt-machine-runtime-v1.json"
    "${profileSource}/profiles/pe32-kernel32-runtime-v1.json"
    "${profileSource}/profiles/pe32-native-callthrough-runtime-v1.json"
    "${profileSource}/profiles/pe32-win32-windowing-runtime-v1.json"
    "${profileSource}/profiles/pe32-winmm-runtime-v1.json"
  ];
  internalFunctionProfile = pkgs.writeText
    "dxball-1.09-internal-function-contracts-v1.json"
    (builtins.readFile ./intent/internal-functions.json);
  analysis = import ../../nix/stage-b-component-analysis.nix {
    inherit pkgs pythonEnv pythonSource;
    inherit isaPythonSource;
    original = "${original}/DXBall.exe";
    externalProfile = builtins.head runtimeMachineImportProfiles;
    additionalMachineImportProfiles = builtins.tail runtimeMachineImportProfiles;
    externalInterfaceProfiles = [
      "${interfaceProfile}/interface-profile.json"
    ];
    callableExternalProfiles = [
      "${profileSource}/profiles/pe32-kernel32-callable-resolvers-v1.json"
    ];
    internalFunctionContractProfiles = [
      internalFunctionProfile
    ];
    normalCallAbiPremise =
      "${profileSource}/profiles/pe32-normal-return-nonvolatile-v1.json";
    launchProfileTemplate =
      "${profileSource}/profiles/pe32-win32-gui-launch-assumptions-v1.json";
    namePrefix = "spaghetti-extractor-dxball-1.09";
    maxUnits = 512;
    maxCandidatesPerSeed = 12;
    isaSelectionAuthority = isaQualification.selectionAuthority.artifact;
  };
  isaQualification = import ../../nix/stage-a-machine-ir-isa-qualification-v2.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      isaPythonSource
      spaghettiExtractor
      kernelCache
      semanticKernel
      bochsRunner
      ;
    requirements =
      analysis.staticHybridAuthorityV2.isaRequirements.artifact;
    name = "spaghetti-extractor-dxball-1.09-isa-v2";
  };
  hybrid = import ../../nix/stage-b-hybrid-candidate.nix {
    inherit pkgs pythonEnv;
    pythonSource = candidatePythonSource;
    machineIr = analysis.machineIr;
    staticExport = analysis.staticExport;
    staticCompletenessReport = analysis.staticHybridCompleteness.report;
    staticAuthorityV2 = analysis.staticHybridAuthorityV2;
    machineImportProfiles = runtimeMachineImportProfiles ++ [
      "${interfaceProfile}/interface-profile.json"
    ];
    namePrefix = "spaghetti-extractor-dxball-1.09";
    allowDeferredPotentialTransfers = false;
  };
  hybridDiagnostic = import ../../nix/stage-b-hybrid-candidate.nix {
    inherit pkgs pythonEnv;
    pythonSource = candidatePythonSource;
    machineIr = analysis.machineIr;
    staticExport = analysis.staticExport;
    staticCompletenessReport = analysis.staticHybridCompleteness.report;
    staticAuthorityV2 = analysis.staticHybridAuthorityV2;
    machineImportProfiles = runtimeMachineImportProfiles ++ [
      "${interfaceProfile}/interface-profile.json"
    ];
    namePrefix = "spaghetti-extractor-dxball-1.09-diagnostic";
    candidateMode = "structural-diagnostic";
    allowDeferredPotentialTransfers = true;
    diagnosticFailureTrap = true;
    externalSiteProposals =
      analysis.diagnosticExternalSiteProposals.artifact;
    callableExternalRuntimeContract =
      analysis.diagnosticCallableExternalRuntime.artifact;
  };
  diagnosticRun = import ../../nix/stage-b-headless-diagnostic-run.nix {
    inherit pkgs pythonEnv;
    pythonSource = candidatePythonSource;
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
  inventory = analysis.originalInventory;
in
{
  inherit
    archive
    installer
    original
    interfaceProfile
    internalFunctionProfile
    inventory
    analysis
    isaQualification
    hybrid
    hybridDiagnostic
    diagnosticRun
    ;
  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource;
    target = ./.;
  };
}
