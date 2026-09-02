# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  repositoryRoot = ../.;
  pythonPackages = pkgs.python3Packages;
  developerOnlyNixFiles = pkgs.lib.fileset.unions [
    ../nix/flake-modules
    ../nix/tests
    ../nix/test-suite-fixtures.nix
    ../nix/generated/test-suite-manifest.json
    ../nix/test-suite-plan.nix
    ../nix/test-suite-shard.nix
    ../nix/test-suite.nix
  ];
  installedNixFiles = pkgs.lib.fileset.difference ../nix developerOnlyNixFiles;
  packageSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = pkgs.lib.fileset.unions [
      ../pyproject.toml
      ../src
      installedNixFiles
      ../profiles
    ];
  };
  # Candidate generation is one physical ownership boundary.  Keeping the
  # fileset at package granularity makes new runtime modules private by
  # default and prevents static/ISA derivations from accidentally acquiring
  # candidate-only dependencies.
  runtimeOnlySourceFiles = ../src/spaghetti_extractor/candidate;
  # Import the proof kernel as its own source identity.  A plain nested path
  # retains the enclosing dirty flake source context and makes unrelated
  # candidate/runtime edits reschedule the target-independent ISA campaign.
  leanSourceFiles = ../src/spaghetti_extractor/lean;
  leanSource = pkgs.lib.fileset.toSource {
    root = leanSourceFiles;
    fileset = leanSourceFiles;
  };
  staticPythonFiles = pkgs.lib.fileset.difference ../src (
    pkgs.lib.fileset.unions [
      runtimeOnlySourceFiles
      leanSourceFiles
    ]
  );
  staticSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = staticPythonFiles;
  };
  profileSource = pkgs.lib.fileset.toSource {
    root = ../profiles;
    fileset = ../profiles;
  };
  fullSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = ../src;
  };
  nativeExtension = import ./native-extension.nix {
    inherit pkgs pythonPackages;
  };
  transferNativeExtension = import ./transfer-native-extension.nix {
    inherit pkgs pythonPackages;
  };
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    capstone
    pefile
    nativeExtension
    unicorn
    z3-solver
  ]);
  transferPythonEnv = pkgs.python3.withPackages (ps: with ps; [
    capstone
    pefile
    nativeExtension
    transferNativeExtension
    unicorn
    z3-solver
  ]);
  package = pythonPackages.buildPythonApplication {
    pname = "spaghetti-extractor";
    version = "0.1.0";
    pyproject = true;
    src = packageSource;
    build-system = [ pythonPackages.setuptools ];
    dependencies = with pythonPackages; [
      capstone
      nativeExtension
      transferNativeExtension
      pefile
      z3-solver
    ];
    # Nixpkgs exposes the z3 Python module without wheel distribution metadata.
    pythonRemoveDeps = [ "z3-solver" ];
    optional-dependencies.conformance = [ pythonPackages.unicorn ];
    pythonImportsCheck = [ "spaghetti_extractor.cli" ];
    doCheck = false;
  };
  testkitTestRunner = pkgs.writeShellScriptBin "spaghetti-extractor-test" ''
    export PYTHONPATH=${fullSource}/src
    exec ${transferPythonEnv}/bin/python -m spaghetti_extractor.testkit.runner "$@"
  '';
  testkitDeveloper = pkgs.writeShellScriptBin "spaghetti-extractor-dev" ''
    export PYTHONPATH=${fullSource}/src
    exec ${transferPythonEnv}/bin/python -m spaghetti_extractor.testkit "$@"
  '';
  isaConformanceKernel = import ./isa-conformance-kernel.nix {
    inherit pkgs leanSource;
  };
  isaSemanticKernel = import ./isa-semantic-kernel.nix {
    inherit pkgs leanSource;
  };
  inductiveCertificateKernel = import ./inductive-certificate-kernel.nix {
    inherit pkgs leanSource;
  };
  relationKernel = import ./relation-kernel.nix {
    inherit pkgs leanSource;
  };
  isaFormInventory = builtins.path {
    path =
      ../src/spaghetti_extractor/qualified_platform/pe32_i686_isa_forms.json;
    name = "spaghetti-qualified-platform-pe32-i686-isa-forms.json";
  };
  bochsConformance = pkgs.callPackage ./bochs-conformance.nix {
    instrumentationSrc = ../tools/bochs-conformance;
  };
  qualifiedPlatform = import ./qualified-platform.nix {
    inherit pkgs pythonEnv;
    kernelCache = isaConformanceKernel;
    semanticKernel = "${isaSemanticKernel}/semantic-kernel.json";
    inherit isaFormInventory;
    bochsRunner =
      "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
  };
  headlessWine = pkgs.writeShellApplication {
    name = "spaghetti-headless-wine";
    runtimeInputs = [ pkgs.wineWow64Packages.stableFull pkgs.xvfb-run ];
    text = ''
      export WINEPREFIX="''${WINEPREFIX:-$TMPDIR/spaghetti-wine}"
      export WINEDEBUG="''${WINEDEBUG:--all}"
      exec xvfb-run -a -s '-screen 0 1024x768x24' wine "$@"
    '';
  };
  minimalImportCall = pkgs.runCommand "spaghetti-pe32-minimal-import-call" {
    nativeBuildInputs = [ pkgs.pkgsCross.mingw32.stdenv.cc ];
    __contentAddressed = true;
  } ''
    mkdir -p "$out"
    cat > fixture.c <<'EOF'
    #include <windows.h>
    int main(void) {
      static const char text[] = "fixture\n";
      DWORD written = 0;
      WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, sizeof(text) - 1, &written, 0);
      return written == sizeof(text) - 1 ? 0 : 1;
    }
    EOF
    i686-w64-mingw32-gcc -Os -s fixture.c -o "$out/minimal-import-call.exe"
  '';
  fixtureCatalog = import ./test-fixture-catalog.nix { inherit (pkgs) lib; };
  fixtures = fixtureCatalog.bind {
    bochs-conformance = {
      path = bochsConformance;
      nativeBuildInputs = [ bochsConformance ];
      environment.SPAGHETTI_BOCHS_INTEGRATION_RUNNER =
        "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
    };
    cbmc = {
      path = pkgs.cbmc;
      nativeBuildInputs = [ pkgs.cbmc ];
    };
    compiler = {
      path = pkgs.pkgsCross.mingw32.stdenv.cc;
      nativeBuildInputs = [
        pkgs.stdenv.cc
        pkgs.pkgsCross.mingw32.stdenv.cc
        pkgs.pkgsCross.mingw32.buildPackages.binutils
      ];
    };
    headless-wine = {
      path = headlessWine;
      nativeBuildInputs = [ headlessWine ];
    };
    lean-isa-runner = {
      path = isaConformanceKernel;
      nativeBuildInputs = [ pkgs.lean4 ];
      environment.SPAGHETTI_LEAN_KERNEL_CACHE = isaConformanceKernel;
    };
    nix = {
      path = pkgs.nix;
      nativeBuildInputs = [ pkgs.nix ];
    };
    pe32-minimal-import-call = {
      path = minimalImportCall;
    };
  };
in
{
  inherit repositoryRoot pythonEnv transferPythonEnv package nativeExtension
    transferNativeExtension fixtureCatalog fixtures;
  sources = {
    inherit
      packageSource
      staticSource
      profileSource
      fullSource
      leanSource
      ;
  };
  packages = {
    inherit testkitTestRunner testkitDeveloper;
  };
  kernels = {
    inherit
      isaConformanceKernel
      isaSemanticKernel
      inductiveCertificateKernel
      relationKernel
      ;
  };
  platforms = {
    inherit qualifiedPlatform;
  };
  tools = {
    inherit bochsConformance headlessWine minimalImportCall;
    bochsRunner = "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
  };
}
