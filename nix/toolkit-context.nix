{ pkgs }:

let
  repositoryRoot = ../.;
  pythonPackages = pkgs.python3Packages;
  packageSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = pkgs.lib.fileset.unions [
      ../pyproject.toml
      ../src
      ../nix
      ../profiles
    ];
  };
  candidateOnlySourceFiles = pkgs.lib.fileset.unions [
    ../src/spaghetti_extractor/stage_b_interpreter_backend.py
    ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
    ../src/spaghetti_extractor/stage_b_candidate_modes.py
    ../src/spaghetti_extractor/stage_b_machine_ir_scope.py
    ../src/spaghetti_extractor/stage_b_native_binding.py
    ../src/spaghetti_extractor/stage_b_native_build.py
    ../src/spaghetti_extractor/stage_b_native_engine.py
    ../src/spaghetti_extractor/stage_b_native_image.py
    ../src/spaghetti_extractor/stage_b_native_runtime.py
    ../src/spaghetti_extractor/stage_b_native_diagnostic.py
    ../src/spaghetti_extractor/stage_b_pe_composer.py
  ];
  leanSource = ../src/spaghetti_extractor/lean;
  analysisPythonFiles = pkgs.lib.fileset.difference ../src (
    pkgs.lib.fileset.unions [
      candidateOnlySourceFiles
      leanSource
    ]
  );
  analysisSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = analysisPythonFiles;
  };
  isaAnalysisSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = pkgs.lib.fileset.unions [
      analysisPythonFiles
      leanSource
    ];
  };
  profileSource = pkgs.lib.fileset.toSource {
    root = ../profiles;
    fileset = ../profiles;
  };
  candidateSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = ../src;
  };
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    capstone
    pefile
    unicorn
    z3-solver
  ]);
  package = pythonPackages.buildPythonApplication {
    pname = "spaghetti-extractor";
    version = "0.1.0";
    pyproject = true;
    src = packageSource;
    build-system = [ pythonPackages.setuptools ];
    dependencies = with pythonPackages; [ capstone pefile z3-solver ];
    # Nixpkgs exposes the z3 Python module without wheel distribution metadata.
    pythonRemoveDeps = [ "z3-solver" ];
    optional-dependencies.conformance = [ pythonPackages.unicorn ];
    pythonImportsCheck = [ "spaghetti_extractor.cli" ];
    doCheck = false;
  };
  testkitTestRunner = pkgs.writeShellScriptBin "spaghetti-extractor-test" ''
    export PYTHONPATH=${candidateSource}/src
    exec ${pythonEnv}/bin/python -m spaghetti_extractor.testkit.runner "$@"
  '';
  testkitDeveloper = pkgs.writeShellScriptBin "spaghetti-extractor-dev" ''
    export PYTHONPATH=${candidateSource}/src
    exec ${pythonEnv}/bin/python -m spaghetti_extractor.testkit "$@"
  '';
  isaConformanceKernel = import ./stage-a-isa-conformance-kernel.nix {
    inherit pkgs leanSource;
  };
  isaSemanticKernel = import ./stage-a-isa-semantic-kernel.nix {
    inherit pkgs leanSource;
  };
  inductiveCertificateKernel = import ./stage-a-inductive-certificate-kernel.nix {
    inherit pkgs leanSource;
  };
  bochsConformance = pkgs.callPackage ./bochs-conformance.nix {
    instrumentationSrc = ../tools/bochs-conformance;
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
  fixtures = {
    bochs-conformance = {
      path = bochsConformance;
      nativeBuildInputs = [ bochsConformance ];
      environment.SPAGHETTI_BOCHS_INTEGRATION_RUNNER =
        "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
      description = "Batched pinned Bochs ISA executor";
      capabilities = [ "bochs" "isa" ];
    };
    compiler = {
      path = pkgs.pkgsCross.mingw32.stdenv.cc;
      nativeBuildInputs = [
        pkgs.stdenv.cc
        pkgs.pkgsCross.mingw32.stdenv.cc
        pkgs.pkgsCross.mingw32.buildPackages.binutils
      ];
      description = "Pinned PE32 cross-compiler toolchain";
      capabilities = [ "compiler" ];
    };
    headless-wine = {
      path = headlessWine;
      nativeBuildInputs = [ headlessWine ];
      description = "Candidate-only Wine runner in a headless X session";
      capabilities = [ "wine" ];
    };
    lean-isa-runner = {
      path = isaConformanceKernel;
      nativeBuildInputs = [ pkgs.lean4 ];
      environment.SPAGHETTI_LEAN_KERNEL_CACHE = isaConformanceKernel;
      description = "Precompiled Lean ISA conformance runner";
      capabilities = [ "isa" "lean" ];
    };
    nix = {
      path = pkgs.nix;
      nativeBuildInputs = [ pkgs.nix ];
      description = "Pinned Nix evaluator for pure fixture inspection";
      capabilities = [ "nix" ];
    };
    pe32-minimal-import-call = {
      path = minimalImportCall;
      description = "Small deterministic PE32 import-call fixture";
      capabilities = [ "native" ];
    };
  };
in
{
  inherit repositoryRoot pythonEnv package fixtures;
  sources = {
    inherit
      packageSource
      analysisSource
      isaAnalysisSource
      profileSource
      candidateSource
      leanSource
      ;
  };
  packages = {
    inherit testkitTestRunner testkitDeveloper;
  };
  kernels = {
    inherit isaConformanceKernel isaSemanticKernel inductiveCertificateKernel;
  };
  tools = {
    inherit bochsConformance headlessWine minimalImportCall;
    bochsRunner = "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
  };
}
