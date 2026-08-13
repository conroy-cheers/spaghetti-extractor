{ ... }:

{
  perSystem = { pkgs, ... }:
    let
      context = import ../toolkit-context.nix { inherit pkgs; };
    in
    {
      packages = {
        default = context.package;
        spaghetti-extractor = context.package;
        testkit-test-runner = context.packages.testkitTestRunner;
        testkit-developer = context.packages.testkitDeveloper;
      };

      legacyPackages = {
        default = context.package;
        spaghetti-extractor = context.package;
        testkit-test-runner = context.packages.testkitTestRunner;
        testkit-developer = context.packages.testkitDeveloper;
        isa-kernel = context.kernels.isaConformanceKernel;
        isa-semantic-kernel = context.kernels.isaSemanticKernel;
        inductive-certificate-kernel = context.kernels.inductiveCertificateKernel;
        bochs-conformance = context.tools.bochsConformance;
        test-fixture-bochs-conformance = context.tools.bochsConformance;
        test-fixture-compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
        test-fixture-headless-wine = context.tools.headlessWine;
        test-fixture-lean-isa-runner = context.kernels.isaConformanceKernel;
        test-fixture-nix = pkgs.nix;
        test-fixture-pe32-minimal-import-call = context.tools.minimalImportCall;
      };

      apps = {
        default = {
          type = "app";
          program = "${context.package}/bin/spaghetti-extractor";
          meta.description = "Static PE32 reconstruction and component-lifting toolkit";
        };
        test = {
          type = "app";
          program = "${context.packages.testkitTestRunner}/bin/spaghetti-extractor-test";
          meta.description = "Nix-first cached smoke, affected, full, and benchmark validation";
        };
        dev = {
          type = "app";
          program = "${context.packages.testkitDeveloper}/bin/spaghetti-extractor-dev";
          meta.description = "Test scaffolding, fixture discovery, rebuild explanation, and environment diagnosis";
        };
      };

      devShells.default = pkgs.mkShell {
        packages = [
          context.pythonEnv
          pkgs.lean4
          pkgs.z3
          pkgs.cbmc
          pkgs.jq
          pkgs.pkg-config
          pkgs.pkgsCross.mingw32.stdenv.cc
          pkgs.pkgsCross.mingw32.buildPackages.binutils
          pkgs.wineWow64Packages.stableFull
          pkgs.xvfb-run
          pkgs.xwd
          pkgs.imagemagick
        ];
        shellHook = ''export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"'';
      };
    };
}
