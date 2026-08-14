{ ... }:

{
  perSystem = { pkgs, ... }:
    let
      context = import ../toolkit-context.nix { inherit pkgs; };
      xedIsaCatalog = pkgs.callPackage ../xed-isa-catalog.nix {
        xedCatalogSrc = ../../tools/xed-isa-catalog;
      };
    in
    {
      packages = {
        default = context.package;
        spaghetti-extractor = context.package;
        testkit-test-runner = context.packages.testkitTestRunner;
        testkit-developer = context.packages.testkitDeveloper;
        xed-isa-catalog = xedIsaCatalog;
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
      } // context.fixtureCatalog.packageAttributes context.fixtures;

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
        xed-isa-catalog = {
          type = "app";
          program = "${xedIsaCatalog}/bin/xed-isa-catalog";
          meta.description = "Emit the pinned raw XED instruction catalog for PE32 i686";
        };
      };

      devShells.default = pkgs.mkShell {
        packages = [
          context.package
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
