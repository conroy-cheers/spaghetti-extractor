{ ... }:

{
  perSystem = { pkgs, ... }:
    let
      context = import ../toolkit-context.nix { inherit pkgs; };
      xedIsaCatalog = pkgs.callPackage ../xed-isa-catalog.nix {
        xedCatalogSrc = ../../tools/xed-isa-catalog;
      };
      sourcePackages = [
        context.package
        context.pythonEnv
        context.nativeExtension
        context.transferNativeExtension
      ];
      executionPackages = [
        pkgs.pkgsCross.mingw32.stdenv.cc
        pkgs.pkgsCross.mingw32.buildPackages.binutils
        pkgs.wineWow64Packages.stableFull
        context.tools.headlessWayland
      ];
      liftingEnvironment = {
        SPAGHETTI_PE32_MCFGTHREAD_DLL = "${pkgs.pkgsCross.mingw32.windows.mcfgthreads}/bin/libmcfgthread-2.dll";
        shellHook = ''
          export PYTHONPATH="$PWD:$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
          export NIX_LDFLAGS_i686_w64_mingw32="-L${pkgs.pkgsCross.mingw32.windows.mcfgthreads}/lib ''${NIX_LDFLAGS_i686_w64_mingw32:-}"
        '';
      };
    in
    {
      packages = {
        default = context.package;
        spaghetti-extractor = context.package;
        spaghetti-extractor-native = context.nativeExtension;
        spaghetti-extractor-transfer-native = context.transferNativeExtension;
        testkit-test-runner = context.packages.testkitTestRunner;
        testkit-developer = context.packages.testkitDeveloper;
        xed-isa-catalog = xedIsaCatalog;
        qualified-platform-v1 = context.platforms.qualifiedPlatform.derivation;
      };

      legacyPackages = {
        default = context.package;
        spaghetti-extractor = context.package;
        spaghetti-extractor-native = context.nativeExtension;
        spaghetti-extractor-transfer-native = context.transferNativeExtension;
        testkit-test-runner = context.packages.testkitTestRunner;
        testkit-developer = context.packages.testkitDeveloper;
        isa-kernel = context.kernels.isaConformanceKernel;
        isa-semantic-kernel = context.kernels.isaSemanticKernel;
        inductive-certificate-kernel = context.kernels.inductiveCertificateKernel;
        relation-kernel = context.kernels.relationKernel;
        bochs-conformance = context.tools.bochsConformance;
        qualified-platform-v1 = context.platforms.qualifiedPlatform.derivation;
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

      # Ordinary component editing needs fewer build inputs than proof/toolkit
      # development. The large full-shell environment also triggered a pinned
      # Wine/Linux-loader crash in retained jq cases with long arguments.
      devShells.lifting = pkgs.mkShell (liftingEnvironment // {
        packages = sourcePackages ++ executionPackages ++ [
          # Preparing pinned source backends for exported component projects.
          pkgs.autoconf
          pkgs.automake
          pkgs.libtool
          pkgs.m4
          pkgs.bison
        ];
      });

      devShells.default = pkgs.mkShell (liftingEnvironment // {
        packages = sourcePackages ++ [
          pkgs.lean4
          pkgs.z3
          pkgs.cbmc
          pkgs.bubblewrap
          pkgs.jq
          pkgs.pkg-config
        ] ++ executionPackages ++ [
          pkgs.xwd
          pkgs.imagemagick
        ];
      });
    };
}
