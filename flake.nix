{
  description = "Spaghetti Extractor static PE32 reconstruction and source-lifting toolkit";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      lib = {
        mkPythonModuleClosure = import ./nix/python-module-closure.nix;
        mkISAQualificationGraph = import ./nix/stage-a-isa-qualification-graph.nix;
        mkRoundtripCorpus = import ./nix/stage-a-roundtrip-corpus.nix;
        mkExternalInterfaceProfile = import ./nix/stage-a-external-interface-profile.nix;
        mkComponentAnalysis = import ./nix/stage-b-component-analysis.nix;
        mkComponentDiscovery = import ./nix/stage-b-component-discovery.nix;
        mkComponentInterfaces = import ./nix/stage-b-component-interfaces.nix;
        mkComponentSelection = import ./nix/stage-b-component-selection.nix;
        mkLinkedLibraryAnalysis = import ./nix/stage-b-linked-libraries.nix;
        mkSourceCallSubstitutions = import ./nix/stage-b-source-call-substitutions.nix;
        mkSourceComponentAssurance = import ./nix/stage-b-source-component-assurance.nix;
        mkFunctionalSuite = import ./nix/stage-b-functional-suite.nix;
        mkUpstreamShellSuite = import ./nix/stage-b-upstream-shell-suite.nix;
        mkHybridCandidate = import ./nix/stage-b-hybrid-candidate.nix;
      };

      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pythonPackages = pkgs.python3Packages;
          packageSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./pyproject.toml
              ./src
              ./nix
              ./profiles
            ];
          };
          candidateOnlySourceFiles = pkgs.lib.fileset.unions [
            ./src/spaghetti_extractor/stage_b_interpreter_backend.py
            ./src/spaghetti_extractor/stage_b_interpreter_native_build.py
            ./src/spaghetti_extractor/stage_b_machine_ir_scope.py
            ./src/spaghetti_extractor/stage_b_native_binding.py
            ./src/spaghetti_extractor/stage_b_native_build.py
            ./src/spaghetti_extractor/stage_b_native_engine.py
            ./src/spaghetti_extractor/stage_b_native_image.py
            ./src/spaghetti_extractor/stage_b_native_runtime.py
            ./src/spaghetti_extractor/stage_b_pe_composer.py
          ];
          analysisSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.difference ./src candidateOnlySourceFiles;
          };
          profileSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./profiles;
          };
          candidateSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./src;
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
            # Nixpkgs builds the z3 Python module as an output of z3 rather than
            # a wheel with z3-solver distribution metadata.
            pythonRemoveDeps = [ "z3-solver" ];
            optional-dependencies = {
              conformance = [ pythonPackages.unicorn ];
            };
            pythonImportsCheck = [ "spaghetti_extractor.cli" ];
            doCheck = false;
          };
          leanKernel = pkgs.runCommand "spaghetti-extractor-isa-kernel" {
            nativeBuildInputs = [ pkgs.lean4 ];
            __contentAddressed = true;
          } ''
            cp -r ${./src/spaghetti_extractor/lean}/StageA .
            chmod -R u+w StageA
            mkdir -p "$out/StageA"
            export LEAN_PATH="$out:$PWD"
            for module in X87 Formal ISAQualification ISAInventory ISAConformance ISAConformanceRunner; do
              lean -o "$out/StageA/$module.olean" \
                StageA/$module.lean
            done
          '';
          roundtrip = import ./nix/stage-a-roundtrip-corpus.nix {
            inherit pkgs pythonEnv;
            source = analysisSource;
            count = 6;
          };
          gnuHello = import ./targets/gnu-hello {
            inherit pkgs pythonEnv;
            pythonSource = analysisSource;
          };
          jqTarget = import ./targets/jq {
            inherit pkgs pythonEnv;
            pythonSource = analysisSource;
          };
          dxball = import ./targets/dxball {
            inherit pkgs pythonEnv;
            pythonSource = analysisSource;
            inherit profileSource;
            candidatePythonSource = candidateSource;
          };
        in {
          default = package;
          spaghetti-extractor = package;
          isa-kernel = leanKernel;
          roundtrip-corpus = roundtrip.corpus;
          roundtrip-qualification = roundtrip.qualification;
          gnu-hello-candidate = gnuHello.idiomaticCandidate;
          gnu-hello-intent = gnuHello.intent.validation;
          jq-intent = jqTarget.intent.validation;
          dxball-original = dxball.original;
          dxball-interface-profile = dxball.interfaceProfile;
          dxball-static-inventory = dxball.inventory;
          dxball-static-export = dxball.analysis.staticExport;
          dxball-state-machine = dxball.analysis.stateMachine;
          dxball-machine-ir = dxball.analysis.machineIr;
          dxball-reconstruction-plan = dxball.analysis.reconstructionPlan;
          dxball-component-proposals = dxball.analysis.componentProposals;
          dxball-interpreter = dxball.hybrid.interpreter;
          dxball-native-engine = dxball.hybrid.nativeEngine;
          dxball-native-runtime = dxball.hybrid.nativeRuntime;
          dxball-native-objects = dxball.hybrid.nativeObjects.package;
          dxball-hybrid-candidate = dxball.hybrid.candidate;
          dxball-hybrid-diagnostic-candidate = dxball.hybridDiagnostic.candidate;
        });

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          package = self.packages.${system}.spaghetti-extractor;
          testPython = pkgs.python3.withPackages (ps: with ps; [
            capstone
            pefile
            unicorn
            z3-solver
          ]);
          testSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./README.md
              ./REPOSITORY_MAP.md
              ./docs
              ./flake.nix
              ./isa-catalogs
              ./nix
              ./profiles
              ./pyproject.toml
              ./src
              ./targets
              ./tests
              ./tools
            ];
          };
          interpreterPythonClosure = import ./nix/python-module-closure.nix {
            inherit pkgs;
            source = testSource;
            modules = [ "spaghetti_extractor.stage_b_interpreter_backend" ];
            name = "spaghetti-extractor-interpreter-python-closure-smoke";
          };
        in {
          import-smoke = pkgs.runCommand "spaghetti-extractor-import-smoke" {
            nativeBuildInputs = [ package ];
          } ''
            spaghetti-extractor --help >/dev/null
            spaghetti-extractor stage-a-inventory-binary --help >/dev/null
            spaghetti-extractor stage-b-create-component --help >/dev/null
            touch "$out"
          '';
          python-tests = pkgs.runCommand "spaghetti-extractor-python-tests" {
            nativeBuildInputs = [ testPython ];
          } ''
            export PYTHONPATH=${testSource}/src:${testSource}/tests
            cd ${testSource}
            python -m unittest discover -s tests -p 'test_*.py'
            touch "$out"
          '';
          python-module-closure = pkgs.runCommand
            "spaghetti-extractor-python-module-closure-check"
            { nativeBuildInputs = [ testPython ]; }
            ''
              export PYTHONPATH=${interpreterPythonClosure}/src
              python -c 'import spaghetti_extractor.stage_b_interpreter_backend'
              test -s ${interpreterPythonClosure}/python-module-closure.json
              touch "$out"
            '';
          isa-kernel = self.packages.${system}.isa-kernel;
          roundtrip = self.packages.${system}.roundtrip-qualification;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.spaghetti-extractor}/bin/spaghetti-extractor";
          meta.description = "Static PE32 reconstruction and component-lifting toolkit";
        };
        slice = {
          type = "app";
          program = "${self.packages.${system}.spaghetti-extractor}/bin/spaghetti-extractor-slice";
          meta.description = "Incremental candidate repair loop";
        };
      });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pythonEnv = pkgs.python3.withPackages (ps: with ps; [ capstone pefile unicorn z3-solver ]);
        in {
          default = pkgs.mkShell {
            packages = [
              pythonEnv
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
        });
    };
}
