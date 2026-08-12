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
        mkMachineIRISAQualificationV2 =
          import ./nix/stage-a-machine-ir-isa-qualification-v2.nix;
        mkISASemanticKernel = import ./nix/stage-a-isa-semantic-kernel.nix;
        mkInductiveCertificateKernel =
          import ./nix/stage-a-inductive-certificate-kernel.nix;
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
        mkStaticHybridCompleteness =
          import ./nix/stage-b-static-hybrid-completeness.nix;
        mkCAJsonPhase = import ./nix/ca-python-json-phase.nix;
        mkStaticHybridAuthorityV2Graph =
          import ./nix/stage-b-static-hybrid-authority-v2.nix;
        mkHybridCandidate = import ./nix/stage-b-hybrid-candidate.nix;
        mkHeadlessDiagnosticRun = import ./nix/stage-b-headless-diagnostic-run.nix;
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
            ./src/spaghetti_extractor/stage_b_candidate_modes.py
            ./src/spaghetti_extractor/stage_b_machine_ir_scope.py
            ./src/spaghetti_extractor/stage_b_native_binding.py
            ./src/spaghetti_extractor/stage_b_native_build.py
            ./src/spaghetti_extractor/stage_b_native_engine.py
            ./src/spaghetti_extractor/stage_b_native_image.py
            ./src/spaghetti_extractor/stage_b_native_runtime.py
            ./src/spaghetti_extractor/stage_b_native_diagnostic.py
            ./src/spaghetti_extractor/stage_b_pe_composer.py
          ];
          leanSourceFiles = ./src/spaghetti_extractor/lean;
          analysisPythonFiles = pkgs.lib.fileset.difference ./src (
            pkgs.lib.fileset.unions [
              candidateOnlySourceFiles
              leanSourceFiles
            ]
          );
          analysisSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = analysisPythonFiles;
          };
          isaAnalysisSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              analysisPythonFiles
              leanSourceFiles
            ];
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
              lean --trust=0 \
                -o "$out/StageA/$module.olean" \
                -c "$out/StageA/$module.c" \
                StageA/$module.lean
              leanc -c -o "$out/StageA/$module.o" \
                "$out/StageA/$module.c"
            done
          '';
          isaSemanticKernel = import ./nix/stage-a-isa-semantic-kernel.nix {
            inherit pkgs;
            leanSource = ./src/spaghetti_extractor/lean;
          };
          inductiveCertificateKernel =
            import ./nix/stage-a-inductive-certificate-kernel.nix {
              inherit pkgs;
              leanSource = ./src/spaghetti_extractor/lean;
            };
          bochsConformance = pkgs.callPackage ./nix/bochs-conformance.nix {
            instrumentationSrc = ./tools/bochs-conformance;
          };
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
            isaPythonSource = isaAnalysisSource;
            inherit profileSource;
            candidatePythonSource = candidateSource;
            spaghettiExtractor = package;
            kernelCache = leanKernel;
            semanticKernel = "${isaSemanticKernel}/semantic-kernel.json";
            bochsRunner = "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
          };
        in {
          default = package;
          spaghetti-extractor = package;
          isa-kernel = leanKernel;
          isa-semantic-kernel = isaSemanticKernel;
          inductive-certificate-kernel = inductiveCertificateKernel;
          bochs-conformance = bochsConformance;
          roundtrip-corpus = roundtrip.corpus;
          roundtrip-qualification = roundtrip.qualification;
          gnu-hello-candidate = gnuHello.idiomaticCandidate;
          gnu-hello-intent = gnuHello.intent.validation;
          jq-intent = jqTarget.intent.validation;
          dxball-original = dxball.original;
          dxball-interface-profile = dxball.interfaceProfile;
          dxball-static-inventory = dxball.inventory;
          dxball-static-export = dxball.analysis.staticExport;
          dxball-launch-analysis-assumptions =
            dxball.analysis.launchAnalysisAssumptions;
          dxball-state-machine = dxball.analysis.stateMachine;
          dxball-machine-ir = dxball.analysis.machineIr;
          dxball-static-hybrid-completeness =
            dxball.analysis.staticHybridCompleteness.report;
          dxball-static-hybrid-authority-v2 =
            dxball.analysis.staticHybridAuthorityV2.finalAudit.derivation;
          dxball-transition-summaries-v2 =
            dxball.analysis.staticHybridAuthorityV2.transitionSummaries.derivation;
          dxball-memory-version-graph-v2 =
            dxball.analysis.staticHybridAuthorityV2.memoryVersionGraph.derivation;
          dxball-structural-target-proposals-v2 =
            dxball.analysis.staticHybridAuthorityV2.structuralTargetProposals.derivation;
          dxball-inductive-certificate-proposals-v2 =
            dxball.analysis.staticHybridAuthorityV2.inductiveCertificateProposals.derivation;
          dxball-local-inductive-authority-v2 =
            dxball.analysis.staticHybridAuthorityV2.inductiveCertificateAuthority.derivation;
          dxball-inductive-dependency-closure-v2 =
            dxball.analysis.staticHybridAuthorityV2.inductiveDependencyClosure.derivation;
          dxball-external-site-proposals-v2 =
            dxball.analysis.staticHybridAuthorityV2.checkedExternalSites.derivation;
          dxball-diagnostic-external-site-proposals-v2 =
            dxball.analysis.diagnosticExternalSiteProposals.derivation;
          dxball-diagnostic-rooted-closure-v2 =
            dxball.analysis.diagnosticRootedClosure.derivation;
          dxball-diagnostic-callable-external-runtime-v2 =
            dxball.analysis.diagnosticCallableExternalRuntime.derivation;
          dxball-control-invariants-v2 =
            dxball.analysis.staticHybridAuthorityV2.controlInvariantCertificates.derivation;
          dxball-memory-range-invariants-v2 =
            dxball.analysis.staticHybridAuthorityV2.memoryRangeInvariants.derivation;
          dxball-joint-interprocedural-v2 =
            dxball.analysis.staticHybridAuthorityV2.jointInterproceduralV2.derivation;
          dxball-interprocedural-seed-v2 =
            dxball.analysis.staticHybridAuthorityV2.interproceduralSeed.derivation;
          dxball-parametric-indirect-exit-summaries-v2 =
            dxball.analysis.staticHybridAuthorityV2.parametricIndirectExitSummaries.derivation;
          dxball-interprocedural-v2 =
            dxball.analysis.staticHybridAuthorityV2.interproceduralV2.derivation;
          dxball-global-slot-analysis-v2 =
            dxball.analysis.staticHybridAuthorityV2.globalSlotAnalysis.derivation;
          dxball-global-slot-authority-v2 =
            dxball.analysis.staticHybridAuthorityV2.globalSlotAuthority.derivation;
          dxball-isa-requirements-v2 =
            dxball.analysis.staticHybridAuthorityV2.isaRequirements.derivation;
          dxball-isa-qualification-v2 =
            dxball.isaQualification.aggregate;
          dxball-isa-catalog-proposal-v2 =
            dxball.isaQualification.catalogProposal.derivation;
          dxball-isa-catalog-enrichment-v2 =
            dxball.isaQualification.catalogEnrichment.derivation;
          dxball-isa-boundary-corpus-v2 =
            dxball.isaQualification.corpus;
          dxball-static-authority-report-v2 =
            dxball.analysis.staticHybridAuthorityV2.staticAuthority.derivation;
          dxball-static-hybrid-authority-bundle-v2 =
            dxball.analysis.staticHybridAuthorityV2.authorityBundle.derivation;
          dxball-reconstruction-plan = dxball.analysis.reconstructionPlan;
          dxball-component-proposals = dxball.analysis.componentProposals;
          dxball-interpreter = dxball.hybrid.interpreter;
          dxball-fallback-coverage-receipt =
            dxball.hybrid.fallbackCoverageReceipt;
          dxball-native-engine = dxball.hybrid.nativeEngine;
          dxball-native-runtime = dxball.hybrid.nativeRuntime;
          dxball-native-objects = dxball.hybrid.nativeObjects.package;
          dxball-hybrid-candidate = dxball.hybrid.candidate;
          dxball-diagnostic-native-engine = dxball.hybridDiagnostic.nativeEngine;
          dxball-diagnostic-native-runtime = dxball.hybridDiagnostic.nativeRuntime;
          dxball-hybrid-diagnostic-candidate = dxball.hybridDiagnostic.candidate;
          dxball-headless-diagnostic-run = dxball.diagnosticRun;
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
          staticHybridV2GraphFixture =
            import ./nix/tests/stage-b-static-hybrid-authority-v2.nix {
              inherit pkgs;
              pythonEnv = testPython;
              pythonSource = testSource;
            };
          machineImportControlProfileFixture =
            import ./nix/tests/machine-import-control-profile.nix {
              inherit pkgs;
              pythonEnv = testPython;
              pythonSource = testSource;
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
            python tools/update-python-module-index.py \
              --repository ${testSource} \
              --out ${testSource}/nix/python-module-index.json \
              --check
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
          python-module-index = pkgs.runCommand
            "spaghetti-extractor-python-module-index-check"
            { nativeBuildInputs = [ testPython ]; }
            ''
              python ${testSource}/tools/update-python-module-index.py \
                --repository ${testSource} \
                --out ${testSource}/nix/python-module-index.json \
                --check
              touch "$out"
            '';
          static-hybrid-v2-phase-graph = staticHybridV2GraphFixture.check;
          machine-import-control-profile = machineImportControlProfileFixture;
          isa-kernel = self.packages.${system}.isa-kernel;
          inductive-certificate-kernel =
            self.packages.${system}.inductive-certificate-kernel;
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
