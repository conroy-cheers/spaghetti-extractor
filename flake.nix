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
        mkISAConformanceKernel =
          import ./nix/stage-a-isa-conformance-kernel.nix;
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
        mkSourceProject = import ./nix/stage-b-source-project.nix;
        mkSourceIterationAudit =
          import ./nix/stage-b-source-iteration-audit.nix;
        mkSourceLiftAudit = import ./nix/stage-b-source-lift-audit.nix;
        mkSourceQualification = import ./nix/stage-b-source-qualification.nix;
        mkLiftCompletionReceipt =
          import ./nix/stage-b-lift-completion-receipt.nix;
        mkSourceComponentAssurance = import ./nix/stage-b-source-component-assurance.nix;
        mkFunctionalSuite = import ./nix/stage-b-functional-suite.nix;
        mkUpstreamShellSuite = import ./nix/stage-b-upstream-shell-suite.nix;
        mkCAJsonPhase = import ./nix/ca-python-json-phase.nix;
        mkArtifactSetV3 = import ./nix/artifact-set-v3.nix;
        mkArtifactSeedV3 = import ./nix/artifact-seed-v3.nix;
        mkArtifactPhaseV3 = import ./nix/artifact-phase-v3.nix;
        mkAnalysisSourcePlanV3 = import ./nix/analysis-v3-source-plan.nix;
        mkAnalysisMachineIRInputV3 = import ./nix/analysis-v3-machine-ir-input.nix;
        mkAnalysisAuthorityV3 = import ./nix/analysis-v3-authority.nix;
        mkAnalysisAuthorityDiagnosticsV3 =
          import ./nix/analysis-v3-diagnostics.nix;
        mkExternalSiteEvidenceV3 =
          import ./nix/analysis-v3-external-site-evidence.nix;
        mkImplementationCapabilitiesV3 =
          import ./nix/analysis-v3-implementation-capabilities.nix;
        mkISAFrontiersV3 = import ./nix/analysis-v3-isa-frontiers.nix;
        mkIndexedTargetEvidenceV3 =
          import ./nix/analysis-v3-indexed-target-evidence.nix;
        mkFinalAuthorityGateV3 =
          import ./nix/analysis-v3-final-authority-gate.nix;
        mkAnalysisGraphManifestV3 = import ./nix/analysis-v3-graph-manifest.nix;
        mkAuthorityGraphV3 = import ./nix/authority-graph-v3.nix;
        mkTestSuite = import ./nix/test-suite.nix;
        mkHybridCandidate = import ./nix/stage-b-hybrid-candidate.nix;
        mkFallbackCoverageReceipt =
          import ./nix/stage-b-fallback-coverage-receipt.nix;
        mkHeadlessDiagnosticRun = import ./nix/stage-b-headless-diagnostic-run.nix;
      };

      # Heavy target artifacts and granular test shards remain directly
      # buildable through Nix's legacyPackages fallback, but are deliberately
      # kept out of `packages`.  `nix flake check` validates every package
      # attribute eagerly; exposing the analysis universe there turned a warm
      # check into tens of seconds of evaluator work without checking more
      # semantics.
      legacyPackages = forAllSystems (system:
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
          testkitTestRunner = pkgs.writeShellScriptBin "spaghetti-extractor-test" ''
            export PYTHONPATH=${candidateSource}/src
            exec ${pythonEnv}/bin/python -m spaghetti_extractor.testkit.runner "$@"
          '';
          testkitDeveloper = pkgs.writeShellScriptBin "spaghetti-extractor-dev" ''
            export PYTHONPATH=${candidateSource}/src
            exec ${pythonEnv}/bin/python -m spaghetti_extractor.testkit "$@"
          '';
          leanKernel = import ./nix/stage-a-isa-conformance-kernel.nix {
            inherit pkgs;
            leanSource = ./src/spaghetti_extractor/lean;
          };
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
          headlessWineFixture = pkgs.writeShellApplication {
            name = "spaghetti-headless-wine";
            runtimeInputs = [ pkgs.wineWow64Packages.stableFull pkgs.xvfb-run ];
            text = ''
              export WINEPREFIX="''${WINEPREFIX:-$TMPDIR/spaghetti-wine}"
              export WINEDEBUG="''${WINEDEBUG:--all}"
              exec xvfb-run -a -s '-screen 0 1024x768x24' wine "$@"
            '';
          };
          minimalImportCallFixture = pkgs.runCommand
            "spaghetti-pe32-minimal-import-call" {
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
          testFixtures = {
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
                pkgs.pkgsCross.mingw32.stdenv.cc
                pkgs.pkgsCross.mingw32.buildPackages.binutils
              ];
              description = "Pinned PE32 cross-compiler toolchain";
              capabilities = [ "compiler" ];
            };
            headless-wine = {
              path = headlessWineFixture;
              nativeBuildInputs = [ headlessWineFixture ];
              description = "Candidate-only Wine runner in a headless X session";
              capabilities = [ "wine" ];
            };
            lean-isa-runner = {
              path = leanKernel;
              nativeBuildInputs = [ pkgs.lean4 ];
              environment.SPAGHETTI_LEAN_KERNEL_CACHE = leanKernel;
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
              path = minimalImportCallFixture;
              description = "Small deterministic PE32 import-call fixture";
              capabilities = [ "native" ];
            };
          };
          mkTestSuite = mode: import ./nix/test-suite.nix {
            inherit pkgs pythonEnv mode;
            repositoryRoot = ./.;
            fixtures = testFixtures;
          };
          smokeSuite = mkTestSuite "smoke";
          fullSuite = mkTestSuite "full";
          catalogSuite = mkTestSuite "catalog";
          benchmarkSuite = mkTestSuite "benchmark";
          targetSuites = pkgs.lib.genAttrs [ "gnu-hello" "jq" "dxball" ]
            (target: import ./nix/test-suite.nix {
              inherit pkgs pythonEnv target;
              repositoryRoot = ./.;
              mode = "target";
              fixtures = testFixtures;
            });
          roundtrip = import ./nix/stage-a-roundtrip-corpus.nix {
            inherit pkgs pythonEnv;
            source = analysisSource;
            count = 6;
          };
          authorityGraphV3Check = import ./tests/unit/nix_v3/check.nix { inherit pkgs; };
          artifactSeedV3Check = import ./nix/tests/artifact-seed-v3.nix {
            inherit pkgs pythonEnv;
            pythonSource = analysisSource;
          };
          analysisV3MachineIrInputCheck = import ./nix/tests/analysis-v3-machine-ir-input.nix {
            inherit pkgs pythonEnv;
            pythonSource = analysisSource;
          };
          fullGate = pkgs.linkFarm "spaghetti-extractor-test-full" [
            { name = "python-suite"; path = fullSuite.aggregate; }
            { name = "analysis-v3-machine-ir-input"; path = analysisV3MachineIrInputCheck; }
            { name = "authority-graph-v3"; path = authorityGraphV3Check; }
            { name = "artifact-seed-v3"; path = artifactSeedV3Check; }
            { name = "roundtrip-qualification"; path = roundtrip.qualification; }
          ];
          gnuHello = import ./targets/gnu-hello {
            inherit pkgs pythonEnv isaSemanticKernel;
            pythonSource = analysisSource;
            isaPythonSource = isaAnalysisSource;
            spaghettiExtractor = package;
            isaKernelCache = leanKernel;
            bochsRunner =
              "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
          };
          jqTarget = import ./targets/jq {
            inherit pkgs pythonEnv isaSemanticKernel;
            pythonSource = analysisSource;
            isaPythonSource = isaAnalysisSource;
            spaghettiExtractor = package;
            isaKernelCache = leanKernel;
            bochsRunner =
              "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
          };
          dxball = import ./targets/dxball {
            inherit pkgs pythonEnv isaSemanticKernel;
            pythonSource = analysisSource;
            isaPythonSource = isaAnalysisSource;
            spaghettiExtractor = package;
            isaKernelCache = leanKernel;
            bochsRunner =
              "${bochsConformance}/bin/spaghetti-bochs-conformance-runner";
            inherit profileSource;
            candidatePythonSource = candidateSource;
          };
        in {
          default = package;
          spaghetti-extractor = package;
          testkit-test-runner = testkitTestRunner;
          testkit-developer = testkitDeveloper;
          isa-kernel = leanKernel;
          isa-semantic-kernel = isaSemanticKernel;
          inductive-certificate-kernel = inductiveCertificateKernel;
          bochs-conformance = bochsConformance;
          test-smoke = smokeSuite.aggregate;
          test-full = fullGate;
          test-benchmark = benchmarkSuite.aggregate;
          test-target-gnu-hello = targetSuites.gnu-hello.aggregate;
          test-target-jq = targetSuites.jq.aggregate;
          test-target-dxball = targetSuites.dxball.aggregate;
          test-fixture-bochs-conformance = bochsConformance;
          test-fixture-compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
          test-fixture-headless-wine = headlessWineFixture;
          test-fixture-lean-isa-runner = leanKernel;
          test-fixture-nix = pkgs.nix;
          test-fixture-pe32-minimal-import-call = minimalImportCallFixture;
          authority-graph-v3-check = authorityGraphV3Check;
          artifact-seed-v3-check = artifactSeedV3Check;
          analysis-v3-machine-ir-input-check = analysisV3MachineIrInputCheck;
          roundtrip-corpus = roundtrip.corpus;
          roundtrip-qualification = roundtrip.qualification;
          gnu-hello-candidate = gnuHello.idiomaticCandidate;
          gnu-hello-native-candidate =
            gnuHello.idiomaticSourceProject.nativeCandidate;
          gnu-hello-source-project-specification =
            gnuHello.idiomaticSourceSpecification;
          gnu-hello-source-project-evidence-plan =
            gnuHello.idiomaticSourceEvidencePlan;
          gnu-hello-source-project-binding = gnuHello.idiomaticSourceBinding;
          gnu-hello-source-iteration-audit =
            gnuHello.sourceIterationAudit;
          gnu-hello-source-ast = gnuHello.sourceAst;
          gnu-hello-source-call-inventory =
            gnuHello.sourceCalls.sourceInventory;
          gnu-hello-call-frontier = gnuHello.sourceCalls.callFrontier;
          gnu-hello-call-substitution-plan = gnuHello.sourceCalls.callPlan;
          gnu-hello-static-indirect-call-targets =
            gnuHello.sourceCalls.generatedIndirectTargets;
          gnu-hello-source-call-report =
            gnuHello.sourceCalls.sourceBindingReport;
          gnu-hello-candidate-dependency-audit =
            gnuHello.sourceCalls.candidateAudit;
          gnu-hello-source-component-assurance =
            gnuHello.sourceComponentAssurance;
          gnu-hello-source-lift-audit = gnuHello.idiomaticSourceLiftAudit;
          gnu-hello-source-qualification = gnuHello.sourceQualification;
          gnu-hello-runtime-qualification = gnuHello.runtimeQualification;
          gnu-hello-candidate-validation = gnuHello.candidateValidation;
          gnu-hello-native-functional-suite =
            gnuHello.idiomaticSourceProject.nativeFunctionalSuite;
          gnu-hello-static-implementation-ledger =
            gnuHello.staticImplementationLedger;
          gnu-hello-portable-implementation-ledger =
            gnuHello.portableImplementationLedger;
          gnu-hello-runtime-lock = gnuHello.runtimeLock;
          gnu-hello-static-completion-receipt =
            gnuHello.staticCompletionReceipt;
          gnu-hello-portable-completion-receipt =
            gnuHello.portableCompletionReceipt;
          gnu-hello-lift-workbench = gnuHello.liftWorkbench;
          gnu-hello-lift-workflow = gnuHello.liftWorkflow;
          gnu-hello-linked-islands = gnuHello.linkedLibraries.linkedIslands;
          gnu-hello-functional-suite-spec =
            gnuHello.idiomaticFunctionalSuiteSpec;
          gnu-hello-original = gnuHello.original;
          gnu-hello-machine-ir = gnuHello.analysis.machineIr;
          gnu-hello-component-proposals =
            gnuHello.analysis.componentProposals;
          gnu-hello-intent = gnuHello.intent.validation;
          gnu-hello-final-authority-v3 = gnuHello.analysisV3.finalAuthority;
          gnu-hello-final-authority-v3-gate =
            gnuHello.analysisV3.finalAuthorityGate;
          gnu-hello-authority-graph-v3-metadata =
            gnuHello.analysisV3.graph.metadata;
          gnu-hello-authority-diagnostics-v3 =
            gnuHello.analysisV3.diagnostics;
          gnu-hello-external-site-evidence-v3 =
            gnuHello.analysisV3.generatedExternalSiteEvidence;
          gnu-hello-isa-evidence-v3 =
            gnuHello.analysisV3.generatedISAEvidence.projection;
          gnu-hello-isa-requirements-v2 =
            gnuHello.analysisV3.generatedISAEvidence.requirements;
          gnu-hello-isa-selection-authority =
            gnuHello.analysisV3.generatedISAEvidence.qualification.selectionAuthority.derivation;
          gnu-hello-isa-frontiers =
            gnuHello.analysisV3.generatedISAEvidence.frontiers;
          gnu-hello-indexed-target-evidence-v3 =
            gnuHello.analysisV3.generatedIndexedTargetEvidence;
          gnu-hello-fallback-interpreter-v3 =
            gnuHello.analysisV3.fallbackInterpreter;
          gnu-hello-fallback-coverage-receipt-v3 =
            gnuHello.analysisV3.fallbackCoverageReceipt;
          gnu-hello-implementation-capabilities-v3 =
            gnuHello.analysisV3.generatedImplementationCapabilities;
          jq-intent = jqTarget.intent.validation;
          jq-final-authority-v3 = jqTarget.analysisV3.finalAuthority;
          jq-final-authority-v3-gate = jqTarget.analysisV3.finalAuthorityGate;
          jq-authority-graph-v3-metadata = jqTarget.analysisV3.graph.metadata;
          jq-authority-diagnostics-v3 = jqTarget.analysisV3.diagnostics;
          dxball-original = dxball.original;
          dxball-interface-profile = dxball.interfaceProfile;
          dxball-static-inventory = dxball.inventory;
          dxball-static-export = dxball.analysis.staticExport;
          dxball-launch-analysis-assumptions =
            dxball.analysis.launchAnalysisAssumptions;
          dxball-state-machine = dxball.analysis.stateMachine;
          dxball-machine-ir = dxball.analysis.machineIr;
          dxball-final-authority-v3 = dxball.analysisV3.finalAuthority;
          dxball-final-authority-v3-gate = dxball.analysisV3.finalAuthorityGate;
          dxball-transition-summaries-v3 =
            dxball.analysisV3.graph.phases."transition-summaries-v3".derivation;
          dxball-authority-graph-v3-metadata = dxball.analysisV3.graph.metadata;
          dxball-authority-diagnostics-v3 = dxball.analysisV3.diagnostics;
          dxball-reconstruction-plan = dxball.analysis.reconstructionPlan;
          dxball-component-proposals = dxball.analysis.componentProposals;
          dxball-interpreter = dxball.hybrid.interpreter;
          dxball-fallback-coverage-receipt =
            dxball.hybrid.fallbackCoverageReceipt;
          dxball-candidate-authority-v3 =
            dxball.hybrid.candidateAuthorityReport;
          dxball-native-engine = dxball.hybrid.nativeEngine;
          dxball-native-runtime = dxball.hybrid.nativeRuntime;
          dxball-native-objects = dxball.hybrid.nativeObjects.package;
          dxball-hybrid-candidate = dxball.hybrid.candidate;
          dxball-diagnostic-native-engine = dxball.hybridDiagnostic.nativeEngine;
          dxball-diagnostic-native-runtime = dxball.hybridDiagnostic.nativeRuntime;
          dxball-hybrid-diagnostic-candidate = dxball.hybridDiagnostic.candidate;
          dxball-headless-diagnostic-run = dxball.diagnosticRun;
          test-shards = catalogSuite.shards;
        });

      packages = forAllSystems (system: {
        default = self.legacyPackages.${system}.default;
        spaghetti-extractor =
          self.legacyPackages.${system}.spaghetti-extractor;
        testkit-test-runner =
          self.legacyPackages.${system}.testkit-test-runner;
        testkit-developer =
          self.legacyPackages.${system}.testkit-developer;
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
          isaClassifierPythonClosure = import ./nix/python-module-closure.nix {
            inherit pkgs;
            source = testSource;
            modules = [ "spaghetti_extractor.isa_semantic_forms" ];
            name = "spaghetti-extractor-isa-classifier-python-closure-smoke";
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
          test-suite = self.legacyPackages.${system}.test-full;
          python-module-closure = pkgs.runCommand
            "spaghetti-extractor-python-module-closure-check"
            { nativeBuildInputs = [ testPython ]; }
            ''
              export PYTHONPATH=${interpreterPythonClosure}/src
              python -c 'import spaghetti_extractor.stage_b_interpreter_backend'
              test -s ${interpreterPythonClosure}/python-module-closure.json
              export PYTHONPATH=${isaClassifierPythonClosure}/src
              python -c 'from spaghetti_extractor.isa_semantic_forms import lean_semantic_form_classifier_sha256; assert len(lean_semantic_form_classifier_sha256()) == 64'
              test -s ${isaClassifierPythonClosure}/python-module-closure.json
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
          authority-graph-v3 = self.legacyPackages.${system}.authority-graph-v3-check;
          artifact-seed-v3 = self.legacyPackages.${system}.artifact-seed-v3-check;
          analysis-v3-machine-ir-input = self.legacyPackages.${system}.analysis-v3-machine-ir-input-check;
          machine-import-control-profile = machineImportControlProfileFixture;
          isa-kernel = self.legacyPackages.${system}.isa-kernel;
          inductive-certificate-kernel =
            self.legacyPackages.${system}.inductive-certificate-kernel;
          roundtrip = self.legacyPackages.${system}.roundtrip-qualification;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.spaghetti-extractor}/bin/spaghetti-extractor";
          meta.description = "Static PE32 reconstruction and component-lifting toolkit";
        };
        test = {
          type = "app";
          program = "${self.packages.${system}.testkit-test-runner}/bin/spaghetti-extractor-test";
          meta.description = "Nix-first cached smoke, affected, full, target, and benchmark validation";
        };
        dev = {
          type = "app";
          program = "${self.packages.${system}.testkit-developer}/bin/spaghetti-extractor-dev";
          meta.description = "Test scaffolding, fixture discovery, rebuild explanation, and environment diagnosis";
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
