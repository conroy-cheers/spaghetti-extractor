# spaghetti-extractor-python-role: developer
{ ... }:

{
  perSystem = { config, pkgs, ... }:
    let
      context = import ../toolkit-context.nix { inherit pkgs; };
      testSource = pkgs.lib.fileset.toSource {
        root = ../..;
        fileset = pkgs.lib.fileset.unions [
          ../../README.md
          ../../REPOSITORY_MAP.md
          ../../docs
          ../../flake.nix
          ../../flake.lock
          ../../isa-catalogs
          ../../nix
          ../../profiles
          ../../pyproject.toml
          ../../src
          ../../tests
          ../../tools
        ];
      };
      mkTestSuite = mode: import ../test-suite.nix {
        inherit pkgs mode;
        inherit (context) pythonEnv fixtures;
        repositoryRoot = ../..;
      };
      smokeSuite = mkTestSuite "smoke";
      fullSuite = mkTestSuite "full";
      catalogSuite = mkTestSuite "catalog";
      benchmarkSuite = mkTestSuite "benchmark";
      repositoryMetadataFreshness = pkgs.runCommand "spaghetti-extractor-repository-metadata-freshness" {
        nativeBuildInputs = [ context.packages.testkitDeveloper ];
        preferLocalBuild = true;
        allowSubstitutes = true;
        __contentAddressed = true;
      } ''
        spaghetti-extractor-dev --repository ${testSource} refresh --check
        touch "$out"
      '';
      productionPythonLint = pkgs.runCommand "spaghetti-extractor-production-python-lint" {
        nativeBuildInputs = [ pkgs.ruff ];
        preferLocalBuild = true;
        allowSubstitutes = true;
        __contentAddressed = true;
      } ''
        ruff check --select F401,F811,F821 \
          ${testSource}/src/spaghetti_extractor/candidate \
          ${testSource}/src/spaghetti_extractor/static_program \
          ${testSource}/src/spaghetti_extractor/extraction \
          ${testSource}/src/spaghetti_extractor/target_bundles \
          ${testSource}/src/spaghetti_extractor/commands \
          ${testSource}/src/spaghetti_extractor/artifacts/formats.py
        touch "$out"
      '';
      architectureBoundaryCheck = pkgs.runCommand
        "spaghetti-extractor-retired-architecture-boundary" { } ''
          set -euo pipefail
          test ! -e ${testSource}/src/spaghetti_extractor/reference_contract
          test ! -e ${testSource}/src/spaghetti_extractor/candidate/modes.py
          test ! -e ${testSource}/src/spaghetti_extractor/candidate/machine_ir_scope.py
          test ! -e ${testSource}/nix/structural-diagnostics.nix
          test ! -e ${testSource}/nix/stage-b-functional-suite.nix
          test ! -e ${testSource}/nix/stage-b-upstream-shell-suite.nix
          if grep -R -n -E \
            'spaghetti_extractor\.reference_contract|candidate_mode|allow_deferred_potential_transfers|stage-b-run-functional-suite' \
            ${testSource}/src ${testSource}/nix \
            --exclude='checks.nix' \
            --exclude='python-module-index.json' \
            --exclude='test-suite-manifest.json'; then
            echo "retired binary-pair or diagnostic-candidate API reintroduced" >&2
            exit 1
          fi
          touch "$out"
        '';
      roundtrip = import ../stage-a-roundtrip-corpus.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        source = context.sources.staticSource;
        count = 6;
      };
      authorityGraphV3Check = import ../../tests/unit/nix_v3/check.nix {
        inherit pkgs;
      };
      artifactSeedV3Check = import ../tests/artifact-seed-v3.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.staticSource;
      };
      authorityMachineIrInputCheck = import ../tests/authority-machine-ir-input.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.staticSource;
      };
      candidateTestSuiteCheck = import ../tests/candidate-test-suite.nix {
        inherit pkgs;
      };
      profileRegistryCheck = import ../profile-registry-check.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.staticSource;
        profiles = context.sources.profileSource;
      };
      fullGate = pkgs.linkFarm "spaghetti-extractor-test-full" [
        { name = "repository-metadata-freshness"; path = repositoryMetadataFreshness; }
        { name = "production-python-lint"; path = productionPythonLint; }
        { name = "retired-architecture-boundary"; path = architectureBoundaryCheck; }
        { name = "python-suite"; path = fullSuite.aggregate; }
        { name = "authority-machine-ir-input"; path = authorityMachineIrInputCheck; }
        { name = "authority-graph-v3"; path = authorityGraphV3Check; }
        { name = "artifact-seed-v3"; path = artifactSeedV3Check; }
        { name = "candidate-test-suite"; path = candidateTestSuiteCheck; }
        { name = "profile-registry"; path = profileRegistryCheck; }
        { name = "roundtrip-qualification"; path = roundtrip.qualification; }
      ];
      smokeGate = pkgs.linkFarm "spaghetti-extractor-test-smoke" [
        { name = "repository-metadata-freshness"; path = repositoryMetadataFreshness; }
        { name = "production-python-lint"; path = productionPythonLint; }
        { name = "retired-architecture-boundary"; path = architectureBoundaryCheck; }
        { name = "python-suite"; path = smokeSuite.aggregate; }
      ];
      benchmarkGate = pkgs.linkFarm "spaghetti-extractor-test-benchmark" [
        { name = "repository-metadata-freshness"; path = repositoryMetadataFreshness; }
        { name = "python-suite"; path = benchmarkSuite.aggregate; }
      ];
      interpreterPythonClosure = import ../python-module-closure.nix {
        phaseRole = "developer";
        inherit pkgs;
        modules = [ "spaghetti_extractor.candidate.interpreter" ];
        name = "spaghetti-extractor-interpreter-python-closure-smoke";
      };
      isaClassifierPythonClosure = import ../python-module-closure.nix {
        phaseRole = "developer";
        inherit pkgs;
        modules = [ "spaghetti_extractor.isa.semantic_forms" ];
        name = "spaghetti-extractor-isa-classifier-python-closure-smoke";
      };
      crossRoleClosure = builtins.tryEval (
        (import ../python-module-closure.nix {
          phaseRole = "operator";
          inherit pkgs;
          modules = [ "spaghetti_extractor.candidate.interpreter" ];
          name = "spaghetti-extractor-invalid-cross-role-closure";
        }).drvPath
      );
      machineImportControlProfileFixture = import ../tests/machine-import-control-profile.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      targetSdkCheck = import ../tests/target-sdk.nix { inherit pkgs; };
      componentsCheck = import ../tests/components.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.staticSource;
      };
    in
    {
      legacyPackages = {
        test-smoke = smokeGate;
        test-full = fullGate;
        test-benchmark = benchmarkGate;
        test-shards = catalogSuite.shards;
        authority-graph-v3-check = authorityGraphV3Check;
        artifact-seed-v3-check = artifactSeedV3Check;
        authority-machine-ir-input-check = authorityMachineIrInputCheck;
        roundtrip-corpus = roundtrip.corpus;
        roundtrip-qualification = roundtrip.qualification;
      };

      checks = {
        import-smoke = pkgs.runCommand "spaghetti-extractor-import-smoke" {
          nativeBuildInputs = [ config.packages.spaghetti-extractor ];
        } ''
          spaghetti-extractor --help >/dev/null
          spaghetti-extractor project status --help >/dev/null
          spaghetti-extractor component list --help >/dev/null
          spaghetti-extractor component status --help >/dev/null
          spaghetti-extractor candidate list --help >/dev/null
          spaghetti-extractor candidate status --help >/dev/null
          spaghetti-extractor candidate test --help >/dev/null
          spaghetti-extractor expert stage-a-inventory-binary --help >/dev/null
          touch "$out"
        '';
        test-suite = fullGate;
        repository-metadata = repositoryMetadataFreshness;
        production-python-lint = productionPythonLint;
        retired-architecture-boundary = architectureBoundaryCheck;
        python-module-closure =
          assert !crossRoleClosure.success;
          pkgs.runCommand
          "spaghetti-extractor-python-module-closure-check"
          { nativeBuildInputs = [ context.pythonEnv ]; }
          ''
            export PYTHONPATH=${interpreterPythonClosure}/src
            python -c 'import spaghetti_extractor.candidate.interpreter'
            test -s ${interpreterPythonClosure}/python-module-closure.json
            export PYTHONPATH=${isaClassifierPythonClosure}/src
            python -c 'from spaghetti_extractor.isa.semantic_forms import lean_semantic_form_classifier_sha256; assert len(lean_semantic_form_classifier_sha256()) == 64'
            test -s ${isaClassifierPythonClosure}/python-module-closure.json
            touch "$out"
          '';
        authority-graph-v3 = authorityGraphV3Check;
        artifact-seed-v3 = artifactSeedV3Check;
        authority-machine-ir-input = authorityMachineIrInputCheck;
        machine-import-control-profile = machineImportControlProfileFixture;
        isa-kernel = context.kernels.isaConformanceKernel;
        inductive-certificate-kernel = context.kernels.inductiveCertificateKernel;
        roundtrip = roundtrip.qualification;
        target-sdk = targetSdkCheck;
        components = componentsCheck;
        candidate-test-suite = candidateTestSuiteCheck;
        profile-registry = profileRegistryCheck;
      };
    };
}
