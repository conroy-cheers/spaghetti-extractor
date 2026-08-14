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
      testManifestFreshness = pkgs.runCommand "spaghetti-extractor-test-manifest-freshness" {
        nativeBuildInputs = [ context.pythonEnv ];
        preferLocalBuild = true;
        allowSubstitutes = true;
        __contentAddressed = true;
      } ''
        export PYTHONPATH=${testSource}/src
        python -m spaghetti_extractor.testkit.static_manifest \
          --repository ${testSource} \
          --manifest ${testSource}/nix/test-suite-manifest.json \
          --check
        touch "$out"
      '';
      roundtrip = import ../stage-a-roundtrip-corpus.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        source = context.sources.analysisSource;
        count = 6;
      };
      authorityGraphV3Check = import ../../tests/unit/nix_v3/check.nix {
        inherit pkgs;
      };
      artifactSeedV3Check = import ../tests/artifact-seed-v3.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.analysisSource;
      };
      analysisV3MachineIrInputCheck = import ../tests/analysis-v3-machine-ir-input.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.analysisSource;
      };
      fullGate = pkgs.linkFarm "spaghetti-extractor-test-full" [
        { name = "test-manifest-freshness"; path = testManifestFreshness; }
        { name = "python-suite"; path = fullSuite.aggregate; }
        { name = "analysis-v3-machine-ir-input"; path = analysisV3MachineIrInputCheck; }
        { name = "authority-graph-v3"; path = authorityGraphV3Check; }
        { name = "artifact-seed-v3"; path = artifactSeedV3Check; }
        { name = "roundtrip-qualification"; path = roundtrip.qualification; }
      ];
      smokeGate = pkgs.linkFarm "spaghetti-extractor-test-smoke" [
        { name = "test-manifest-freshness"; path = testManifestFreshness; }
        { name = "python-suite"; path = smokeSuite.aggregate; }
      ];
      benchmarkGate = pkgs.linkFarm "spaghetti-extractor-test-benchmark" [
        { name = "test-manifest-freshness"; path = testManifestFreshness; }
        { name = "python-suite"; path = benchmarkSuite.aggregate; }
      ];
      interpreterPythonClosure = import ../python-module-closure.nix {
        inherit pkgs;
        source = testSource;
        modules = [ "spaghetti_extractor.stage_b_interpreter_backend" ];
        name = "spaghetti-extractor-interpreter-python-closure-smoke";
      };
      isaClassifierPythonClosure = import ../python-module-closure.nix {
        inherit pkgs;
        source = testSource;
        modules = [ "spaghetti_extractor.isa_semantic_forms" ];
        name = "spaghetti-extractor-isa-classifier-python-closure-smoke";
      };
      machineImportControlProfileFixture = import ../tests/machine-import-control-profile.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = testSource;
      };
      targetSdkCheck = import ../tests/target-sdk.nix { inherit pkgs; };
      componentsV3Check = import ../tests/components-v3.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.analysisSource;
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
        analysis-v3-machine-ir-input-check = analysisV3MachineIrInputCheck;
        roundtrip-corpus = roundtrip.corpus;
        roundtrip-qualification = roundtrip.qualification;
      };

      checks = {
        import-smoke = pkgs.runCommand "spaghetti-extractor-import-smoke" {
          nativeBuildInputs = [ config.packages.spaghetti-extractor ];
        } ''
          spaghetti-extractor --help >/dev/null
          spaghetti-extractor stage-a-inventory-binary --help >/dev/null
          spaghetti-extractor stage-b-resolve-components --help >/dev/null
          spaghetti-extractor stage-b-build-component-contract --help >/dev/null
          spaghetti-extractor stage-b-build-component-runtime --help >/dev/null
          touch "$out"
        '';
        test-suite = fullGate;
        test-manifest = testManifestFreshness;
        python-module-closure = pkgs.runCommand
          "spaghetti-extractor-python-module-closure-check"
          { nativeBuildInputs = [ context.pythonEnv ]; }
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
          { nativeBuildInputs = [ context.pythonEnv ]; }
          ''
            python ${testSource}/tools/update-python-module-index.py \
              --repository ${testSource} \
              --out ${testSource}/nix/python-module-index.json \
              --check
            touch "$out"
          '';
        authority-graph-v3 = authorityGraphV3Check;
        artifact-seed-v3 = artifactSeedV3Check;
        analysis-v3-machine-ir-input = analysisV3MachineIrInputCheck;
        machine-import-control-profile = machineImportControlProfileFixture;
        isa-kernel = context.kernels.isaConformanceKernel;
        inductive-certificate-kernel = context.kernels.inductiveCertificateKernel;
        roundtrip = roundtrip.qualification;
        target-sdk = targetSdkCheck;
        components-v3 = componentsV3Check;
      };
    };
}
