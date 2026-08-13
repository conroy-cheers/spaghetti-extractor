{
  description = "Spaghetti Extractor static PE32 reconstruction and source-lifting toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      imports = [
        ./nix/flake-modules/toolkit.nix
        ./nix/flake-modules/checks.nix
      ];

      flake.lib = {
        mkTargetSdkV1 = import ./nix/target-sdk-v1.nix;
        unstable = {
          mkPythonModuleClosure = import ./nix/python-module-closure.nix;
          mkISAQualificationGraph = import ./nix/stage-a-isa-qualification-graph.nix;
          mkMachineIRISAQualificationV2 =
            import ./nix/stage-a-machine-ir-isa-qualification-v2.nix;
          mkISASemanticKernel = import ./nix/stage-a-isa-semantic-kernel.nix;
          mkISAConformanceKernel = import ./nix/stage-a-isa-conformance-kernel.nix;
          mkInductiveCertificateKernel =
            import ./nix/stage-a-inductive-certificate-kernel.nix;
          mkRoundtripCorpus = import ./nix/stage-a-roundtrip-corpus.nix;
          mkExternalInterfaceProfile =
            import ./nix/stage-a-external-interface-profile.nix;
          mkComponentAnalysis = import ./nix/stage-b-component-analysis.nix;
          mkComponentDiscovery = import ./nix/stage-b-component-discovery.nix;
          mkComponentInterfaces = import ./nix/stage-b-component-interfaces.nix;
          mkComponentSelection = import ./nix/stage-b-component-selection.nix;
          mkLinkedLibraryAnalysis = import ./nix/stage-b-linked-libraries.nix;
          mkSourceCallSubstitutions =
            import ./nix/stage-b-source-call-substitutions.nix;
          mkSourceProject = import ./nix/stage-b-source-project.nix;
          mkSourceIterationAudit = import ./nix/stage-b-source-iteration-audit.nix;
          mkSourceLiftAudit = import ./nix/stage-b-source-lift-audit.nix;
          mkSourceQualification = import ./nix/stage-b-source-qualification.nix;
          mkLiftCompletionReceipt =
            import ./nix/stage-b-lift-completion-receipt.nix;
          mkSourceComponentAssurance =
            import ./nix/stage-b-source-component-assurance.nix;
          mkFunctionalSuite = import ./nix/stage-b-functional-suite.nix;
          mkUpstreamShellSuite = import ./nix/stage-b-upstream-shell-suite.nix;
          mkCAJsonPhase = import ./nix/ca-python-json-phase.nix;
          mkArtifactSetV3 = import ./nix/artifact-set-v3.nix;
          mkArtifactSeedV3 = import ./nix/artifact-seed-v3.nix;
          mkArtifactPhaseV3 = import ./nix/artifact-phase-v3.nix;
          mkAnalysisSourcePlanV3 = import ./nix/analysis-v3-source-plan.nix;
          mkAnalysisMachineIRInputV3 = import ./nix/analysis-v3-machine-ir-input.nix;
          mkAnalysisAuthorityV3 = import ./nix/analysis-v3-authority.nix;
          mkAnalysisAuthorityDiagnosticsV3 = import ./nix/analysis-v3-diagnostics.nix;
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
          mkHeadlessDiagnosticRun =
            import ./nix/stage-b-headless-diagnostic-run.nix;
        };
      };
    };
}
