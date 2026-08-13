{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource ? null,
  spaghettiExtractor ? null,
  isaKernelCache ? null,
  isaSemanticKernel ? null,
  bochsRunner ? null,
}:

let
  mingw = pkgs.pkgsCross.mingw32;
  aarch64 = pkgs.pkgsCross.aarch64-multiplatform;
  target = builtins.fromJSON (builtins.readFile ./target.json);
  commonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
  originalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${commonCflags}";
  layoutLdflags = pkgs.lib.concatStringsSep " " [
    "-Wl,--section-start=.data=0x420000"
    "-Wl,--section-start=.rdata=0x421000"
    "-Wl,--section-start=.bss=0x430000"
    "-Wl,--section-start=.edata=0x431000"
    "-Wl,--section-start=.idata=0x432000"
    "-Wl,--section-start=.tls=0x433000"
    "-Wl,--section-start=.reloc=0x434000"
  ];
  original = mingw.hello.overrideAttrs (old: {
    pname = "spaghetti-extractor-gnu-hello-original";
    doCheck = false;
    doInstallCheck = false;
    dontStrip = true;
    outputs = [ "out" ];
    env = (old.env or { }) // {
      CFLAGS = originalCflags;
      LDFLAGS = "${layoutLdflags} -Wl,-Map,hello-original.map";
    };
    postFixup = "";
    postInstall = (old.postInstall or "") + ''
      test "$(sha256sum "$out/bin/hello.exe" | cut -d ' ' -f 1)" = \
        ${target.input.expected_sha256}
    '';
    __contentAddressed = true;
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  originalPe = "${original}/bin/hello.exe";
  profileSource = pkgs.lib.fileset.toSource {
    root = ../../profiles;
    fileset = ../../profiles;
  };
  analysis = import ../../nix/stage-b-component-analysis.nix {
    inherit pkgs pythonEnv pythonSource;
    original = originalPe;
    externalProfile =
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json";
    namePrefix = "spaghetti-extractor-gnu-hello-2.12.3";
  };
  analysisV3 = import ../../nix/analysis-v3-authority.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      isaPythonSource
      spaghettiExtractor
      isaKernelCache
      isaSemanticKernel
      bochsRunner
      ;
    name = "spaghetti-extractor-gnu-hello-2.12.3-authority-v3";
    machineIr = "${analysis.machineIr}/machine-ir.jsonl";
    binary = originalPe;
    binaryIdentity = "hello.exe";
    machineImportProfiles = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
    ];
    launchProfileTemplate =
      "${profileSource}/pe32-win32-console-launch-assumptions-v1.json";
  };
  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource;
    target = ./.;
  };
  idiomaticSourceSpecification = builtins.elemAt intent.sourceProjects 0;
  idiomaticSourceEvidencePlan = builtins.elemAt intent.sourceEvidence 0;
  linkedLibraries = import ../../nix/stage-b-linked-libraries.nix {
    inherit pkgs pythonEnv pythonSource;
    original = originalPe;
    machineIr = "${analysis.machineIr}/machine-ir.jsonl";
    namePrefix = "spaghetti-extractor-gnu-hello-2.12.3";
    review = "${intent.linkedIslandReview}/linked-island-review.json";
  };
  runtimeLock = import ../../nix/stage-b-runtime-lock.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3";
    dependencies = [
      {
        kind = "toolchain";
        identity = "nixpkgs-mingw32-stdenv";
        path = mingw.stdenv.cc;
      }
      {
        kind = "toolchain";
        identity = "nixpkgs-aarch64-multiplatform-stdenv";
        path = aarch64.stdenv.cc;
      }
      {
        kind = "external-profile";
        identity = "pe32-msvcrt-machine-runtime-v1";
        path = "${profileSource}/pe32-msvcrt-machine-runtime-v1.json";
      }
      {
        kind = "launch-profile";
        identity = "pe32-win32-console-launch-v1";
        path = "${profileSource}/pe32-win32-console-launch-assumptions-v1.json";
      }
      {
        kind = "reviewed-runtime-imports";
        identity = "gnu-hello-2.12.3-idiomatic-mingw32-v1";
        path = ./intent/runtime-imports.json;
      }
    ];
  };
  idiomatic = import ./idiomatic.nix {
    inherit pkgs pythonEnv pythonSource;
    mingw32 = mingw;
    aarch64Stdenv = aarch64.stdenv;
    machineIr = analysis.machineIr;
    authorityGate = analysisV3.finalAuthorityGate;
    specification = "${idiomaticSourceSpecification}/source-project.json";
    inherit runtimeLock;
    sourceRoot = ./source/idiomatic;
    linkedIslands = "${linkedLibraries.linkedIslands}/linked-islands.json";
  };
  sourceIterationAudit = import ../../nix/stage-b-source-iteration-audit.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    machineIr = analysis.machineIr;
    sourceBinding = idiomatic.sourceBinding;
    sourceEvidencePlan = idiomaticSourceEvidencePlan;
    candidate = idiomatic.candidate;
  };
  sourceLiftAudit = import ../../nix/stage-b-source-lift-audit.nix {
    inherit pkgs pythonEnv pythonSource sourceIterationAudit;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    authorityDiagnostics = analysisV3.diagnostics;
  };
  sourceAst = import ../../nix/stage-b-clang-ast-bundle.nix {
    inherit pkgs;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    source = idiomatic.source;
    sourceFiles = [ "hello.c" "hello.h" ];
    compileSources = [ "hello.c" ];
  };
  sourceCalls = import ../../nix/stage-b-source-call-substitutions.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    sourceBinding =
      "${idiomatic.sourceBinding}/source-project-binding.json";
    linkedIslands =
      "${linkedLibraries.linkedIslands}/linked-islands.json";
    dynamicRequirements =
      "${linkedLibraries.dynamicRequirements}/dynamic-library-requirements.json";
    original = originalPe;
    machineIr = analysis.machineIr;
    clangAst = "${sourceAst}/clang-ast-bundle.json";
    sourceRoot = idiomatic.source;
    candidate = "${idiomatic.candidate}/bin/hello.exe";
    allowedRuntimeImports = ./intent/runtime-imports.json;
    proposeSourceComponents = true;
  };
  sourceComponentAssurance = import ../../nix/stage-b-source-component-assurance.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    binding = idiomatic.sourceBinding;
    sourceInventory = "${sourceCalls.sourceInventory}/source-call-inventory.json";
    sourceCallReport = "${sourceCalls.sourceBindingReport}/source-call-binding-report.json";
    functionalReport = "${idiomatic.functionalSuite}/functional-report.json";
    evidencePlan = "${idiomaticSourceEvidencePlan}/source-component-evidence.json";
  };
  sourceQualification = import ../../nix/stage-b-source-qualification.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    sourceBinding = idiomatic.sourceBinding;
    componentAssurance = sourceComponentAssurance;
    sourceCallReport = sourceCalls.sourceBindingReport;
    candidateDependencyAudit = sourceCalls.candidateAudit;
  };
  runtimeQualification = import ../../nix/stage-b-runtime-qualification.nix {
    inherit pkgs pythonEnv pythonSource runtimeLock;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    linkedIslands = linkedLibraries.linkedIslands;
    candidateDependencyAudit = sourceCalls.candidateAudit;
    componentAssurance = sourceComponentAssurance;
    substitutionPlan = ./intent/runtime-substitution.json;
  };
  candidateValidation = import ../../nix/stage-b-candidate-validation.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3-idiomatic";
    pe32Report = idiomatic.functionalSuite;
    nonX86Report = idiomatic.nativeFunctionalSuite;
  };
  staticImplementationLedger = import ../../nix/stage-b-implementation-ledger.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3";
    machineIr = analysis.machineIr;
    profile = "static-baseline-v1";
    fallbackCoverage =
      analysisV3.graph.phases."fallback-coverage-v3".artifact;
  };
  portableImplementationLedger = import ../../nix/stage-b-implementation-ledger.nix {
    inherit pkgs pythonEnv pythonSource;
    namePrefix = "stage-b-gnu-hello-2.12.3";
    machineIr = analysis.machineIr;
    profile = "validation-qualified-v1";
    sourceBinding = idiomatic.sourceBinding;
    sourceQualification = sourceQualification;
    linkedIslands = linkedLibraries.linkedIslands;
    libraryQualifications = [ runtimeQualification ];
  };
  staticCompletionReceipt = import ../../nix/stage-b-lift-completion-receipt.nix {
    inherit pkgs pythonEnv pythonSource runtimeLock;
    namePrefix = "stage-b-gnu-hello-2.12.3";
    profile = "static-baseline-v1";
    finalAuthority = analysisV3.finalAuthority;
    fallbackCoverage =
      analysisV3.graph.phases."fallback-coverage-v3".artifact;
    implementationLedger = staticImplementationLedger;
    authorityDiagnostics = analysisV3.diagnostics;
  };
  portableCompletionReceipt = import ../../nix/stage-b-lift-completion-receipt.nix {
    inherit pkgs pythonEnv pythonSource runtimeLock;
    namePrefix = "stage-b-gnu-hello-2.12.3";
    profile = "validation-qualified-v1";
    finalAuthority = analysisV3.finalAuthority;
    fallbackCoverage =
      analysisV3.graph.phases."fallback-coverage-v3".artifact;
    implementationLedger = portableImplementationLedger;
    authorityDiagnostics = analysisV3.diagnostics;
    pe32Candidate = idiomatic.candidate;
    nonX86Candidate = idiomatic.nativeCandidate;
    sourceQualifications = [ sourceQualification ];
    libraryQualifications = [ runtimeQualification ];
    validation = candidateValidation;
  };
  liftWorkbench = pkgs.runCommand
    "spaghetti-extractor-gnu-hello-2.12.3-lift-workbench-v1"
    { __contentAddressed = true; } ''
      set -euo pipefail
      mkdir -p "$out"
      ln -s ${analysisV3.finalAuthority} "$out/final-authority-v3"
      ln -s ${analysisV3.diagnostics} "$out/authority-diagnostics-v3"
      ln -s ${analysisV3.generatedExternalSiteEvidence} \
        "$out/external-site-evidence-v3"
      ln -s ${analysisV3.generatedIndexedTargetEvidence} \
        "$out/indexed-target-evidence-v3"
      ln -s ${analysisV3.fallbackInterpreter} "$out/fallback-interpreter-v3"
      ln -s ${analysisV3.fallbackCoverageReceipt} \
        "$out/fallback-coverage-receipt-v3"
      ln -s ${analysisV3.generatedImplementationCapabilities} \
        "$out/implementation-capabilities-v3"
      ln -s ${analysisV3.generatedISAEvidence.frontiers} \
        "$out/isa-frontiers-v1"
      ln -s ${analysis.machineIr} "$out/machine-ir-v2"
      ln -s ${linkedLibraries.linkedIslands} "$out/linked-islands"
      ln -s ${idiomatic.sourceBinding} "$out/source-project-binding"
      ln -s ${sourceAst} "$out/source-ast"
      ln -s ${sourceCalls.sourceBindingReport} "$out/source-call-report"
      ln -s ${sourceCalls.candidateAudit} "$out/candidate-dependency-audit"
      ln -s ${sourceIterationAudit} "$out/source-iteration-audit"
      ln -s ${sourceLiftAudit} "$out/source-lift-audit"
      ln -s ${staticImplementationLedger} "$out/static-implementation-ledger-v2"
      ln -s ${staticCompletionReceipt} "$out/static-completion-receipt-v2"
      ln -s ${runtimeLock} "$out/runtime-lock-v1"
      ln -s ${idiomatic.candidate} "$out/candidate-pe32"
      ln -s ${idiomatic.nativeCandidate} "$out/candidate-aarch64"
      cat > "$out/workbench.json" <<'EOF'
      {
        "format": "spaghetti-extractor-target-lift-workbench-v1",
        "target": "gnu-hello",
        "iteration_entrypoint": "source-iteration-audit/source-iteration-audit.json",
        "authority_entrypoint": "authority-diagnostics-v3/authority-diagnostics-v3.json",
        "acceptance_gate": "gnu-hello-final-authority-v3-gate",
        "release_workflow": "gnu-hello-lift-workflow",
        "runtime_execution_permitted_only_after_authority": true,
        "executes_original_binary": false
      }
      EOF
    '';
  liftWorkflow = pkgs.runCommand
    "spaghetti-extractor-gnu-hello-2.12.3-lift-workflow-v1"
    { __contentAddressed = true; } ''
      set -euo pipefail
      mkdir -p "$out"
      ln -s ${analysisV3.finalAuthority} "$out/final-authority-v3"
      ln -s ${analysisV3.diagnostics} "$out/authority-diagnostics-v3"
      ln -s ${analysisV3.generatedExternalSiteEvidence} \
        "$out/external-site-evidence-v3"
      ln -s ${analysisV3.generatedIndexedTargetEvidence} \
        "$out/indexed-target-evidence-v3"
      ln -s ${analysisV3.fallbackInterpreter} "$out/fallback-interpreter-v3"
      ln -s ${analysisV3.fallbackCoverageReceipt} \
        "$out/fallback-coverage-receipt-v3"
      ln -s ${analysisV3.generatedImplementationCapabilities} \
        "$out/implementation-capabilities-v3"
      ln -s ${analysisV3.generatedISAEvidence.frontiers} \
        "$out/isa-frontiers-v1"
      ln -s ${analysis.machineIr} "$out/machine-ir-v2"
      ln -s ${linkedLibraries.linkedIslands} "$out/linked-islands"
      ln -s ${idiomatic.sourceBinding} "$out/source-project-binding"
      ln -s ${sourceIterationAudit} "$out/source-iteration-audit"
      ln -s ${sourceLiftAudit} "$out/source-lift-audit"
      ln -s ${sourceQualification} "$out/source-qualification-v1"
      ln -s ${portableImplementationLedger} "$out/implementation-ledger-v2"
      ln -s ${runtimeLock} "$out/runtime-lock-v1"
      ln -s ${idiomatic.candidate} "$out/candidate-pe32"
      ln -s ${idiomatic.nativeCandidate} "$out/candidate-aarch64"
      ln -s ${portableCompletionReceipt} "$out/completion-receipt-v2"
      cat > "$out/workflow.json" <<'EOF'
      {
        "format": "spaghetti-extractor-target-lift-workflow-v1",
        "target": "gnu-hello",
        "profile": "validation-qualified-v1",
        "entrypoint": "completion-receipt-v2/lift-completion-report-v2.json",
        "runtime_execution_permitted_only_after_authority": true,
        "executes_original_binary": false
      }
      EOF
    '';
in
{
  inherit original analysis analysisV3 linkedLibraries runtimeLock;
  inherit intent;

  idiomaticSourceProject = idiomatic // {
    specification = idiomaticSourceSpecification;
    evidencePlan = idiomaticSourceEvidencePlan;
  };
  inherit idiomaticSourceSpecification idiomaticSourceEvidencePlan;
  idiomaticSourceBinding = idiomatic.sourceBinding;
  idiomaticCandidate = idiomatic.candidate;
  idiomaticRunner = idiomatic.runner;
  idiomaticFunctionalSuiteSpec = idiomatic.functionalSuiteSpec;
  idiomaticFunctionalSuiteDag = idiomatic.functionalSuiteDag;
  idiomaticFunctionalSuite = idiomatic.functionalSuite;
  idiomaticSourceLiftAudit = sourceLiftAudit;
  inherit sourceIterationAudit;
  inherit sourceQualification;
  inherit sourceAst sourceCalls sourceComponentAssurance runtimeQualification;
  inherit candidateValidation;
  inherit
    staticImplementationLedger
    portableImplementationLedger
    staticCompletionReceipt
    portableCompletionReceipt
    liftWorkbench
    liftWorkflow
    ;
}
