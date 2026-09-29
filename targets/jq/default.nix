{ pkgs, sdk }:

let
  target = builtins.fromJSON (builtins.readFile ./target.json);
  mingw = pkgs.pkgsCross.mingw32;
  oniguruma = mingw.oniguruma.overrideAttrs (old: {
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  commonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
  originalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${commonCflags}";
  unverifiedOriginal = (mingw.jq.override { inherit oniguruma; }).overrideAttrs (old: {
    pname = "spaghetti-extractor-jq-original";
    doCheck = false;
    doInstallCheck = false;
    dontStrip = true;
    outputs = [ "out" ];
    buildInputs = (old.buildInputs or [ ]) ++ [ mingw.windows.pthreads ];
    configureFlags = [
      "--prefix=${builtins.placeholder "out"}"
      "--bindir=${builtins.placeholder "out"}/bin"
      "--sbindir=${builtins.placeholder "out"}/bin"
      "--datadir=${builtins.placeholder "out"}/share"
      "--mandir=${builtins.placeholder "out"}/share/man"
    ];
    CFLAGS = originalCflags;
    LDFLAGS = "-Wl,-Map,jq-original.map";
    postFixup = "";
    postInstall = (old.postInstall or "") + ''
      map_path="$(find . -name 'jq-original.map' -print -quit)"
      if [ -z "$map_path" ]; then
        echo "missing jq-original.map" >&2
        exit 1
      fi
      mkdir -p "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original"
      cp "$map_path" "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original/jq.map"
      cp "$out/bin/jq.exe" "$out/share/spaghetti-extractor/spaghetti-extractor-jq-fixtures/original/jq.exe"
    '';
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  original = unverifiedOriginal;
  originalPe = "${original}/bin/jq.exe";
  concatFixture = ../../tests/fixtures/jq-array-concat;
  valueFixture = ../../tests/fixtures/jq-value-transport;
  valueRepresentation = revision: {
    group = { id = "jq-array-values"; label = "Shared private array values"; members = [ "array-concat" "array-append" ]; };
    inherit revision;
    inputs = { transport = "headers/value-transport.h"; implementation = "headers/value-runtime-impl.h"; };
  };
  valueHeaders = implementation: {
    "value-transport.h" = valueFixture + "/value-transport.h";
    "value-runtime-impl.h" = valueFixture + "/${implementation}-runtime.h";
  };
  concatSource = sdk.lifting.sourcePackage {
    namePrefix = "spaghetti-extractor-jq-practical";
    componentId = "array-concat";
    sourceRoot = concatFixture;
    sourceIntent = {
      files = [ "concat.c" ];
      shared_inputs = [ ];
      operation_symbols.run = "lifted_array_concat";
    };
  };
  concatComparisonArguments = {
    namePrefix = "spaghetti-extractor-jq-practical";
    targetId = "jq";
    componentId = "array-concat";
    interfacePackage = concatFixture + "/component-interface-intent-v1.json";
    sourcePackage = concatSource.package;
    adapterFiles = {
      "driver.c" = concatFixture + "/native-driver.c";
      "value-runtime.c" = valueFixture + "/value-runtime.c";
    };
    representation = valueRepresentation "raw-jv-v1";
    includeFiles."value-transport.h" = valueFixture + "/value-transport.h";
    includeFiles."value-runtime-impl.h" = valueFixture + "/raw-runtime.h";
    includeFiles."jv.h" = "${original}/include/jv.h";
    includeFiles."controlled-append.h" = concatFixture + "/controlled-append.h";
    includeFiles."pe32-entry-hook.h" = ../../tests/fixtures/native/pe32-entry-hook.h;
    includeFiles."comparison-selection.h" = concatFixture + "/real-selection.h";
    linkFiles."libjq.dll.a" = "${original}/lib/libjq.dll.a";
    runtimeFiles = builtins.listToAttrs (map (name: {
      inherit name; value = "${original}/bin/${name}";
    }) [ "libjq-1.dll" "libonig-5.dll" "libgcc_s_sjlj-1.dll" "libmcfgthread-2.dll" "libwinpthread-1.dll" ]);
    originalFiles = [ "runtime/libjq-1.dll" ];
    cases = map (index: { id = toString index; arguments = [ (toString index) ]; }) (pkgs.lib.range 0 5)
      ++ map (index: { id = "controlled-${toString index}"; arguments = [ (toString index) "controlled" ]; }) (pkgs.lib.range 0 5)
      ++ map (mode: { id = mode; arguments = [ "1" mode ]; }) [ "fail-first" "fail-second" ];
    observationFields = [ "input_words" "scenario" "result" "left_after" "right_after" "right_references" "outcome" "dependency_mode" "interactions" ];
    inputDomain = { words = [ "left_length" "right_length" ]; constraints = [
      { argument_index = 0; minimum = 0; maximum = 2147483647; }
      { argument_index = 1; minimum = 0; maximum = 2147483647; }
    ]; };
    assumptions = [ "valid arrays with owned references" "single-threaded fixture; sampled state and lifetime observations"
      "controlled append validates logical arguments and uses real array_set for writes; invalid outcomes are injected contract cases" ];
    scope = "jq/libjq array-concat component network; actual PE32 original oracle";
  };
  concatComparison = sdk.lifting.comparisonPackage concatComparisonArguments;
  appendFixture = ../../tests/fixtures/jq-array-append;
  appendSource = sdk.lifting.sourcePackage {
    namePrefix = "spaghetti-extractor-jq-practical";
    componentId = "array-append";
    sourceRoot = appendFixture;
    sourceIntent = { files = [ "append.c" ]; shared_inputs = [ ]; operation_symbols.run = "lifted_array_append"; };
  };
  appendComparisonArguments = {
    namePrefix = "spaghetti-extractor-jq-practical";
    targetId = "jq";
    componentId = "array-append";
    interfacePackage = appendFixture + "/component-interface-intent-v1.json";
    sourcePackage = appendSource.package;
    adapterFiles = { "driver.c" = appendFixture + "/native-driver.c"; "bridge.c" = appendFixture + "/native-bridge.c";
      "value-runtime.c" = valueFixture + "/value-runtime.c"; };
    representation = valueRepresentation "raw-jv-v1";
    includeFiles."value-transport.h" = valueFixture + "/value-transport.h";
    includeFiles."value-runtime-impl.h" = valueFixture + "/raw-runtime.h";
    includeFiles."jv.h" = "${original}/include/jv.h";
    inherit (concatComparisonArguments) linkFiles runtimeFiles originalFiles;
    cases = map (index: { id = toString index; arguments = [ (toString index) ]; }) (pkgs.lib.range 0 4);
    observationFields = [ "input_words" "scenario" "result" "value_after" "item_after" ];
    inputDomain = { words = [ "array_length" ]; constraints = [
      { argument_index = 0; minimum = 0; maximum = 2147483646; }
    ]; };
    assumptions = [ "valid owned array and item; array length below INT_MAX" "single-threaded fixture; retained aliases preserve logical contents" ];
    scope = "jq/libjq array-append; actual PE32 original oracle and generated component ABI";
  };
  appendComparison = sdk.lifting.comparisonPackage appendComparisonArguments;
  concatIsolated = sdk.lifting.comparisonPackage (concatComparisonArguments // {
    namePrefix = "spaghetti-extractor-jq-practical-isolated";
    cases = builtins.filter (row: builtins.length row.arguments == 2) concatComparisonArguments.cases;
    scope = "jq array-concat isolated from authored append; original append entry intercepted for every case";
  });
  concatIntegrated = sdk.lifting.comparisonPackage (concatComparisonArguments // {
    namePrefix = "spaghetti-extractor-jq-practical-integrated";
    includeFiles = concatComparisonArguments.includeFiles // {
      "comparison-selection.h" = concatFixture + "/supplier-selection.h";
    };
    dependencies.array-append = {
      package = appendComparison.derivation;
      adapterFiles."bridge.c" = appendFixture + "/native-bridge.c";
    };
    cases = map (index: { id = toString index; arguments = [ (toString index) "supplier" ]; }) (pkgs.lib.range 0 5);
    scope = "jq array-concat with selected authored array-append; original side uses real original append";
  });
  appendHandles = sdk.lifting.comparisonPackage (appendComparisonArguments // {
    namePrefix = "spaghetti-extractor-jq-handles";
    representation = valueRepresentation "owned-handles-v1";
    includeFiles = appendComparisonArguments.includeFiles // valueHeaders "handle";
  });
  concatHandles = sdk.lifting.comparisonPackage (concatComparisonArguments // {
    namePrefix = "spaghetti-extractor-jq-handles";
    representation = valueRepresentation "owned-handles-v1";
    includeFiles = concatComparisonArguments.includeFiles // valueHeaders "handle" // {
      "comparison-selection.h" = concatFixture + "/supplier-selection.h";
    };
    dependencies.array-append = {
      package = appendHandles.derivation;
      adapterFiles."bridge.c" = appendFixture + "/native-bridge.c";
    };
    cases = map (index: { id = toString index; arguments = [ (toString index) "supplier" ]; }) (pkgs.lib.range 0 5);
    scope = "jq concat/append replacement group using bounded owned handles; native original oracle and logical observations";
  });
  profileSource = sdk.profiles;
  libjqPublicAbiProfile = sdk.analysis.headerMachineAbiProfile {
    id = "jq-libjq-public-abi-v1";
    providerDll = "libjq-1.dll";
    headers = [
      { include = "jq.h"; path = "${original}/include/jq.h"; }
      { include = "jv.h"; path = "${original}/include/jv.h"; }
    ];
    functionPrefixes = [ "jq_" "jv_" ];
  };
  libjqPublicAbiProfilePath =
    "${libjqPublicAbiProfile}/machine-import-profile.json";
  libjqOutputCallthroughProfile = sdk.environment.nativeCallthroughProfile {
    abiProfile = libjqPublicAbiProfilePath;
    effectProfile = ./intent/libjq-output-native-effects.json;
    name = "spaghetti-extractor-jq-libjq-output-native-profile";
  };
  libjqOutputCallthroughProfilePath =
    "${libjqOutputCallthroughProfile}/machine-import-profile.json";
  boundaries = sdk.lifting.boundarySchema {
    name = "spaghetti-extractor-jq-1.8.1";
    spec = ./intent/boundaries.json;
    sources = [ ./source/output-value-boundary.c ];
  };
  environment = sdk.environment.pe32 {
    id = "jq-win32";
    profilePacks = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
      "${profileSource}/pe32-oniguruma-runtime-v1.json"
      libjqOutputCallthroughProfilePath
    ];
    interfacePacks = [ ];
    launchProfile =
      "${profileSource}/pe32-win32-console-launch-assumptions-v1.json";
    boundaryIntents."service:output-value-boundary" =
      ./intent/boundaries.json;
    support.processTermination = null;
  };
  rootWorkflowArgs = {
    targetId = target.id;
    original = originalPe;
    externalEnvironment = environment;
    lifting = {
      boundaries = [ {
        subject = "service:output-value-boundary";
        package = boundaries;
      } ];
      components = {
        intent = ./intent/components.json;
        operatorRoot = ./intent;
        sourceRoot = ./source;
      };
      libraries = {
        packs = [ ];
        adoptionRoot = ./intent/libraries;
      };
    };
    backend = {
      kind = "behavioral-c";
      sourcePresentation = null;
    };
    analysisLimits = {
      maxUnits = 512;
      maxCandidatesPerSeed = 12;
    };
  };
  libjqEnvironment = sdk.environment.pe32 {
    id = "jq-libjq-win32";
    profilePacks = [
      "${profileSource}/pe32-msvcrt-machine-runtime-v1.json"
      "${profileSource}/pe32-oniguruma-runtime-v1.json"
      libjqPublicAbiProfilePath
    ];
    interfacePacks = [ ];
    launchProfile =
      "${profileSource}/pe32-win32-console-launch-assumptions-v1.json";
    boundaryIntents = { };
    support.processTermination = null;
  };
  project = sdk.workflow.pe32Project {
    projectId = "jq";
    rootImageId = "jq";
    targetDistributionRoots = [ "bin" ];
    hostEnvironment = {
      id = "jq-win32-host-v1";
      sha256 = builtins.hashString "sha256" "jq-win32-host-v1";
    };
    images = {
      jq = {
        filename = "jq.exe";
        aliases = [ ];
        ownership = "target";
        implementation = "behavioral_c";
        configuration_id = target.workflow.default_configuration;
        workflowArgs = rootWorkflowArgs;
      };
      libjq = {
        filename = "libjq-1.dll";
        aliases = [ ];
        ownership = "target";
        implementation = "behavioral_c";
        configuration_id = "faithful";
        workflowArgs = {
          targetId = "jq-libjq";
          original = "${original}/bin/libjq-1.dll";
          externalEnvironment = libjqEnvironment;
          lifting = {
            boundaries = [ ];
            components = null;
            libraries = {
              packs = [ ];
              adoptionRoot = null;
            };
          };
          backend = {
            kind = "behavioral-c";
            sourcePresentation = null;
          };
          analysisLimits = {
            maxUnits = 512;
            maxCandidatesPerSeed = 12;
          };
        };
      };
      kernel32 = {
        filename = "kernel32.dll";
        aliases = [ "kernelbase.dll" ];
        ownership = "runtime";
        implementation = "native_host";
      };
      msvcrt = {
        filename = "msvcrt.dll";
        aliases = [ ];
        ownership = "runtime";
        implementation = "native_host";
      };
      oniguruma = {
        filename = "libonig-5.dll";
        aliases = [ ];
        ownership = "runtime";
        implementation = "native_host";
      };
      winpthread = {
        filename = "libwinpthread-1.dll";
        aliases = [ ];
        ownership = "runtime";
        implementation = "native_host";
      };
      libgcc = {
        filename = "libgcc_s_sjlj-1.dll";
        aliases = [ ];
        ownership = "runtime";
        implementation = "native_host";
      };
      shlwapi = {
        filename = "shlwapi.dll";
        aliases = [ ];
        ownership = "runtime";
        implementation = "native_host";
      };
    };
  };
  workflow = project.root;
  components = workflow.components;
  outputValuePipelineProvider =
    workflow.portableSemanticProvidersByComponent.output-value-pipeline;
  outputValuePipelineProviderSet =
    workflow.portableSemanticProviderSets.output-value-pipeline-enabled;
  outputValuePipelineSelection =
    workflow.semanticImplementationSelections.output-value-pipeline-enabled;
  outputValuePipelineProofGate =
    pkgs.runCommand "jq-output-value-pipeline-contextual-bisimulation-v6"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        provider=${outputValuePipelineProvider.derivation}
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_portable_c" and
          ([.facets[] | select(.name == "bisimulation") | .status] == ["checked"]) and
          .blockers == []
        ' "$provider/semantic-provider-qualification.json" >/dev/null
        jq -L ${sdk.validation.jqModules} -e '
          include "strong-contextual-proof";
          .status == "satisfied" and
          .proof.status == "satisfied" and
          .proof.activation_authorized == true and
          spx_strong_contextual_proof and
          ([.proof.shards[].nonvacuity.status] | all(. == "satisfied")) and
          (.proof.shards | length) == 1 and
          .proof.checker.model_bounds.maximum_exact_stack_cached_accesses == 14 and
          .proof.checker.model_bounds.maximum_exact_stack_cached_bytes == 56
        ' "$provider/contextual-refinement-result.json" >/dev/null
        jq -L ${sdk.validation.jqModules} -e '
          include "strong-contextual-proof";
          spx_strong_cutpoint_plan
        ' "$provider/component-proof-plan-v1.json" >/dev/null
        jq -L ${sdk.validation.jqModules} -e '
          include "strong-contextual-proof";
          spx_contextual_exact_c_slice
        ' "$provider/exact-c/component-exact-c-slice-v1.json" >/dev/null
        touch "$out"
      '';
  outputValuePipelineLinkageBoundaryGate =
    assert outputValuePipelineProviderSet.directIds == [ "output-value-pipeline" ];
    pkgs.runCommand "jq-output-value-pipeline-native-linkage-boundary-v6"
      { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; }
      ''
        set -euo pipefail
        provider=${outputValuePipelineProvider.derivation}
        selection=${outputValuePipelineSelection.artifact}
        linked=${workflow.linkedSemanticModule.linkedSemanticModule}
        provider_sha256="$(jq -r '.qualification_sha256' \
          "$provider/semantic-provider-qualification.json")"
        linked_sha256="$(jq -r '.linked_semantic_module_sha256' "$linked")"

        # The component is qualified and selected, but jq's whole linked
        # semantic module is not complete.  The selection receipt must remain
        # the fail-closed endpoint: native realization cannot start until the
        # linked-module blockers below are discharged.
        jq -e \
          --arg provider_sha256 "$provider_sha256" \
          --arg linked_sha256 "$linked_sha256" '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "incomplete" and
          .ready_for_realization == false and
          .mode == "hybrid" and
          .bindings.linked_semantic_module_sha256 == $linked_sha256 and
          ([.qualification_sha256s[] | select(. == $provider_sha256)] |
            length) == 1 and
          ([.definition_selections[] | select(
            .provider_id == "jq.output-value-pipeline.portable-c" and
            .provider_kind == "qualified_portable_c" and
            .qualification_sha256 == $provider_sha256
          )] | length) == 7 and
          ([.blockers[] | select(
            .code == "linked_semantic_module_incomplete"
          )] | length) == 1
        ' "$selection" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-linked-semantic-module-v2" and
          .status == "incomplete" and
          .authority == false and
          .counts.semantic_holes > 0 and
          ([.semantic_holes[].code] | index(
            "resolved_external_environment_incomplete"
          )) != null
        ' "$linked" >/dev/null
        mkdir -p "$out"
        cp "$selection" "$out/implementation-selection.json"
        cp "$linked" "$out/linked-semantic-module.json"
      '';
  componentMigrationStatus = pkgs.writeTextFile {
    name = "jq-component-v6-migration-status";
    destination = "/component-v6-migration-status.json";
    text = builtins.readFile ./intent/interfaces-v5/index.json;
  };
  v6ComponentChecks = builtins.listToAttrs (pkgs.lib.concatMap
    (componentId: [
      {
        name = "${componentId}-interface-v5";
        value = components.v5Interfaces.${componentId}.derivation;
      }
      {
        name = "${componentId}-semantic-slice-v2";
        value = components.v6SemanticSlices.${componentId}.derivation;
      }
      {
        name = "${componentId}-work-package-v6";
        value = components.v6WorkPackages.${componentId}.derivation;
      }
    ]) (builtins.attrNames components.v6SemanticSlices));
  authoredComponentChecks = {
    output-value-pipeline-v6-work-package =
      components.v6WorkPackages.output-value-pipeline.derivation;
    math-error-callback-dispatch-v6-work-package =
      components.v6WorkPackages.math-error-callback-dispatch.derivation;
  };
  authoredComponentBlockerGate = pkgs.runCommand
    "jq-authored-component-v6-honest-blockers"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; }
    ''
      check_blockers() {
        package="$1/component-work-package-v6.json"
        component="$2"
        jq -e --arg component "$component" '
          .format == "spaghetti-extractor-component-work-package-v6" and
          .authority == false and
          .status == "ready" and
          ([.blockers[].code] | sort) == [
            "machine_effect_service_callback_outcome_projection_unreviewed",
            "portable_interface_semantics_unreviewed"
          ] and
          ([.blockers[] | .component_id] | unique) == [$component] and
          ([.blockers[] | .source] | unique) == ["component_binding_intent"]
        ' "$package" >/dev/null
      }
      check_blockers \
        ${components.v6WorkPackages.math-error-callback-dispatch.derivation} \
        math-error-callback-dispatch
      touch "$out"
    '';
  semanticMigrationGate = pkgs.runCommand
    "jq-semantic-module-v2-migration-checkpoint"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; }
    ''
      jq -e '
        .status == "incomplete" and
        .authority == "none" and
        ([.blockers[].category] | unique) == [
          "reachable_import_contract_unresolved"
        ] and
        ([.blockers[].identity.symbol] | sort) == [
          "jq_realpath",
          "jq_testsuite",
          "jv_tsd_dtoa_ctx_init"
        ]
      ' ${workflow.resolvedEnvironment.derivation}/resolved-external-environment.json >/dev/null

      jq -e '
        .status == "incomplete" and
        .counts.roots == 14 and
        .counts.direct_control_edges == 5709 and
        .counts.active_relocations == 7026 and
        .counts.residual_obligations == 89 and
        .counts.semantic_holes == 21 and
        ([.semantic_holes | group_by(.code)[] | {
          code: .[0].code,
          count: length
        }]) == [
          {"code":"checked_import_code_contract_unresolved","count":9},
          {"code":"linked_import_code_protocol_missing","count":3},
          {"code":"may_reachable_symbol_has_no_provider","count":6},
          {"code":"resolved_external_environment_incomplete","count":3}
        ]
      ' ${workflow.linkedSemanticModule.linkedSemanticModule} >/dev/null

      jq -e '
        .status == "incomplete" and
        .counts.roots == 197 and
        .counts.direct_control_edges == 46084 and
        .counts.active_relocations == 51809 and
        .counts.residual_obligations == 412 and
        .counts.semantic_holes == 603
      ' ${project.linkedSemanticModules.libjq} >/dev/null

      jq -e '
        .status == "incomplete" and
        .counts.target_images == 2 and
        .counts.target_edges == 47 and
        .counts.host_edges == 204 and
        .counts.blockers == 5 and
        ([.blockers[] | select(
          .category == "target_resolved_environment_incomplete"
        ) | .image_id] | sort) == ["jq", "libjq"] and
        ([.blockers[] | select(
          .category == "cross_image_edge_authority_missing"
        ) | .slot_id] | sort) == [
          "jq:iat:00012270",
          "jq:iat:00012290",
          "jq:iat:0001230c"
        ]
      ' ${project.loadPlan}/project-load-plan.json >/dev/null
      touch "$out"
    '';
  candidateTests = {
    "jq-1.8.1-idiomatic-candidate-functional" = workflow.candidateTestFor {
      id = "jq-1.8.1-idiomatic-candidate-functional";
      configurationId = target.workflow.default_configuration;
      suite = ./tests/candidate-suite.json;
      timeoutSeconds = 90;
    };
  };
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow project candidateTests;
  inputs.original = original;
  targetAssets.documentation = [ "intent/libraries/README.md" ];
  targetAssets.boundary_schema = [ "intent/boundaries.json" ];
  targetAssets.boundary_source = [ "source/output-value-boundary.c" ];
  extraArtifacts.boundaries = boundaries;
  extraArtifacts.array-concat-comparison-package = concatComparison.derivation;
  extraArtifacts.array-append-comparison-package = appendComparison.derivation;
  extraArtifacts.array-append-handles-comparison-package = appendHandles.derivation;
  extraArtifacts.array-concat-handles-comparison-package = concatHandles.derivation;
  extraArtifacts.array-concat-isolated-comparison-package = concatIsolated.derivation;
  extraArtifacts.array-concat-integrated-comparison-package = concatIntegrated.derivation;
  extraArtifacts.output-value-pipeline-v6-provider =
    outputValuePipelineProvider.derivation;
  extraArtifacts.output-value-pipeline-contextual-bisimulation-v6 =
    outputValuePipelineProofGate;
  extraArtifacts.output-value-pipeline-native-linkage-boundary-v6 =
    outputValuePipelineLinkageBoundaryGate;
  checks = v6ComponentChecks // authoredComponentChecks // {
    component-v6-migration-status = componentMigrationStatus;
    authored-component-v6-honest-blockers = authoredComponentBlockerGate;
    output-value-pipeline-contextual-bisimulation-v6 =
      outputValuePipelineProofGate;
    output-value-pipeline-native-linkage-boundary-v6 =
      outputValuePipelineLinkageBoundaryGate;
    semantic-module-v2-migration-checkpoint = semanticMigrationGate;
    canonical-boundaries = boundaries;
  };
}
