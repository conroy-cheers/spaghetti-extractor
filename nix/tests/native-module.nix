# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  pythonEnv = context.pythonEnv;
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
  fixturePhase = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-native-module-fixture";
    kind = "native-module-fixture";
    artifactName = "executable-transfer-plan.json";
    expectedFormat = "spaghetti-extractor-executable-transfer-plan-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.pe32.behavioral_roots"
      "spaghetti_extractor.testkit.native_module_fixture"
    ];
    phaseRole = "developer";
    # This phase emits exact PE32 inputs beside its JSON artifact.  Nix's
    # generic fixup/strip pass must not rewrite bytes after their interfaces,
    # transfer plan, and ISA occurrence inventory have been content-bound.
    dontFixup = true;
    # Floating CA output finalization can rewrite an output-path reference in
    # PE/COFF auxiliary material after the producer has hashed the module.
    # Keep this binary-producing fixture input-addressed; every semantic phase
    # above it remains content-addressed over the resulting exact bytes.
    contentAddressed = false;
    extraNativeBuildInputs = [ compiler ];
    inputs = {
      inherit compiler;
      original_source = ./fixtures/native-module/original.c;
      original_exports = ./fixtures/native-module/original.def;
      host_source = ./fixtures/native-module/host.c;
      interface_provider_source =
        ./fixtures/native-module/interface-provider.c;
      interface_provider_exports =
        ./fixtures/native-module/interface-provider.def;
      interface_profile = ./fixtures/native-module/interface-profile.json;
    };
    program = ''
      import json
      import shutil
      import subprocess

      import pefile

      from spaghetti_extractor.pe32.behavioral_roots import (
          generate_behavioral_roots,
      )
      from spaghetti_extractor.testkit.native_module_fixture import (
          set_pe32_tls_zero_fill,
          write_native_module_fixture,
      )
      from spaghetti_extractor.util import write_json

      root = output.parent
      original_source = root / "original.c"
      original_exports = root / "original.def"
      host_source = root / "host.c"
      interface_provider_source = root / "interface-provider.c"
      interface_provider_exports = root / "interface-provider.def"
      interface_profile = root / "interface-profile.json"
      shutil.copyfile(inputs["original_source"], original_source)
      shutil.copyfile(inputs["original_exports"], original_exports)
      shutil.copyfile(inputs["host_source"], host_source)
      shutil.copyfile(
          inputs["interface_provider_source"], interface_provider_source
      )
      shutil.copyfile(
          inputs["interface_provider_exports"], interface_provider_exports
      )
      shutil.copyfile(inputs["interface_profile"], interface_profile)
      interface_provider = root / "fixture-provider.dll"
      interface_import_library = root / "libfixture-provider.dll.a"
      subprocess.run([
          str(inputs["compiler"] / "bin/i686-w64-mingw32-gcc"),
          "-shared", "-nostdlib",
          str(interface_provider_source), str(interface_provider_exports),
          "-Wl,--entry,_DllMain@12",
          "-Wl,--image-base,0x69000000",
          "-Wl,--disable-dynamicbase",
          "-Wl,--kill-at",
          "-o", str(interface_provider),
      ], check=True)
      subprocess.run([
          str(inputs["compiler"] / "bin/i686-w64-mingw32-dlltool"),
          "-d", str(interface_provider_exports),
          "-D", "fixture-provider.dll",
          "-l", str(interface_import_library),
          "-k",
      ], check=True)
      original_pe = root / "fixture.dll"
      subprocess.run([
          str(inputs["compiler"] / "bin/i686-w64-mingw32-gcc"),
          "-shared",
          "-nostdlib",
          str(original_source), str(original_exports),
          str(interface_import_library),
          "-Wl,--entry,_DllMain@12",
          "-Wl,--image-base,0x68000000",
          "-Wl,--disable-dynamicbase",
          "-lkernel32",
          "-o", str(original_pe),
      ], check=True)
      set_pe32_tls_zero_fill(original_pe, 16)
      write_json(
          root / "behavioral-roots.json",
          generate_behavioral_roots(original_pe),
      )
      symbol_rows = subprocess.run([
          str(inputs["compiler"] / "bin/i686-w64-mingw32-nm"),
          "-n", str(original_pe),
      ], check=True, capture_output=True, text=True).stdout.splitlines()
      def exact_symbol_rva(symbol):
          matches = [
              row.split() for row in symbol_rows
              if row.split() and row.split()[-1] == symbol
          ]
          if len(matches) != 1:
              raise SystemExit(f"DLL fixture symbol {symbol!r} is not exact")
          return int(matches[0][0], 16)
      parsed_original = pefile.PE(str(original_pe), fast_load=True)
      try:
          original_image_base = int(parsed_original.OPTIONAL_HEADER.ImageBase)
          callback_target_rva = (
              exact_symbol_rva("_fixture_callback_target@4")
              - original_image_base
          )
          exception_handler_rva = (
              exact_symbol_rva("_fixture_guest_exception_handler")
              - original_image_base
          )
          exception_resumption_rva = (
              exact_symbol_rva("_fixture_guest_exception_resumption")
              - original_image_base
          )
          exception_finally_inner_rva = (
              exact_symbol_rva("_fixture_guest_finally_inner")
              - original_image_base
          )
          exception_finally_outer_rva = (
              exact_symbol_rva("_fixture_guest_finally_outer")
              - original_image_base
          )
          nonlocal_callee_rva = (
              exact_symbol_rva("_fixture_nonlocal_callee")
              - original_image_base
          )
          nonlocal_continuation_rva = (
              exact_symbol_rva("_fixture_nonlocal_continuation")
              - original_image_base
          )
          unwind_handler_rva = (
              exact_symbol_rva("_fixture_guest_unwind_handler")
              - original_image_base
          )
          unwind_continuation_rva = (
              exact_symbol_rva("_fixture_unwind_continuation")
              - original_image_base
          )
      finally:
          parsed_original.close()
      artifacts = write_native_module_fixture(
          root,
          original_pe=original_pe,
          interface_profile=interface_profile,
          include_export_ingress=True,
          callback_target_rva=callback_target_rva,
          exception_handler_rva=exception_handler_rva,
          exception_resumption_rva=exception_resumption_rva,
          exception_finally_inner_rva=exception_finally_inner_rva,
          exception_finally_outer_rva=exception_finally_outer_rva,
          nonlocal_callee_rva=nonlocal_callee_rva,
          nonlocal_continuation_rva=nonlocal_continuation_rva,
          unwind_handler_rva=unwind_handler_rva,
          unwind_continuation_rva=unwind_continuation_rva,
          pin_numeric_exception_addresses=True,
      )
      original_interface = json.loads(
          (root / "interface/module-interface.json").read_text(
              encoding="utf-8"
          )
      )
      expected_host_tls_order = 0
      for tls_index, _callback in enumerate(original_interface["tls"]["callbacks"]):
          expected_host_tls_order = (
              expected_host_tls_order * 33 + tls_index + 1
          ) & 0xffffffff
      subprocess.run([
          str(inputs["compiler"] / "bin/i686-w64-mingw32-gcc"),
          f"-DEXPECTED_TLS_ORDER=0x{expected_host_tls_order:08x}U",
          str(host_source), "-o", str(root / "host.exe"),
      ], check=True)
      transfer_payload = json.loads(
          artifacts["transfer"].read_text(encoding="utf-8")
      )
      output.write_bytes(artifacts["transfer"].read_bytes())
    '';
  };
  fixture = fixturePhase.derivation;
  fixtureIsaRequirements = import ../semantic-isa-requirements.nix {
    inherit pkgs;
    pythonEnv = context.pythonEnv;
    kernelCache = context.kernels.isaConformanceKernel;
    binary = "${fixture}/fixture.dll";
    machineIr = "${fixture}/machine-ir.jsonl";
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  fixtureSemanticObject = import ../semantic-object.nix {
    inherit pkgs pythonEnv;
    transferPlan = "${fixture}/machine-ir-transfer/executable-transfer-plan.json";
    moduleInterface = "${fixture}/interface/module-interface.json";
    resolvedExternalEnvironment = "${fixture}/environment";
    isaRequirements = fixtureIsaRequirements.artifact;
    qualifiedPlatform = context.platforms.qualifiedPlatform.qualifiedPlatform;
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  fixtureLinkedSemanticModule = import ../linked-semantic-module.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    semanticObject = fixtureSemanticObject.artifact;
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  generatedBehavioralProviderV2 = import ../generated-behavioral-c-provider-v2.nix {
    inherit pkgs compiler;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    behavioralCPackage = "${fixture}/behavioral";
    providerId = "fixture.generated-c-v2";
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  externalEnvironmentProviderV2 = import ../external-environment-provider-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    providerId = "fixture.external-environment-v2";
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  qualifiedRuntimeProviderV2 = import ../qualified-runtime-provider-v2.nix {
    inherit pkgs compiler;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    behavioralCPackage = "${fixture}/behavioral";
    providerId = "fixture.runtime-v2";
    pinnedLayoutAuthorities = [
      "${fixture}/pinned-layout/pinned-code-layout-authority-v2-0000.json"
    ];
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  interfaceStalePackage = import ../component-v5-interface-package.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    namePrefix = "spaghetti-extractor-native-module-fixture";
    componentId = "fixture-interface-stale";
    intent = ./fixtures/native-module/interface-stale-component.json;
  };
  interfaceStaleSemanticSlice = import ../component-semantic-slice-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    namePrefix = "spaghetti-extractor-native-module-fixture";
    componentId = "fixture-interface-stale";
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    bindingIntent = ./fixtures/native-module/interface-stale-binding.json;
  };
  interfaceStaleSourcePackage = import ../component-source-package-v3.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    namePrefix = "spaghetti-extractor-native-module-fixture";
    componentId = "fixture-interface-stale";
    sourceIntent = {
      files = [ "interface-stale-component.c" ];
      shared_inputs = [ ];
      operation_symbols.exercise = "fixture_interface_stale_exercise";
    };
    sourceRoot = ./fixtures/native-module;
  };
  interfaceStalePortableProviderV2 =
    import ../portable-c-work-package-provider-v2.nix {
      inherit pkgs compiler;
      pythonEnv = context.transferPythonEnv;
      semanticSlice = interfaceStaleSemanticSlice.semanticSlice;
      bindingIntent = ./fixtures/native-module/interface-stale-binding.json;
      interfacePackage = interfaceStalePackage.derivation;
      sourcePackage = interfaceStaleSourcePackage.package;
      transferPlan =
        "${fixture}/machine-ir-transfer/executable-transfer-plan.json";
      resolvedExternalEnvironment =
        "${fixture}/environment/resolved-external-environment.json";
      semanticObject = fixtureSemanticObject.derivation;
      linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
      providerId = "fixture.interface-stale.portable-c";
      proofClassification = "machine_overlay";
      namePrefix = "spaghetti-extractor-native-module-fixture-interface-stale";
    };
  faithfulSelectionV2 = import ../semantic-provider-selection-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    qualificationsById = {
      "fixture.external-environment-v2" =
        "${externalEnvironmentProviderV2}/semantic-provider-qualification.json";
      "fixture.generated-c-v2" =
        "${generatedBehavioralProviderV2}/semantic-provider-qualification.json";
      "fixture.runtime-v2" =
        "${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json";
    };
    choiceFiles = [
      "${generatedBehavioralProviderV2}/definition-choices.json"
      "${externalEnvironmentProviderV2}/definition-choices.json"
      "${qualifiedRuntimeProviderV2}/implementation-choices.json"
    ];
    selectedProviderIds = [
      "fixture.external-environment-v2"
      "fixture.generated-c-v2"
      "fixture.runtime-v2"
    ];
    mode = "faithful";
    namePrefix = "spaghetti-extractor-native-module-fixture-faithful";
  };
  faithfulNativeRealizationV2 = import ../native-realization-v2.nix {
    inherit pkgs compiler;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    implementationSelection = faithfulSelectionV2.artifact;
    providerQualifications = [
      "${generatedBehavioralProviderV2}/semantic-provider-qualification.json"
      "${externalEnvironmentProviderV2}/semantic-provider-qualification.json"
      "${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json"
    ];
    loadImageContract = "${fixture}/load-image-contract.json";
    candidateFilename = "fixture.dll";
    namePrefix = "spaghetti-extractor-native-module-fixture-faithful";
  };
  hybridSelectionV2 = import ../semantic-provider-selection-v2.nix {
    inherit pkgs;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    qualificationsById = {
      "fixture.external-environment-v2" =
        "${externalEnvironmentProviderV2}/semantic-provider-qualification.json";
      "fixture.generated-c-v2" =
        "${generatedBehavioralProviderV2}/semantic-provider-qualification.json";
      "fixture.interface-stale.portable-c" =
        interfaceStalePortableProviderV2.qualification;
      "fixture.runtime-v2" =
        "${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json";
    };
    choiceFiles = [
      "${generatedBehavioralProviderV2}/definition-choices.json"
      interfaceStalePortableProviderV2.definitionChoices
      "${externalEnvironmentProviderV2}/definition-choices.json"
      "${qualifiedRuntimeProviderV2}/implementation-choices.json"
    ];
    selectedProviderIds = [
      "fixture.external-environment-v2"
      "fixture.generated-c-v2"
      "fixture.interface-stale.portable-c"
      "fixture.runtime-v2"
    ];
    mode = "hybrid";
    namePrefix = "spaghetti-extractor-native-module-fixture-hybrid";
  };
  hybridNativeRealizationV2 = import ../native-realization-v2.nix {
    inherit pkgs compiler;
    pythonEnv = context.transferPythonEnv;
    linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule;
    implementationSelection = hybridSelectionV2.artifact;
    providerQualifications = [
      "${generatedBehavioralProviderV2}/semantic-provider-qualification.json"
      "${externalEnvironmentProviderV2}/semantic-provider-qualification.json"
      interfaceStalePortableProviderV2.qualification
      "${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json"
    ];
    loadImageContract = "${fixture}/load-image-contract.json";
    candidateFilename = "fixture.dll";
    namePrefix = "spaghetti-extractor-native-module-fixture-hybrid";
  };
  singleModuleIntent = import ../pe32-single-module-project-intent.nix {
    inherit pkgs pythonEnv;
    moduleInterface = "${fixture}/interface";
    resolvedExternalEnvironment = "${fixture}/environment";
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  singleModuleLoadPlan = import ../pe32-project-load-plan.nix {
    inherit pkgs pythonEnv;
    intent = "${singleModuleIntent}/project-intent.json";
    linkedSemanticModules."fixture.dll" =
      fixtureLinkedSemanticModule.linkedSemanticModule;
    namePrefix = "spaghetti-extractor-native-module-fixture";
  };
  wineRunner = pkgs.writeShellScript "spaghetti-extractor-observe-native-module" ''
    set -euo pipefail
    candidate="$1"
    trace="$2"
    status_file="$3"
    export HOME="$TMPDIR/home"
    export WINEPREFIX="$TMPDIR/wine"
    export WINEDEBUG=+loaddll
    export WINEDLLOVERRIDES="mscoree,mshtml="
    mkdir -p "$HOME" "$WINEPREFIX"
    xvfb-run -a wineboot -u >/dev/null 2>&1
    set +e
    timeout 60 xvfb-run -a wine "$candidate" >"$trace" 2>&1
    status=$?
    set -e
    wineserver -w >/dev/null 2>&1 || true
    echo "$status" >"$status_file"
  '';
  mkWineObservation = observationName: realization:
    pkgs.runCommand
      "spaghetti-extractor-native-module-${observationName}-wine-observation-v1"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.coreutils
          pkgs.wineWow64Packages.stableFull
          pkgs.xvfb-run
        ];
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        mkdir -p distribution observation
        cp ${realization.candidate} distribution/
        cp ${fixture}/fixture-provider.dll distribution/
        cp ${fixture}/host.exe distribution/
        ${wineRunner} "$PWD/distribution/host.exe" \
          "$PWD/observation/wine-loader.log" "$PWD/observation/status"
        status="$(cat observation/status)"
        if test "$status" -ne 0; then
          cat observation/wine-loader.log >&2
          echo "native-module host exited with status $status" >&2
          exit 1
        fi
        grep -Fi 'distribution\\fixture.dll' observation/wine-loader.log >/dev/null
        while IFS= read -r imported_dll; do
          grep -Fi "\\$imported_dll" observation/wine-loader.log >/dev/null
        done < <(
          jq -r '.import_descriptors[].dll' \
            ${fixture}/interface/module-interface.json | sort -fu
        )
        candidate_sha="$(sha256sum distribution/fixture.dll | cut -d' ' -f1)"
        realization_candidate_sha="$(jq -r '.candidate.sha256' \
          ${realization.receipt})"
        realization_sha="$(jq -r '.native_realization_sha256' \
          ${realization.receipt})"
        test "$candidate_sha" = "$realization_candidate_sha"
        test -n "$realization_sha"
        runner_sha="$(sha256sum distribution/host.exe | cut -d' ' -f1)"
        trace_sha="$(sha256sum observation/wine-loader.log | cut -d' ' -f1)"
        loaded_base_hex="$(sed -n 's/^fixture module base=0x//p' \
          observation/wine-loader.log | tr -d '\r' | tail -n 1)"
        test -n "$loaded_base_hex"
        loaded_base="$((16#$loaded_base_hex))"
        jq -n \
          --slurpfile plan ${singleModuleLoadPlan}/project-load-plan.json \
          --arg candidateSha "$candidate_sha" \
          --arg runnerSha "$runner_sha" \
          --arg traceSha "$trace_sha" \
          --argjson loadedBase "$loaded_base" \
          --argjson status "$status" '
          {
            format: "spaghetti-extractor-pe32-load-observation-v2",
            project_id: $plan[0].project_id,
            environment_sha256: $plan[0].host_environment.sha256,
            runner_sha256: $runnerSha,
            trace_sha256: $traceSha,
            process_exit_code: $status,
            modules: [{
              loader_name: "fixture.dll",
              resolved_path: "Z:/build/distribution/fixture.dll",
              sha256: $candidateSha,
              origin: "target_distribution",
              image_id: "fixture.dll",
              loaded_base: $loadedBase
            }],
            slots: ($plan[0].edges | map({
              slot_id,
              resolution: {
                kind: "host_loader",
                environment_sha256: $plan[0].host_environment.sha256
              }
            }))
          }
        ' > observation/load-observation.json
        mkdir -p "$out"
        cp observation/load-observation.json observation/wine-loader.log "$out/"
      '';
  faithfulWineObservation =
    mkWineObservation "faithful" faithfulNativeRealizationV2;
  hybridWineObservation =
    mkWineObservation "hybrid" hybridNativeRealizationV2;
  faithfulObservedLoadGraph = import ../pe32-observed-load-graph.nix {
    inherit pkgs pythonEnv;
    loadPlan = singleModuleLoadPlan;
    observation = "${faithfulWineObservation}/load-observation.json";
    namePrefix = "spaghetti-extractor-native-module-fixture-faithful";
  };
  hybridObservedLoadGraph = import ../pe32-observed-load-graph.nix {
    inherit pkgs pythonEnv;
    loadPlan = singleModuleLoadPlan;
    observation = "${hybridWineObservation}/load-observation.json";
    namePrefix = "spaghetti-extractor-native-module-fixture-hybrid";
  };
  faithfulProjectCompletion = import ../pe32-project-completion.nix {
    inherit pkgs pythonEnv;
    loadPlan = singleModuleLoadPlan;
    nativeRealizations."fixture.dll" = faithfulNativeRealizationV2.derivation;
    observedLoadGraph =
      "${faithfulObservedLoadGraph}/observed-load-graph.json";
    namePrefix = "spaghetti-extractor-native-module-fixture-faithful-realization";
  };
  hybridProjectCompletion = import ../pe32-project-completion.nix {
    inherit pkgs pythonEnv;
    loadPlan = singleModuleLoadPlan;
    nativeRealizations."fixture.dll" = hybridNativeRealizationV2.derivation;
    observedLoadGraph = "${hybridObservedLoadGraph}/observed-load-graph.json";
    namePrefix = "spaghetti-extractor-native-module-fixture-hybrid-realization";
  };
in
pkgs.runCommand "spaghetti-extractor-native-module-check"
  {
    nativeBuildInputs = [
      pkgs.jq
    ];
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    jq -e '
      .format ==
        "spaghetti-extractor-semantic-provider-qualification-v2" and
      .status == "complete" and .blockers == [] and
      .provider_kind == "generated_behavioral_c" and
      (.definition_materializations | length) > 0
    ' ${generatedBehavioralProviderV2}/semantic-provider-qualification.json \
      >/dev/null
    jq -e '
      .format ==
        "spaghetti-extractor-semantic-provider-qualification-v2" and
      .status == "complete" and .blockers == [] and
      .provider_id == "fixture.interface-stale.portable-c" and
      .provider_kind == "qualified_portable_c" and
      (.definition_materializations | length) == 1 and
      ([.facets[].status] | unique) == ["checked"]
    ' ${interfaceStalePortableProviderV2.qualification} >/dev/null
    jq -e '
      .status == "satisfied" and
      .proof.status == "satisfied" and
      .proof_classification == "machine_overlay" and
      .policy == {cbmc_required: true, tests_authorize: false}
    ' ${interfaceStalePortableProviderV2.contextualRefinement} >/dev/null
    test -s ${interfaceStalePortableProviderV2.objectManifest}
    jq -e '
      .format ==
        "spaghetti-extractor-semantic-provider-qualification-v2" and
      .status == "complete" and .blockers == [] and
      .provider_kind == "external_environment"
    ' ${externalEnvironmentProviderV2}/semantic-provider-qualification.json \
      >/dev/null
    jq -e '
      .format ==
        "spaghetti-extractor-semantic-provider-qualification-v2" and
      .status == "complete" and .blockers == [] and
      .provider_kind == "qualified_runtime" and
      (.obligation_implementations | length) > 0
    ' ${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json \
      >/dev/null
    jq -e '
      .format == "spaghetti-extractor-implementation-selection-v2" and
      .status == "complete" and .ready_for_realization == true and
      .mode == "faithful" and .blockers == []
    ' ${faithfulSelectionV2.artifact} >/dev/null
    jq -e '
      .format == "spaghetti-extractor-implementation-selection-v2" and
      .status == "complete" and .ready_for_realization == true and
      .mode == "hybrid" and .blockers == [] and
      ([.definition_selections[] | select(
        .provider_id == "fixture.interface-stale.portable-c"
      )] | length) == 1
    ' ${hybridSelectionV2.artifact} >/dev/null
    jq -e '
      .format == "spaghetti-extractor-linked-semantic-module-replay-v2" and
      .status == "complete" and .authority == "none" and
      (.semantic_object_file_sha256 | test("^[0-9a-f]{64}$")) and
      (.linked_semantic_module_sha256 | test("^[0-9a-f]{64}$"))
    ' ${fixtureLinkedSemanticModule.replayReceipt} >/dev/null
    jq -e '
      .format == "spaghetti-extractor-pe32-module-interface-v2" and
      .kind == "dll" and
      .loader.preferred_base == 1744830464 and
      .tls.template_size == 4 and
      .tls.template_data_hex == "10203040" and
      .tls.zero_fill_size == 16 and
      (.tls.callbacks | length >= 2) and
      ([.imports[] | select(
        (.dll | ascii_downcase) == "fixture-provider.dll" and
        .symbol == "FixtureCreate"
      )] | length) == 1
    ' ${fixture}/interface/module-interface.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-resolved-external-environment-v1" and
      .status == "complete" and .blockers == [] and
      (.interface_method_catalogs | length) == 1 and
      .interface_method_catalogs[0].interface_id == "IFixture" and
      ([.interface_method_catalogs[0].methods[].external_protocol.method] |
        sort) == ["Clone", "Enumerate", "FillRecord", "GetValue", "Release", "SetValue"] and
      ([.original_semantic_imports[] | select(
        (.identity.dll | ascii_downcase) == "fixture-provider.dll" and
        .identity.symbol == "FixtureCreate" and
        (.contract.payload.out_interface_relations | length) == 1 and
        .contract.payload.out_interface_relations[0].interface_id ==
          "IFixture"
      )] | length) == 1
    ' ${fixture}/environment/resolved-external-environment.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-linked-semantic-module-v2" and
      .status == "complete" and .authority == false and
      .counts.semantic_holes == 0 and
      .counts.analysis_frontiers == 0 and
      .counts.residual_obligations == 17 and
      ([.residual_obligations[] | select(
        .class == "indirect_external_callthrough"
      )] | length) == 13 and
      ([.residual_obligations[] | select(
        .class == "indirect_external_callthrough" and
        .admitted_domain.kind == "catalog_reference" and
        .allowed_provider_kinds == ["qualified_runtime"]
      )] | length) == 13
    ' ${fixtureLinkedSemanticModule.linkedSemanticModule} >/dev/null
    jq -e '
      .format == "spaghetti-extractor-pe32-module-interface-v2" and
      .status == "complete" and
      .image_id == "fixture.dll" and
      .kind == "dll" and
      .tls.template_size == 4 and
      .tls.template_data_hex == "10203040" and
      .tls.zero_fill_size > 16 and
      (.tls.callbacks | length >= 2) and
      .export_directory.ordinal_base == 2 and
      .export_directory.slot_count == 20 and
      ([.export_directory.holes[].ordinal] == [3]) and
      ([.export_directory.slots[] | select(.kind == "code") | .rva] | unique | length == 17) and
      ([.export_directory.slots[] | select(.kind == "data") | .ordinal] == [5]) and
      ([.imports[] | select(
        (.dll | ascii_downcase) == "fixture-provider.dll" and
        .symbol == "FixtureCreate"
      )] | length) == 1 and
      ([.imports[] | select(.dll == "kernel32.dll" and .symbol == "RaiseException")] | length) == 2 and
      ([.imports[] | select(.dll == "kernel32.dll" and .symbol == "UnhandledExceptionFilter")] | length) == 1 and
      ([.imports[] | select(.dll == "kernel32.dll" and .symbol == "RtlUnwind")] | length) == 1 and
      (.load_config.safe_seh.handler_rvas | length) >= 1 and
      .loader.entry_rva != 0
    ' ${faithfulNativeRealizationV2.candidateInterface} \
      >/dev/null
    jq -e '
      .format == "spaghetti-extractor-native-realization-v2" and
      .status == "complete" and .ready_for_observation == true and
      .blockers == [] and
      (.providers | length) == 3 and
      (.definitions | length) == 85 and
      (.obligations | length) == 17 and
      (.native_objects | length) > 0 and
      (.bridges | length) ==
        (input.ingresses | length) and
      (.pinned_code_layout_requirements | length) == 1
    ' ${faithfulNativeRealizationV2.receipt} \
      ${qualifiedRuntimeProviderV2}/native-ingress-plan.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-native-realization-v2" and
      .status == "complete" and .ready_for_observation == true and
      .blockers == [] and
      ([.providers[] | select(
        .provider_id == "fixture.interface-stale.portable-c" and
        .provider_kind == "qualified_portable_c" and
        (.definition_ids | length) == 1
      )] | length) == 1 and
      ([.definitions[] | select(
        .provider_id == "fixture.interface-stale.portable-c"
      )] | length) == 1 and
      ([.native_objects[] | select(
        .provider_ids == ["fixture.interface-stale.portable-c"]
      )] | length) > 0
    ' ${hybridNativeRealizationV2.receipt} >/dev/null
    jq -e '
      .status == "ready" and .blockers == [] and
      .counts.transfers == 51 and
      .counts.external_sites == 21 and
      .counts.external_contract_domains == 9 and
      .counts.external_site_target_pairs == 164 and
      ([.external_target_contracts[] | select(
        .checked_external_contract.identity.kind == "interface"
      ) | .checked_external_contract.identity.operation] | unique | sort) ==
        ["IFixture::Clone", "IFixture::Enumerate", "IFixture::FillRecord", "IFixture::GetValue",
         "IFixture::Release", "IFixture::SetValue"] and
      ([.external_sites[] | select(
        .site_kind == "dynamic_target"
      )] | length) == 13 and
      (.external_service_routes | length) == 2 and
      ([.external_service_routes | sort_by(
        .admitted_domain.protocol.id
      )[] | {
        obligation_class,
        symbol:.admitted_domain.identity.symbol,
        protocol_id:.admitted_domain.protocol.id,
        implementation
      }]) == [{
        "obligation_class":"checked_external_nonlocal_service",
        "symbol":"RtlUnwind",
        "protocol_id":"win32-rtl-unwind-v1",
        "implementation":"checked_runtime"
      },{
        "obligation_class":"checked_external_exception_object_service",
        "symbol":"UnhandledExceptionFilter",
        "protocol_id":"win32-unhandled-exception-filter-v1",
        "implementation":"checked_runtime"
      }]
    ' ${qualifiedRuntimeProviderV2}/module-runtime-plan.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-pe32-observed-load-graph-v1" and
      .status == "qualified" and .blockers == [] and
      (.modules | map(select(
        .origin == "target_distribution" and .loaded_base == 1744830464
      )) | length) == 1
    ' ${faithfulObservedLoadGraph}/observed-load-graph.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-pe32-observed-load-graph-v1" and
      .status == "qualified" and .blockers == [] and
      (.modules | map(select(
        .origin == "target_distribution" and .loaded_base == 1744830464
      )) | length) == 1
    ' ${hybridObservedLoadGraph}/observed-load-graph.json >/dev/null
    jq -e --arg realization_sha "$(sha256sum \
        ${faithfulNativeRealizationV2.receipt} | cut -d' ' -f1)" '
      .format == "spaghetti-extractor-pe32-project-completion-v3" and
      .status == "complete" and
      (.images | length) == 1 and
      .images[0].image_id == "fixture.dll" and
      .images[0].status == "complete" and
      .images[0].native_realization_sha256 == $realization_sha and
      .images[0].candidate_sha256 ==
        input.modules[0].sha256 and
      .blockers == []
    ' ${faithfulProjectCompletion}/project-completion.json \
      ${faithfulObservedLoadGraph}/observed-load-graph.json >/dev/null
    jq -e --arg realization_sha "$(sha256sum \
        ${hybridNativeRealizationV2.receipt} | cut -d' ' -f1)" '
      .format == "spaghetti-extractor-pe32-project-completion-v3" and
      .status == "complete" and
      (.images | length) == 1 and
      .images[0].image_id == "fixture.dll" and
      .images[0].status == "complete" and
      .images[0].native_realization_sha256 == $realization_sha and
      .images[0].candidate_sha256 ==
        input.modules[0].sha256 and
      .blockers == []
    ' ${hybridProjectCompletion}/project-completion.json \
      ${hybridObservedLoadGraph}/observed-load-graph.json >/dev/null
    test -s ${faithfulNativeRealizationV2.candidate}
    test -s ${hybridNativeRealizationV2.candidate}
    mkdir -p "$out"
    cp ${faithfulWineObservation}/wine-loader.log "$out/faithful-wine.log"
    cp ${hybridWineObservation}/wine-loader.log "$out/hybrid-wine.log"
    cp ${faithfulNativeRealizationV2.compositionManifest} "$out/"
    cp ${faithfulObservedLoadGraph}/observed-load-graph.json \
      "$out/faithful-observed-load-graph.json"
    cp ${hybridObservedLoadGraph}/observed-load-graph.json \
      "$out/hybrid-observed-load-graph.json"
    cp ${faithfulProjectCompletion}/project-completion.json \
      "$out/faithful-project-completion.json"
    cp ${hybridProjectCompletion}/project-completion.json \
      "$out/hybrid-project-completion.json"
    cp ${faithfulNativeRealizationV2.candidateInterface} \
      "$out/candidate-module-interface.json"
  ''
