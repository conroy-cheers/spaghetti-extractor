# spaghetti-extractor-python-role: developer
{ pkgs, sdk }:

let
  mingw = pkgs.pkgsCross.mingw32;
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
    postInstall = old.postInstall or "";
    __contentAddressed = true;
    meta = (old.meta or { }) // {
      platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
    };
  });
  originalPe = "${original}/bin/hello.exe";
  registrationFixture =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-derived-registration-fixture"
      {
        nativeBuildInputs = [
          mingw.stdenv.cc
          mingw.buildPackages.binutils
        ];
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        mkdir -p "$out/bin"
        i686-w64-mingw32-gcc \
          -O2 -g0 -fno-ident -fno-asynchronous-unwind-tables \
          -fno-align-functions -fno-align-labels -fno-align-loops \
          -fno-align-jumps -Wl,--no-insert-timestamp \
          ${../../tests/fixtures/hello-derived-registration.c} \
          -o "$out/bin/hello-derived-registration.exe"
        image_base="$(${mingw.buildPackages.binutils}/bin/i686-w64-mingw32-objdump \
          -p "$out/bin/hello-derived-registration.exe" \
          | awk '$1 == "ImageBase" { print $2; exit }')"
        destructor_va="$(${mingw.buildPackages.binutils}/bin/i686-w64-mingw32-nm \
          "$out/bin/hello-derived-registration.exe" \
          | awk '$3 == "_registered_destructor" { print $1; exit }')"
        test -n "$image_base"
        test -n "$destructor_va"
        printf '{"registered_destructor_rva":%d}\n' \
          "$((16#$destructor_va - 16#$image_base))" \
          > "$out/verification-symbols.json"
      '';
  registrationFixturePe = "${registrationFixture}/bin/hello-derived-registration.exe";
  runtimeProfile = "${sdk.profiles}/pe32-msvcrt-machine-runtime-v1.json";
  mingwRuntimeCatalog = sdk.lifting.catalogPack {
    name = "mingw-w64-i686-runtime";
    snapshot = {
      id = "mingw-w64-${mingw.windows.mingw_w64.version}";
      target = {
        architecture = "i686";
        object_format = "coff";
        abi = "mingw32-gcc";
      };
    };
    artifacts = [
      {
        id = "libmingw32.a";
        path = "${mingw.windows.mingw_w64}/lib/libmingw32.a";
        familyId = "mingw-w64";
        componentId = "startup-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
      {
        id = "libmingwex.a";
        path = "${mingw.windows.mingw_w64}/lib/libmingwex.a";
        familyId = "mingw-w64";
        componentId = "extended-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
      {
        id = "libmoldname.a";
        path = "${mingw.windows.mingw_w64}/lib/libmoldname.a";
        familyId = "mingw-w64";
        componentId = "legacy-name-runtime";
        releaseId = mingw.windows.mingw_w64.version;
        abiId = "mingw32-gcc";
        retentionModel = "archive_member";
        provenance = {
          provider = "nixpkgs";
          package = mingw.windows.mingw_w64.name;
        };
      }
    ];
  };
  environment = sdk.environment.pe32 {
    id = "gnu-hello-win32";
    profilePacks = [ runtimeProfile ];
    interfacePacks = [ ];
    launchProfile = "${sdk.profiles}/pe32-win32-console-launch-assumptions-v1.json";
    boundaryIntents."callback:unhandled-exception-filter" =
      ./intent/calls/unhandled-exception-filter.json;
    support.processTermination = {
      dll = "msvcrt.dll";
      symbol = "exit";
    };
  };
  registrationFixtureEnvironment = sdk.environment.pe32 {
    id = "gnu-hello-derived-registration";
    profilePacks = [ runtimeProfile ];
    interfacePacks = [ ];
    launchProfile = "${sdk.profiles}/pe32-win32-console-launch-assumptions-v1.json";
    support.processTermination = {
      dll = "msvcrt.dll";
      symbol = "exit";
    };
  };
  workflow = sdk.workflow.pe32 {
    targetId = target.id;
    original = originalPe;
    binaryIdentity = "hello.exe";
    externalEnvironment = environment;
    lifting = {
      boundaries = [
        {
          subject = "callback:unhandled-exception-filter";
          protocol = {
            layouts = ./intent/calls/unhandled-exception-filter-layouts.json;
          };
        }
      ];
      components = {
        intent = ./intent/components.json;
        operatorRoot = ./intent;
        sourceRoot = ./source;
      };
      libraries = {
        packs = [ mingwRuntimeCatalog ];
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
  registrationFixtureWorkflow = sdk.workflow.pe32 {
    targetId = "gnu-hello-derived-registration";
    original = registrationFixturePe;
    binaryIdentity = "hello-derived-registration.exe";
    externalEnvironment = registrationFixtureEnvironment;
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
  registrationGeneratedProvider = registrationFixtureWorkflow.generatedSemanticProvider;
  registrationExternalProvider = registrationFixtureWorkflow.externalSemanticProvider;
  registrationRuntimeProvider = registrationFixtureWorkflow.runtimeSemanticProvider;
  registrationGeneratedSelection =
    registrationFixtureWorkflow.semanticImplementationSelections.faithful;
  registrationFixtureProviderCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-derived-registration-provider-check"
      {
        nativeBuildInputs = [ pkgs.jq ];
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        jq -e '
          .format == "spaghetti-extractor-linked-semantic-module-v2" and
          .status == "complete" and .authority == false and
          .counts.semantic_holes == 0 and .semantic_holes == [] and
          ([.definition_requirements[] | select(
            .allowed_provider_kinds | index("generated_behavioral_c") != null
          )] | length) == 611 and
          ([.definition_requirements[] | select(
            .allowed_provider_kinds | index("qualified_runtime") != null
          )] | length) == 16 and
          .counts.residual_obligations == 27
        ' ${registrationFixtureWorkflow.linkedSemanticModule.linkedSemanticModule} \
          >/dev/null
        jq -e '
          .format ==
            "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and .blockers == [] and
          .provider_kind == "generated_behavioral_c" and
          (.semantic_slice.definitions | length) == 611 and
          (.definition_materializations | length) == 611 and
          ([.definition_materializations[].source_sha256s | length] |
            all(. >= 2)) and
          ([.definition_materializations[].object_sha256s | length] |
            all(. == 1))
        ' ${registrationGeneratedProvider}/semantic-provider-qualification.json \
          >/dev/null
        jq -e '
          .format ==
            "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and .blockers == [] and
          .provider_kind == "qualified_runtime" and
          (.semantic_slice.definitions | length) == 16 and
          (.semantic_slice.obligations | length) == 27 and
          (.definition_materializations | length) == 16 and
          (.obligation_implementations | length) == 27 and
          ([.definition_materializations[].object_sha256s | length] |
            unique) == [11] and
          ([.obligation_implementations[].object_sha256s | length] |
            unique) == [11]
        ' ${registrationRuntimeProvider}/semantic-provider-qualification.json \
          >/dev/null
        test -s ${registrationRuntimeProvider}/native-ingress-plan.json
        test -s \
          ${registrationRuntimeProvider}/shared-module-runtime-package.json
        test -s \
          ${registrationRuntimeProvider}/native-realization-object-manifest.json
        jq -e '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and .ready_for_realization == true and
          .blockers == [] and
          .mode == "faithful" and
          (.qualification_sha256s | length) == 3 and
          (.definition_selections | length) == 703 and
          (.obligation_selections | length) == 27 and
          ([.definition_selections[].provider_kind] | unique | sort) ==
            ["external_environment", "generated_behavioral_c",
             "qualified_runtime"] and
          ([.obligation_selections[].provider_kind] | unique) ==
            ["qualified_runtime"]
        ' ${registrationGeneratedSelection.artifact} >/dev/null
        test "$(find ${registrationGeneratedProvider}/objects \
          -type f -name '*.o' | wc -l)" -gt 0
        mkdir -p "$out"
        cp ${registrationGeneratedProvider}/semantic-provider-qualification.json \
          "$out/"
        cp ${registrationGeneratedSelection.artifact} \
          "$out/implementation-selection.json"
        cp ${registrationExternalProvider}/semantic-provider-qualification.json \
          "$out/external-provider-qualification.json"
        cp ${registrationRuntimeProvider}/semantic-provider-qualification.json \
          "$out/runtime-provider-qualification.json"
      '';
  registrationFixtureLinkedCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-derived-registration-linked-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        linked=${registrationFixtureWorkflow.linkedSemanticModule.linkedSemanticModule}
        target_rva="$(jq -r .registered_destructor_rva \
          ${registrationFixture}/verification-symbols.json)"
        jq -e --argjson target_rva "$target_rva" '
          .format == "spaghetti-extractor-linked-semantic-module-v2" and
          .status == "complete" and .semantic_holes == [] and
          ([.admitted_domains[] | .guest_transfer_entry_rvas[]?] |
            index($target_rva)) != null and
          ([.active_symbols[] | select(
            .kind == "function"
          ) | .original_rva] | index($target_rva)) != null
        ' "$linked" >/dev/null
        mkdir -p "$out"
        cp "$linked" "$out/linked-semantic-module.json"
        cp ${registrationFixture}/verification-symbols.json \
          "$out/verification-symbols.json"
      '';
  registrationFixtureSemanticObjectCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-derived-registration-semantic-object-check"
      { __contentAddressed = true; }
      ''
        set -euo pipefail
        export PYTHONPATH=${registrationFixtureWorkflow.semanticObject.phasePythonSource.pythonPath}
        ${registrationFixtureWorkflow.semanticObject.python} - \
          ${registrationFixtureWorkflow.semanticObject.artifact} \
          ${registrationFixtureWorkflow.transferPlan.plan} \
          ${registrationFixtureWorkflow.moduleInterface}/module-interface.json \
          ${registrationFixtureWorkflow.qualifiedPlatform.qualifiedPlatform} \
          ${registrationFixture}/verification-symbols.json \
          "$out" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.semantic_objects.replay import (
            replay_semantic_object_v1,
        )

        semantic_path = pathlib.Path(sys.argv[1])
        transfer_path = pathlib.Path(sys.argv[2])
        interface_path = pathlib.Path(sys.argv[3])
        platform_path = pathlib.Path(sys.argv[4])
        symbols_path = pathlib.Path(sys.argv[5])
        output = pathlib.Path(sys.argv[6])
        package_root = semantic_path.parent

        semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
        transfer = json.loads(transfer_path.read_text(encoding="utf-8"))
        interface = json.loads(interface_path.read_text(encoding="utf-8"))
        platform = json.loads(platform_path.read_text(encoding="utf-8"))
        symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
        replay = replay_semantic_object_v1(semantic_path)

        assert (package_root / "executable-transfer-plan.json").is_symlink()
        assert (package_root / "module-interface.json").is_symlink()
        assert not (package_root / "exceptional-transitions").exists()
        # Requirements are normalized into canonical package bytes; the other
        # large, already-canonical inputs remain store links.
        assert (package_root / "isa-requirements.json").is_file()
        assert (package_root / "qualified-platform.json").is_symlink()
        assert (package_root / "isa-form-qualification-certificate.json").is_symlink()
        assert (package_root / "qualified-platform-selection.json").is_file()
        assert (
            (package_root / "executable-transfer-plan.json").read_bytes()
            == transfer_path.read_bytes()
        )
        assert (
            (package_root / "module-interface.json").read_bytes()
            == interface_path.read_bytes()
        )
        assert semantic["status"] == "complete"
        assert semantic["role"] == "checked_relocatable"
        assert semantic["authority"] is False
        assert transfer["status"] == "complete"
        assert transfer["counts"]["blockers"] == 0
        assert semantic["counts"]["transfers"] == transfer["counts"]["compiled_transfers"]
        assert semantic["bindings"]["transfer_plan_sha256"] == transfer["plan_sha256"]
        assert semantic["bindings"]["pe_sha256"] == interface["identity"]["pe_sha256"]
        assert (
            semantic["bindings"]["qualified_platform_sha256"]
            == platform["platform_sha256"]
        )
        assert semantic["platform_selection"] is not None
        assert semantic["platform_selection"]["status"] == "qualified"
        assert semantic["platform_selection"]["counts"]["issues"] == 0
        assert semantic["counts"]["transfers"] == 611
        # The semantic object declares the complete checked callable catalog,
        # including SetUnhandledExceptionFilter even though this compact fixture
        # reaches it through a loader-written function value rather than a
        # statically named transfer call.
        assert semantic["counts"]["symbols"] == 703
        assert semantic["counts"]["definitions"] == 622
        assert semantic["counts"]["relocations"] == 1147
        assert semantic["counts"]["holes"] == 22
        assert semantic["counts"]["isa_forms"] == 109
        assert semantic["counts"]["isa_occurrences"] == 1523
        assert (
            semantic["counts"]["isa_occurrences_qualified"]
            == semantic["counts"]["isa_occurrences"]
        )
        assert not any(
            hole["kind"] == "qualified_platform_selection_missing"
            for hole in semantic["holes"]
        )
        assert {
            symbol["anchor_kind"]
            for symbol in semantic["symbols"]
            if symbol["kind"] == "data_anchor"
        } == {"tls_template", "tls_index_cell", "tls_callback_array"}
        assert interface["counts"]["relocation_blocks"] == 4
        assert interface["counts"]["relocation_slots"] == 266
        assert interface["counts"]["base_relocations"] == 263
        assert interface["counts"]["runtime_header_bytes"] == 1024
        assert sum(
            symbol["storage_class"] == "image_headers"
            for symbol in semantic["symbols"]
        ) == 1
        base_relocations = [
            relocation for relocation in semantic["relocations"]
            if relocation["kind"] == "image_base_relocation"
        ]
        assert len(base_relocations) == 263
        assert {
            relocation["status"] for relocation in base_relocations
        } == {"resolved_local"}
        assert {
            relocation["kind"] for relocation in semantic["relocations"]
        } == {
            "direct_control", "external_call", "iat_slot",
            "image_base_relocation", "indirect_call", "internal_call",
        }
        assert {
            symbol["declaration"]["namespace"]
            for symbol in semantic["symbols"]
            if symbol["kind"] in {
                "external_function", "runtime_primitive", "unclassified_import",
            }
        } == {
            "original_loader_import_slot", "original_semantic_import",
            "generated_runtime_support",
        }
        target_rva = symbols["registered_destructor_rva"]
        assert any(
            definition["source"]["rva_start"] == target_rva
            for definition in semantic["definitions"]
            if definition["definition_kind"] == "transfer_v2"
        )
        assert replay["semantic_object_sha256"] == semantic["semantic_object_sha256"]
        assert replay["transfer_plan_sha256"] == transfer["plan_sha256"]
        assert replay["counts"] == semantic["counts"]

        output.mkdir(parents=True)
        (output / "semantic-object-derived-registration.json").write_text(
            json.dumps({
                "authority": False,
                "registered_destructor_rva": target_rva,
                "semantic_object_sha256": replay["semantic_object_sha256"],
                "transfer_plan_sha256": replay["transfer_plan_sha256"],
                "qualified_platform_sha256": semantic["bindings"][
                    "qualified_platform_sha256"
                ],
                "counts": replay["counts"],
            }, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
      '';
  semanticObjectRealHelloCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-semantic-object-real-scale-check"
      { __contentAddressed = true; }
      ''
        set -euo pipefail
        export PYTHONPATH=${workflow.semanticObject.phasePythonSource.pythonPath}
        ${workflow.semanticObject.python} - \
          ${workflow.semanticObject.artifact} \
          ${workflow.transferPlan.plan} \
          "$out" <<'PY'
        import json
        import pathlib
        import resource
        import sys
        import time

        from spaghetti_extractor.semantic_objects.replay import (
            replay_semantic_object_v1,
        )

        semantic_path = pathlib.Path(sys.argv[1])
        transfer_path = pathlib.Path(sys.argv[2])
        output = pathlib.Path(sys.argv[3])
        package_root = semantic_path.parent
        assert (package_root / "executable-transfer-plan.json").is_symlink()
        assert (package_root / "module-interface.json").is_symlink()
        assert (
            (package_root / "executable-transfer-plan.json").read_bytes()
            == transfer_path.read_bytes()
        )
        started = time.perf_counter()
        replay = replay_semantic_object_v1(semantic_path)
        elapsed = time.perf_counter() - started
        rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
        transfer = json.loads(transfer_path.read_text(encoding="utf-8"))
        interface = json.loads(
            (package_root / "module-interface.json").read_text(encoding="utf-8")
        )
        assert semantic["status"] == "complete"
        assert semantic["role"] == "checked_relocatable"
        assert semantic["authority"] is False
        assert semantic["counts"]["transfers"] == 7849
        assert semantic["counts"]["symbols"] == 8019
        assert semantic["counts"]["definitions"] == 7863
        assert semantic["counts"]["relocations"] == 12249
        assert semantic["counts"]["holes"] == 103
        assert semantic["counts"]["transfers"] == transfer["counts"]["compiled_transfers"]
        assert semantic["bindings"]["transfer_plan_sha256"] == transfer["plan_sha256"]
        assert transfer["status"] == "complete"
        assert transfer["counts"]["blockers"] == 0
        def import_identity(row):
            return (
                row["dll"].lower(), row.get("symbol"), row.get("ordinal")
            )

        static_import_identities = {
            import_identity(row) for row in interface["imports"]
        }
        static_import_identities.update(
            import_identity(cell)
            for descriptor in interface["delay_imports"]
            for cell in descriptor["cells"]
        )
        semantic_imports = [
            symbol for symbol in semantic["symbols"]
            if symbol["kind"] == "external_function"
        ]
        static_semantic_imports = [
            symbol for symbol in semantic_imports
            if import_identity(symbol["declaration"])
            in static_import_identities
        ]
        dynamic_semantic_imports = [
            symbol for symbol in semantic_imports
            if import_identity(symbol["declaration"])
            not in static_import_identities
        ]
        assert len(static_import_identities) == 75
        assert len(static_semantic_imports) == 75
        assert sum(
            symbol["declaration"]["declaration_role"] == "machine_import"
            for symbol in static_semantic_imports
        ) == 73
        assert sum(
            symbol["declaration"]["declaration_role"] == "loader_service"
            for symbol in static_semantic_imports
        ) == 2
        assert [
            {
                key: symbol["declaration"][key]
                for key in (
                    "dll", "symbol", "ordinal", "declaration_role",
                    "loader_service_contract_sha256",
                )
            }
            for symbol in dynamic_semantic_imports
        ] == [{
            "dll": "msvcrt.dll",
            "symbol": "___lc_codepage_func",
            "ordinal": None,
            "declaration_role": "loader_service",
            "loader_service_contract_sha256": (
                "7f5dfd7aff2df8422fb6cf222362d5df"
                "a08ac4ee1aff13ef10160e4d922b38c9"
            ),
        }]
        exception_transitions = [
            symbol for symbol in semantic["symbols"]
            if symbol["kind"] == "exception_transition"
        ]
        assert len(exception_transitions) == 3
        assert all(
            symbol["declaration"]["authorizing"] is True
            and symbol["declaration"]["disposition"] == "terminates"
            and symbol["declaration"]["operation"] == "divide_if"
            for symbol in exception_transitions
        )
        assert semantic["effect_index"]["exceptional_transitions"]["count"] == 3
        assert (
            semantic["effect_index"]["exceptional_transitions"]["source"]
            == "transfer_v2_resolved_environment"
        )
        assert "authority_manifest_sha256" not in (
            semantic["effect_index"]["exceptional_transitions"]
        )
        assert {
            symbol["anchor_kind"]
            for symbol in semantic["symbols"]
            if symbol["kind"] == "data_anchor"
        } == {"tls_template", "tls_index_cell", "tls_callback_array"}
        assert sum(
            symbol["storage_class"] == "image_headers"
            for symbol in semantic["symbols"]
        ) == 1
        base_relocations = [
            relocation for relocation in semantic["relocations"]
            if relocation["kind"] == "image_base_relocation"
        ]
        assert len(base_relocations) == 1162
        assert {
            relocation["status"] for relocation in base_relocations
        } == {"resolved_local"}
        assert {
            relocation["kind"] for relocation in semantic["relocations"]
        } == {
            "direct_control", "external_call", "finite_control_target",
            "iat_slot", "image_base_relocation", "indirect_call", "internal_call",
            "exception_transition_activation",
        }
        assert elapsed <= 8.0, elapsed
        output.mkdir(parents=True)
        (output / "semantic-object-real-hello.json").write_text(
            json.dumps({
                "authority": False,
                "semantic_object_sha256": replay["semantic_object_sha256"],
                "transfer_plan_sha256": replay["transfer_plan_sha256"],
                "counts": replay["counts"],
                "elapsed_seconds": elapsed,
                "max_rss_kib": rss_kib,
                "limits": {"seconds": 8.0},
            }, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
      '';
  nativeIngressExceptionalCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-native-ingress-exception-check"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          sdk.validation.pythonEnv
        ];
      }
      ''
        set -euo pipefail
        linked=${workflow.linkedSemanticModule.linkedSemanticModule}
        export PYTHONPATH=${sdk.sources.fullSource}/src
        mkdir -p "$TMPDIR/ingress"
        python - "$linked" "$TMPDIR/ingress" <<'PY'
        import sys
        from pathlib import Path

        from spaghetti_extractor.candidate.native_ingress_plan import (
            write_native_ingress_plan_from_linked_module,
        )

        write_native_ingress_plan_from_linked_module(
            linked_semantic_module=Path(sys.argv[1]),
            out=Path(sys.argv[2]),
        )
        PY
        ingress="$TMPDIR/ingress/native-ingress-plan.json"
        linked_sha256="$(jq -r '.linked_semantic_module_sha256' "$linked")"
        transition_sha256="$(jq -r \
          '.effects.exceptions[] | select(.occurrence.source_rva == 57683) |
           .transition.transition_sha256' \
          "$linked")"
        jq -e \
          --arg linked_sha256 "$linked_sha256" \
          --arg transition_sha256 "$transition_sha256" '
          .format == "spaghetti-extractor-native-ingress-plan-v2" and
          .status == "complete" and
          (has("module_execution_closure_sha256") | not) and
          (.module | has("module_execution_closure_sha256") | not) and
          .module.linked_semantic_module_sha256 == $linked_sha256 and
          .blockers == [] and
          ([.blockers[] | select(
            .category == "callback_call_protocol_missing_or_ambiguous")] |
            length) == 0 and
          ([.blockers[] | select(
            .category == "native_ingress_lifecycle_transducer_incomplete")]
            | length) == 0 and
          .required_support_imports == [{
            dll: "kernel32.dll",
            ordinal: null,
            ownership: "runtime_support",
            purpose: "checked_exception_escape",
            symbol: "RaiseException"
          }] and
          ([.runtime_requirements.features[]] |
            index("checked_process_root_termination_v1") != null) and
          ([.outcome_protocols[] | select(
            .outcomes == ["exceptional", "normal"])] | length) == 3 and
          (.seh_protocols | length) == 4 and
          ([.seh_protocols[] | select(
            .exceptional_transition.sha256 == $transition_sha256 and
            .exception.code == 3221225620 and
            .exception.continuable == true and
            .portals == [{
              candidate_symbol:
                "spx_exception_portal_9c65a110c18249f61ddb645a",
              source_rva: 57683
            }]
          )] | length) == 2 and
          ([.seh_protocols[].escape_disposition] | sort) ==
            ["escape_callable_root", "escape_callable_root",
             "terminate_process_root", "terminate_process_root"] and
          ([.ingresses[] | select(.role == "process_entry") |
            .outcome_protocol_id] | length) == 1 and
          (([.ingresses[] | select(.role == "process_entry") |
            .outcome_protocol_id][0]) as $process_outcome |
            ([.outcome_protocols[] | select(.id == $process_outcome) |
              .seh_protocol_ids[]]) as $process_seh_ids |
            ($process_seh_ids | length) == 2 and
            ([$process_seh_ids[] as $process_seh |
              .seh_protocols[] | select(.id == $process_seh) |
              .escape_disposition] | sort) ==
                ["terminate_process_root", "terminate_process_root"])
        ' "$ingress" >/dev/null
        mkdir -p "$out"
        cp "$ingress" "$out/native-ingress-plan.json"
      '';
  defaultConfiguration = target.workflow.default_configuration;
  components = workflow.components;
  asciiToLowerLibraryBehaviorPack = sdk.lifting.behaviorPack {
    name = "spaghetti-extractor-gnu-hello-ascii-to-lower-library-pack-v3";
    implementation = ./intent/libraries/ascii-to-lower-provider/implementation.json;
    interfaceIntent = ./intent/interfaces-v5/ascii-to-lower.json;
    sourcePackage = ./intent/libraries/ascii-to-lower-provider/source-package;
    qualification = ./intent/libraries/ascii-to-lower-provider/qualification.json;
  };
  asciiToLowerLibraryProvider = sdk.candidate.portableCWorkPackageProviderV2 {
    semanticSlice = components.v6SemanticSlices.ascii-to-lower.semanticSlice;
    bindingIntent = components.bindingIntentPaths.ascii-to-lower;
    interfacePackage = components.v5Interfaces.ascii-to-lower.derivation;
    sourcePackage = "${asciiToLowerLibraryBehaviorPack.behaviorPack}/source-package";
    # The exact machine slice is independent of the replacement source.  Reuse
    # the already-qualified component slice so the library adapter is proved
    # through the same fail-closed contextual path instead of minting
    # source-only authority.
    exactCSlice =
      "${asciiToLowerV6Provider.derivation}/exact-c/component-exact-c-slice-v1.json";
    transferPlan = workflow.transferPlan.plan;
    resolvedExternalEnvironment = "${workflow.resolvedEnvironment.derivation}/resolved-external-environment.json";
    semanticObject = workflow.semanticObject.derivation;
    provenanceArtifacts = {
      "library-behavior-pack" = "${asciiToLowerLibraryBehaviorPack.behaviorPack}/behavior-pack.json";
      "library-source-qualification" =
        "${asciiToLowerLibraryBehaviorPack.behaviorPack}/source-qualification-v1.json";
    };
    providerId = "gnu-hello.library.ascii-to-lower.portable-c";
    proofClassification = "machine_overlay";
    namePrefix = "spaghetti-extractor-gnu-hello-library-ascii-to-lower";
  };
  asciiToLowerLibraryProviderCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-ascii-to-lower-library-provider-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        qualification=${asciiToLowerLibraryProvider.qualification}
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_id == "gnu-hello.library.ascii-to-lower.portable-c" and
          .provider_kind == "qualified_portable_c" and
          (.definition_materializations | length) == 1 and
          ([.dependencies[] | select(
            startswith("provider-provenance:library-behavior-pack:"))] |
            length) == 1 and
          ([.dependencies[] | select(
            startswith("provider-provenance:library-source-qualification:"))] |
            length) == 1 and
          ([.facets[].status] | unique) == ["checked"] and
          .blockers == []
        ' "$qualification" >/dev/null
        jq -e '
          .status == "satisfied" and
          .proof.status == "satisfied" and
          .policy == {cbmc_required: true, tests_authorize: false}
        ' ${asciiToLowerLibraryProvider.contextualRefinement} >/dev/null
        touch "$out"
      '';
  v6ComponentChecks = builtins.listToAttrs (
    pkgs.lib.concatMap (componentId: [
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
    ]) (builtins.attrNames components.v6SemanticSlices)
  );
  candidateTests = {
    "gnu-hello-default-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-default-candidate";
      configurationId = "faithful";
      namePrefix = "spaghetti-extractor-gnu-hello-semantic-v2";
      suite = ./tests/candidate-suite.json;
      candidateBinary = workflow.nativeRealizations.faithful.candidate;
      nativeRealization = workflow.nativeRealizations.faithful.derivation;
    };
    "gnu-hello-derived-registration-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-derived-registration-candidate";
      configurationId = "faithful";
      namePrefix = "spaghetti-extractor-gnu-hello-derived-registration-semantic-v2";
      suite = ./tests/derived-registration-candidate-suite.json;
      candidateBinary = registrationFixtureWorkflow.nativeRealizations.faithful.candidate;
      nativeRealization = registrationFixtureWorkflow.nativeRealizations.faithful.derivation;
    };
    "gnu-hello-ascii-to-lower-v6-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-ascii-to-lower-v6-candidate";
      configurationId = "ascii-to-lower-enabled";
      namePrefix = "spaghetti-extractor-gnu-hello-ascii-to-lower-v6-semantic-v2";
      suite = ./tests/ascii-to-lower-v6-candidate-suite.json;
      candidateBinary = workflow.nativeRealizations.ascii-to-lower-enabled.candidate;
      nativeRealization = workflow.nativeRealizations.ascii-to-lower-enabled.derivation;
    };
    "gnu-hello-startup-callback-v6-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-startup-callback-v6-candidate";
      configurationId = "startup-callback-enabled";
      namePrefix = "spaghetti-extractor-gnu-hello-startup-callback-v6-semantic-v2";
      suite = ./tests/startup-callback-v6-candidate-suite.json;
      candidateBinary = workflow.nativeRealizations.startup-callback-enabled.candidate;
      nativeRealization = workflow.nativeRealizations.startup-callback-enabled.derivation;
    };
    "gnu-hello-program-name-selection-v6-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-program-name-selection-v6-candidate";
      configurationId = "program-name-selection-enabled";
      namePrefix = "spaghetti-extractor-gnu-hello-program-name-selection-v6-semantic-v2";
      suite = ./tests/program-name-selection-v6-candidate-suite.json;
      candidateBinary = workflow.nativeRealizations.program-name-selection-enabled.candidate;
      nativeRealization = workflow.nativeRealizations.program-name-selection-enabled.derivation;
    };
    "gnu-hello-string-pointer-v6-candidate" = sdk.candidate.testSuite {
      id = "gnu-hello-string-pointer-v6-candidate";
      configurationId = "string-pointer-enabled";
      namePrefix = "spaghetti-extractor-gnu-hello-string-pointer-v6-semantic-v2";
      suite = ./tests/string-pointer-v6-candidate-suite.json;
      candidateBinary = workflow.nativeRealizations.string-pointer-enabled.candidate;
      nativeRealization = workflow.nativeRealizations.string-pointer-enabled.derivation;
    };
  };
  semanticModuleV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-linked-semantic-module-v2-check"
      {
        nativeBuildInputs = [
          pkgs.jq
          sdk.validation.pythonEnv
        ];
      }
      ''
        set -euo pipefail
        module=${workflow.linkedSemanticModule.linkedSemanticModule}
        jq -e '
          .format == "spaghetti-extractor-linked-semantic-module-v2" and
          .status == "complete" and
          .authority == false and
          (has("authorizes_execution") | not) and
          .link_provenance.algorithm
            == "semantic-object-conservative-may-link-v1" and
          (.link_provenance.root_inventory_sha256
            | test("^[0-9a-f]{64}$")) and
          (.link_provenance.relocation_inventory_sha256
            | test("^[0-9a-f]{64}$")) and
          .counts.definitions == 8019 and
          .counts.active_symbols == 8019 and
          .counts.active_relocations == 12249 and
          .counts.direct_control_edges == 10316 and
          .counts.semantic_holes == 0 and
          .counts.analysis_frontiers == 0 and
          .counts.residual_obligations == 109 and
          ([.residual_obligations[] | select(
            .class == "internal_code_dispatch")] | length) == 12 and
          ([.residual_obligations[] | select(
            .class == "indirect_external_callthrough")] | length) == 83 and
          ([.residual_obligations[] | select(
            .class == "callback_capability_publication")] | length) == 14 and
          (.effects.indirect_targets | length) == 95 and
          ([.effects.indirect_targets[] | select(
            .kind == "checked_indirect_callable_dispatch_v2")]
            | length) == 83 and
          ([.admitted_domains[] | select(
            .kind == "checked_indirect_callable_targets_v3")]
            | length) == 1 and
          ([.admitted_domains[] | select(
            .kind == "checked_indirect_callable_targets_v3")][0]
            .guest_transfer_entry_rvas | length) == 7849 and
          ([.admitted_domains[] | select(
            .kind == "checked_indirect_callable_targets_v3")][0]
            .external_loader_targets | length) == 76 and
          (.effects.callbacks | length) == 14 and
          (.effects.exceptions | length) == 3 and
          (.effects.lifecycle | length) == 41 and
          (.effects.runtime_providers | length) == 5 and
          ([.effects.runtime_providers[] | select(
            .kind == "qualified_runtime_provider_effect_v2")]
            | length) == 5 and
          .effects.nonlocal_transitions == [] and
          .effects.export_capabilities == [] and
          (.effects.external_contracts | length) == 151 and
          ([.effects.external_contracts[] | select(
            .semantic_role == "external_function")] | length) == 76 and
          ([.effects.external_contracts[] | select(
            .semantic_role == "loader_import_slot")] | length) == 75 and
          ([.effects.external_contracts[] | select(
            .semantic_role == "external_function" and
            .allowed_outcomes == ["no_return"])] | length) == 5 and
          (.effects.import_uses | length) == 71 and
          ([.effects.import_uses[].sites[] | select(
            .kind == "code_call")] | length) == 321 and
          .effects.code_capabilities == [] and
          ([.effects.callbacks[].callback_protocol_id] | unique | length) == 4
        ' "$module" >/dev/null
        export PYTHONPATH=${sdk.sources.fullSource}/src
        export SPX_LINKED_MODULE_V2="$module"
        python - <<'PY'
        import os
        from pathlib import Path

        from spaghetti_extractor.candidate.runtime_canonical import (
            guest_dispatch_from_linked_module_v2,
        )
        from spaghetti_extractor.semantic_link.module_v2 import (
            LinkedSemanticModuleV2,
        )
        from spaghetti_extractor.transfer.plan import (
            load_executable_transfer_plan,
        )

        source = Path(os.environ["SPX_LINKED_MODULE_V2"])
        linked = LinkedSemanticModuleV2.load(
            source, require_complete=True
        )
        if linked.semantic_object is None:
            raise SystemExit("V2 package omitted its checked semantic object")
        _payload, transfers = load_executable_transfer_plan(
            linked.semantic_object.transfer_plan_path, require_complete=True
        )
        domains, sites = guest_dispatch_from_linked_module_v2(
            transfers=transfers, linked_module=linked.payload
        )
        domain_by_id = {row.domain_sha256: row for row in domains}
        counts = {
            "domains": len(domains),
            "sites": len(sites),
            "domain_targets": sum(len(row.target_rvas) for row in domains),
            "external_targets": sum(
                len(row.external_loader_targets) for row in domains
            ),
            "expanded_targets": sum(
                len(domain_by_id[row.domain_sha256].target_rvas)
                for row in sites
            ),
            "calls": sum(row.kind == "indirect_call" for row in sites),
            "jumps": sum(row.kind == "indirect_jump" for row in sites),
        }
        expected = {
            "domains": 1,
            "sites": 95,
            "domain_targets": 7849,
            "external_targets": 76,
            "expanded_targets": 745655,
            "calls": 83,
            "jumps": 12,
        }
        if counts != expected:
            raise SystemExit(
                f"Hello V2 guest-dispatch reuse changed: {counts!r} != {expected!r}"
            )
        if sorted(len(row.target_rvas) for row in domains) != [7849]:
            raise SystemExit("Hello V2 admitted domains lost exact transfer coverage")
        PY
        touch "$out"
      '';
  semanticModuleV2NativeIngressCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-linked-semantic-module-v2-native-ingress-check"
      {
        nativeBuildInputs = [
          pkgs.jq
          sdk.validation.pythonEnv
        ];
      }
      ''
        set -euo pipefail
        module=${workflow.linkedSemanticModule.linkedSemanticModule}
        export PYTHONPATH=${sdk.sources.fullSource}/src
        python - "$module" "$TMPDIR/ingress" <<'PY'
        import sys
        from pathlib import Path

        from spaghetti_extractor.candidate.native_ingress_plan import (
            write_native_ingress_plan_from_linked_module,
        )

        write_native_ingress_plan_from_linked_module(
            linked_semantic_module=Path(sys.argv[1]),
            out=Path(sys.argv[2]),
        )
        PY
        ingress="$TMPDIR/ingress/native-ingress-plan.json"
        jq -e '
          .format == "spaghetti-extractor-native-ingress-plan-v2" and
          .status == "complete" and
          (.ingresses | length) == 3 and
          ([.ingresses[] | select(.role == "callback")] | length) == 0 and
          (.bridges | length) == 3 and
          (.callback_domains | length) == 4 and
          ([.callback_domains[].protocol_id] | unique | length) == 4 and
          ([.callback_domains[].target_rvas | length] | unique) == [7849] and
          ([.callback_domains[].outcome_groups | length] | unique) == [3] and
          (.callback_publications | length) == 14 and
          ([.callback_publications[].domain_id] | unique | length) == 4 and
          (.callback_bridge_families | length) == 4 and
          ([.callback_bridge_families[].cleanup_bytes] | sort) ==
            [0, 0, 0, 4] and
          ([.callback_domains[].trampoline_stride_bytes] | unique) == [10] and
          (.code_target_registry | length) == 7849 and
          (.outcome_protocols | length) == 4 and
          (.seh_protocols | length) == 4 and
          .required_support_imports == [{
            dll: "kernel32.dll",
            ordinal: null,
            ownership: "runtime_support",
            purpose: "checked_exception_escape",
            symbol: "RaiseException"
          }] and
          .blockers == [] and
          (.runtime_requirements.features | index(
            "compact_callback_domains_v1"
          )) != null and
          ([.callback_domains[] | .physical_transducer.transducer_sha256]
            | unique | length) == 4 and
          ([.callback_domains[] | .lifecycle_transducer.transducer_sha256]
            | unique | length) == 4
        ' "$ingress" >/dev/null
        test "$(stat -c %s "$ingress")" -lt 3000000
        mkdir -p "$out"
        cp "$ingress" "$out/native-ingress-plan.json"
      '';
  generatedSemanticProviderV2 = workflow.generatedSemanticProvider;
  generatedSemanticProviderV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-generated-c-provider-v2-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        qualification=${generatedSemanticProviderV2}/semantic-provider-qualification.json
        choices=${generatedSemanticProviderV2}/definition-choices.json
        jq -e '
          .format ==
            "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "generated_behavioral_c" and
          .blockers == [] and
          (.semantic_slice.definitions | length) == 7849 and
          (.semantic_slice.obligations | length) == 0 and
          (.definition_materializations | length) == 7849 and
          (.obligation_implementations | length) == 0 and
          (.tool_sha256s | length) == 1
        ' "$qualification" >/dev/null
        test "$(jq 'length' "$choices")" -eq 7849
        # One object is emitted per derived behavioral function. Multiple
        # transfer definitions in the same function intentionally select the
        # same exact object materialization.
        test "$(find ${generatedSemanticProviderV2}/objects -maxdepth 1 \
          -type f -name '*.o' | wc -l)" -eq 294
        test "$(jq '[.definition_materializations[].object_sha256s[]] |
          unique | length' "$qualification")" -eq 294
        touch "$out"
      '';
  externalEnvironmentProviderV2 = workflow.externalSemanticProvider;
  externalEnvironmentProviderV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-external-environment-provider-v2-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        qualification=${externalEnvironmentProviderV2}/semantic-provider-qualification.json
        jq -e '
          .format ==
            "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "external_environment" and
          .blockers == [] and
          (.semantic_slice.definitions | length) == 151 and
          (.definition_materializations | length) == 151 and
          (.semantic_slice.obligations | length) == 0 and
          .tool_sha256s == []
        ' "$qualification" >/dev/null
        test "$(jq 'length' \
          ${externalEnvironmentProviderV2}/definition-choices.json)" -eq 151
        touch "$out"
      '';
  qualifiedRuntimeProviderV2 = workflow.runtimeSemanticProvider;
  qualifiedRuntimeProviderV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-qualified-runtime-provider-v2-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        qualification=${qualifiedRuntimeProviderV2}/semantic-provider-qualification.json
        jq -e '
          .format ==
            "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_runtime" and
          .blockers == [] and
          (.semantic_slice.definitions | length) == 19 and
          (.semantic_slice.obligations | length) == 109 and
          (.definition_materializations | length) == 19 and
          (.obligation_implementations | length) == 109 and
          (.tool_sha256s | length) == 1
        ' "$qualification" >/dev/null
        jq -e '
          (.definitions | length) == 19 and
          (.obligations | length) == 109
        ' ${qualifiedRuntimeProviderV2}/implementation-choices.json >/dev/null
        test -s ${qualifiedRuntimeProviderV2}/native-ingress-plan.json
        test -s ${qualifiedRuntimeProviderV2}/native-realization-object-manifest.json
        touch "$out"
      '';
  semanticImplementationSelectionV2 = workflow.semanticImplementationSelections.faithful;
  semanticImplementationSelectionV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-implementation-selection-v2-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        selection=${semanticImplementationSelectionV2.artifact}
        jq -e '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and
          .ready_for_realization == true and
          .mode == "faithful" and
          .blockers == [] and
          (.qualification_sha256s | length) == 3 and
          (.definition_selections | length) == 8019 and
          (.obligation_selections | length) == 109 and
          ([.definition_selections[].provider_kind] | unique | sort) ==
            ["external_environment", "generated_behavioral_c", "qualified_runtime"] and
          ([.obligation_selections[].provider_kind] | unique) ==
            ["qualified_runtime"]
        ' "$selection" >/dev/null
        touch "$out"
      '';
  nativeRealizationV2 = workflow.nativeRealizations.faithful;
  nativeRealizationV2Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-native-realization-v2-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        receipt=${nativeRealizationV2.receipt}
        jq -e '
          .format == "spaghetti-extractor-native-realization-v2" and
          .status == "complete" and
          .ready_for_observation == true and
          .blockers == [] and
          (.providers | length) == 3 and
          (.definitions | length) == 8019 and
          (.obligations | length) == 109 and
          (.native_objects | length) == 305 and
          ([.obligations[].provider_kind] | unique) ==
            ["qualified_runtime"] and
          (.runtime.required_symbols | length) > 5 and
          (.runtime.obligation_receipt_sha256s | length) == 109 and
          .candidate.filename == "hello.exe" and
          (.candidate.size > 0)
        ' "$receipt" >/dev/null
        test -s ${nativeRealizationV2.candidate}
        test -s ${nativeRealizationV2.candidateInterface}
        touch "$out"
      '';
  asciiToLowerV6Provider = workflow.portableSemanticProvidersByComponent.ascii-to-lower;
  asciiToLowerV6Selection = workflow.semanticImplementationSelections.ascii-to-lower-enabled;
  asciiToLowerV6Realization = workflow.nativeRealizations.ascii-to-lower-enabled;
  asciiToLowerV6Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-ascii-to-lower-v6-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        qualification=${asciiToLowerV6Provider.qualification}
        contextual=${asciiToLowerV6Provider.contextualRefinement}
        selection=${asciiToLowerV6Selection.artifact}
        realization=${asciiToLowerV6Realization.receipt}
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_portable_c" and
          (.definition_materializations | length) == 1 and
          ([.facets[].status] | unique) == ["checked"] and
          .blockers == []
        ' "$qualification" >/dev/null
        jq -e '
          .status == "satisfied" and
          .proof.status == "satisfied" and
          .policy == {cbmc_required: true, tests_authorize: false}
        ' "$contextual" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and
          .mode == "hybrid" and
          ([.definition_selections[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 1 and
          .blockers == []
        ' "$selection" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-native-realization-v2" and
          .status == "complete" and
          .ready_for_observation == true and
          ([.definitions[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 1 and
          .blockers == []
        ' "$realization" >/dev/null
        test -s ${asciiToLowerV6Realization.candidate}
        touch "$out"
      '';
  startupCallbackV6Provider =
    workflow.portableSemanticProvidersByComponent.startup-callback-registration;
  startupCallbackV6Selection = workflow.semanticImplementationSelections.startup-callback-enabled;
  startupCallbackV6Realization = workflow.nativeRealizations.startup-callback-enabled;
  startupCallbackV6Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-startup-callback-v6-check"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.ripgrep
        ];
      }
      ''
        set -euo pipefail
        qualification=${startupCallbackV6Provider.qualification}
        contextual=${startupCallbackV6Provider.contextualRefinement}
        selection=${startupCallbackV6Selection.artifact}
        realization=${startupCallbackV6Realization.receipt}
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_portable_c" and
          (.semantic_slice.definitions | length) == 1 and
          (.semantic_slice.obligations | length) == 0 and
          (.semantic_slice.dependency_contract_sha256s | length) == 4 and
          (.definition_materializations | length) == 1 and
          ([.facets[].status] | unique) == ["checked"] and
          .blockers == []
        ' "$qualification" >/dev/null
        jq -e '
          .status == "satisfied" and
          .proof.status == "satisfied" and
          .policy == {cbmc_required: true, tests_authorize: false}
        ' "$contextual" >/dev/null
        rg -q 'spx_native_code_bridge_address\(UINT32_C\(43424\)\)' \
          ${startupCallbackV6Provider.derivation}/component-object/generated/component-machine-overlay.c
        jq -e '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and
          .mode == "hybrid" and
          ([.definition_selections[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 1 and
          ([.obligation_selections[] | select(
            .provider_kind == "qualified_runtime")] | length) == 109 and
          .blockers == []
        ' "$selection" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-native-realization-v2" and
          .status == "complete" and
          .ready_for_observation == true and
          ([.definitions[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 1 and
          ([.obligations[] | select(
            .provider_kind == "qualified_runtime")] | length) == 109 and
          .blockers == []
        ' "$realization" >/dev/null
        test -s ${startupCallbackV6Realization.candidate}
        touch "$out"
      '';
  programNameSelectionV6Provider =
    workflow.portableSemanticProvidersByComponent.program-name-selection;
  memoryRegionsEqualV6Provider = workflow.portableSemanticProvidersByComponent.memory-regions-equal;
  programNameSelectionV6Selection =
    workflow.semanticImplementationSelections.program-name-selection-enabled;
  programNameSelectionV6Realization = workflow.nativeRealizations.program-name-selection-enabled;
  programNameSelectionV6Check =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-program-name-selection-v6-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        program_qualification=${programNameSelectionV6Provider.qualification}
        program_contextual=${programNameSelectionV6Provider.contextualRefinement}
        memory_qualification=${memoryRegionsEqualV6Provider.qualification}
        selection=${programNameSelectionV6Selection.artifact}
        realization=${programNameSelectionV6Realization.receipt}
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_portable_c" and
          (.semantic_slice.definitions | length) == 14 and
          (.definition_materializations | length) == 14 and
          ([.facets[] | select(.name == "relations") | .status] == ["checked"]) and
          ([.facets[].status] | unique) == ["checked"] and
          ([.dependencies[] | select(startswith("interaction-contract:"))] | length) == 1 and
          ([.dependencies[] | select(startswith("interaction-receipt:"))] | length) == 1 and
          .blockers == []
        ' "$program_qualification" >/dev/null
        jq -e '
          .status == "satisfied" and
          .proof.status == "satisfied" and
          (.relation_evidence | length) == 1 and
          .relation_evidence[0].contract_id ==
            "c-runtime.strrchr.borrowed-interior-v1" and
          .relation_evidence[0].input_argument_index == 0 and
          .policy == {cbmc_required: true, tests_authorize: false}
        ' "$program_contextual" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
          .status == "complete" and
          .provider_kind == "qualified_portable_c" and
          (.semantic_slice.definitions | length) == 2 and
          (.definition_materializations | length) == 2 and
          ([.facets[].status] | unique) == ["checked"] and
          .blockers == []
        ' "$memory_qualification" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and
          .mode == "hybrid" and
          ([.definition_selections[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 16 and
          ([.obligation_selections[] | select(
            .provider_kind == "qualified_runtime")] | length) == 109 and
          .blockers == []
        ' "$selection" >/dev/null
        jq -e '
          .format == "spaghetti-extractor-native-realization-v2" and
          .status == "complete" and
          .ready_for_observation == true and
          ([.definitions[] | select(
            .provider_kind == "qualified_portable_c")] | length) == 16 and
          ([.obligations[] | select(
            .provider_kind == "qualified_runtime")] | length) == 109 and
          .blockers == []
        ' "$realization" >/dev/null
        test -s ${programNameSelectionV6Realization.candidate}
        touch "$out"
      '';
  stringPointerV6ProviderSet = workflow.portableSemanticProviderSets.string-pointer-enabled;
  stringPointerV6SelectedIds =
    workflow.components.selectedComponentIdsByConfiguration.string-pointer-enabled;
  stringPointerDirectBisimulationCheck =
    assert stringPointerV6ProviderSet.directIds == stringPointerV6SelectedIds;
    pkgs.runCommand "spaghetti-extractor-gnu-hello-string-pointer-direct-bisimulation-v6-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        for provider in ${pkgs.lib.concatMapStringsSep " "
          (componentId:
            workflow.portableSemanticProvidersByComponent.${componentId}.derivation)
          stringPointerV6SelectedIds}; do
          jq -e '
            .format == "spaghetti-extractor-semantic-provider-qualification-v2" and
            .status == "complete" and
            .provider_kind == "qualified_portable_c" and
            ([.facets[] | select(.name == "bisimulation") | .status] == ["checked"]) and
            .blockers == []
          ' "$provider/semantic-provider-qualification.json" >/dev/null
          jq -L ${../../nix/jq} -e '
            include "strong-contextual-proof";
            .status == "satisfied" and
            .proof.status == "satisfied" and
            .proof.activation_authorized == true and
            spx_strong_contextual_proof and
            ([.proof.shards[].nonvacuity.status] | all(. == "satisfied")) and
            .policy == {cbmc_required: true, tests_authorize: false}
          ' "$provider/contextual-refinement-result.json" >/dev/null
          jq -L ${../../nix/jq} -e '
            include "strong-contextual-proof";
            spx_strong_cutpoint_plan
          ' "$provider/component-proof-plan-v1.json" >/dev/null
          jq -L ${../../nix/jq} -e '
            include "strong-contextual-proof";
            spx_contextual_exact_c_slice
          ' "$provider/exact-c/component-exact-c-slice-v1.json" >/dev/null
        done
        touch "$out"
      '';
  stringPointerV6Selection =
    workflow.semanticImplementationSelections.string-pointer-enabled;
  stringPointerV6Realization = workflow.nativeRealizations.string-pointer-enabled;
  stringPointerV6LinkageCheck =
    pkgs.runCommand "spaghetti-extractor-gnu-hello-string-pointer-v6-linkage-check"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        set -euo pipefail
        selection=${stringPointerV6Selection.artifact}
        realization=${stringPointerV6Realization.receipt}
        expected_provider_ids=${pkgs.lib.escapeShellArg (builtins.toJSON (
          map (componentId: "gnu-hello.${componentId}.portable-c")
            stringPointerV6SelectedIds
        ))}
        selection_sha256="$(jq -r '.selection_sha256' "$selection")"

        jq -e --argjson provider_ids "$expected_provider_ids" '
          .format == "spaghetti-extractor-implementation-selection-v2" and
          .status == "complete" and
          .ready_for_realization == true and
          .mode == "hybrid" and
          .blockers == [] and
          ([.definition_selections[] | select(
            .provider_kind == "qualified_portable_c"
          ) | .provider_id] | unique | sort) == ($provider_ids | sort) and
          ([.definition_selections[] | select(
            .provider_kind == "qualified_portable_c"
          )] | length) > ($provider_ids | length) and
          ([.obligation_selections[].provider_kind] | unique) ==
            ["qualified_runtime"]
        ' "$selection" >/dev/null

        jq -e \
          --arg selection_sha256 "$selection_sha256" \
          --argjson provider_ids "$expected_provider_ids" '
          .format == "spaghetti-extractor-native-realization-v2" and
          .status == "complete" and
          .ready_for_observation == true and
          .blockers == [] and
          .bindings.implementation_selection_sha256 == $selection_sha256 and
          ([.definitions[] | select(
            .provider_kind == "qualified_portable_c"
          ) | .provider_id] | unique | sort) == ($provider_ids | sort) and
          ([.definitions[] | select(
            .provider_kind == "qualified_portable_c"
          )] | all(.implementation_rva > 0)) and
          ([.native_objects[] | select(.role == "portable_c") |
            .provider_ids[]] | unique | sort) == ($provider_ids | sort) and
          .portable_dispatch_link_receipt.status == "complete" and
          .portable_dispatch_link_receipt.activation_authorized == true and
          .portable_dispatch_link_receipt.blockers == [] and
          .portable_dispatch_link_receipt.policy.source_only_authority == false and
          .portable_dispatch_link_receipt.bindings.implementation_selection_sha256 ==
            $selection_sha256 and
          .portable_dispatch_link_receipt.bindings.payload_sha256 ==
            .link.payload_sha256 and
          .portable_dispatch_link_receipt.bindings.linker_map_sha256 ==
            .link.linker_map_sha256 and
          ([.portable_dispatch_link_receipt.entries[].provider_id] |
            unique | sort) == ($provider_ids | sort) and
          ([.portable_dispatch_link_receipt.entries[]] |
            all(.linked_rva > 0 and
                (.implementation_object_sha256 | length) == 64)) and
          .portable_dispatch_link_receipt.registry != null and
          .candidate.filename == "hello.exe" and
          .candidate.size > 0
        ' "$realization" >/dev/null
        test -s ${stringPointerV6Realization.candidate}
        test -s ${stringPointerV6Realization.candidateInterface}
        touch "$out"
      '';
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow candidateTests;
  inputs.original = original;
  extraArtifacts.hello-derived-registration-linked-check = registrationFixtureLinkedCheck;
  extraArtifacts.hello-derived-registration-semantic-object = registrationFixtureSemanticObjectCheck;
  extraArtifacts.hello-derived-registration-provider = registrationFixtureProviderCheck;
  extraArtifacts.hello-derived-registration-native-realization =
    registrationFixtureWorkflow.nativeRealizations.faithful.derivation;
  extraArtifacts.hello-derived-registration-linked-semantic-module =
    registrationFixtureWorkflow.linkedSemanticModule.derivation;
  extraArtifacts.hello-native-ingress-exception = nativeIngressExceptionalCheck;
  extraArtifacts.hello-linked-semantic-module-v2 = workflow.linkedSemanticModule.derivation;
  extraArtifacts.hello-linked-semantic-module-v2-check = semanticModuleV2Check;
  extraArtifacts.hello-linked-semantic-module-v2-native-ingress-check =
    semanticModuleV2NativeIngressCheck;
  extraArtifacts.hello-generated-behavioral-c-provider-v2 = generatedSemanticProviderV2;
  extraArtifacts.hello-generated-behavioral-c-provider-v2-check = generatedSemanticProviderV2Check;
  extraArtifacts.hello-external-environment-provider-v2 = externalEnvironmentProviderV2;
  extraArtifacts.hello-external-environment-provider-v2-check = externalEnvironmentProviderV2Check;
  extraArtifacts.hello-qualified-runtime-provider-v2 = qualifiedRuntimeProviderV2;
  extraArtifacts.hello-qualified-runtime-provider-v2-check = qualifiedRuntimeProviderV2Check;
  extraArtifacts.hello-implementation-selection-v2 = semanticImplementationSelectionV2.derivation;
  extraArtifacts.hello-implementation-selection-v2-check = semanticImplementationSelectionV2Check;
  extraArtifacts.hello-native-realization-v2 = nativeRealizationV2.derivation;
  extraArtifacts.hello-native-realization-v2-check = nativeRealizationV2Check;
  extraArtifacts.hello-ascii-to-lower-v6-provider = asciiToLowerV6Provider.derivation;
  extraArtifacts.hello-ascii-string-compare-v6-provider =
    workflow.portableSemanticProvidersByComponent.ascii-string-compare.derivation;
  extraArtifacts.hello-ascii-to-lower-library-provider = asciiToLowerLibraryProvider.derivation;
  extraArtifacts.hello-ascii-to-lower-v6-native-realization = asciiToLowerV6Realization.derivation;
  extraArtifacts.hello-startup-callback-v6-provider = startupCallbackV6Provider.derivation;
  extraArtifacts.hello-startup-callback-v6-native-realization =
    startupCallbackV6Realization.derivation;
  extraArtifacts.hello-program-name-selection-v6-provider = programNameSelectionV6Provider.derivation;
  extraArtifacts.hello-memory-regions-equal-v6-provider = memoryRegionsEqualV6Provider.derivation;
  extraArtifacts.hello-program-name-selection-v6-native-realization =
    programNameSelectionV6Realization.derivation;
  extraArtifacts.hello-string-pointer-direct-bisimulation-v6 =
    stringPointerDirectBisimulationCheck;
  extraArtifacts.hello-string-pointer-v6-native-realization =
    stringPointerV6Realization.derivation;
  extraArtifacts.hello-string-pointer-v6-linkage-check =
    stringPointerV6LinkageCheck;
  extraArtifacts.hello-linked-semantic-module-independent-replay =
    workflow.linkedSemanticModule.replayCheck;
  extraArtifacts.hello-executable-transfer-plan = workflow.transferPlan.derivation;
  extraArtifacts.hello-semantic-object = workflow.semanticObject.derivation;
  extraArtifacts.hello-semantic-object-real-scale = semanticObjectRealHelloCheck;
  targetAssets.documentation = [ "intent/libraries/README.md" ];
  targetAssets.library_provider = [
    "intent/libraries/ascii-to-lower-provider/implementation.json"
    "intent/libraries/ascii-to-lower-provider/qualification.json"
    "intent/libraries/ascii-to-lower-provider/source-package/source-package.json"
    "intent/libraries/ascii-to-lower-provider/source-package/sources/ascii-to-lower.c"
  ];
  checks = v6ComponentChecks // {
    # Work packages are non-authorizing operator projections.  Exercise one
    # representative package in the target regression without forcing every
    # component's presentation artifact into candidate-oriented checks.
    hello-component-work-package-v6 = components.v6WorkPackages.ascii-string-compare.derivation;
    hello-derived-registration-linked-check = registrationFixtureLinkedCheck;
    hello-derived-registration-semantic-object = registrationFixtureSemanticObjectCheck;
    hello-derived-registration-provider = registrationFixtureProviderCheck;
    hello-derived-registration-candidate =
      candidateTests."gnu-hello-derived-registration-candidate".aggregate;
    hello-native-ingress-exception = nativeIngressExceptionalCheck;
    hello-linked-semantic-module-v2 = semanticModuleV2Check;
    hello-linked-semantic-module-v2-native-ingress = semanticModuleV2NativeIngressCheck;
    hello-generated-behavioral-c-provider-v2 = generatedSemanticProviderV2Check;
    hello-external-environment-provider-v2 = externalEnvironmentProviderV2Check;
    hello-qualified-runtime-provider-v2 = qualifiedRuntimeProviderV2Check;
    hello-implementation-selection-v2 = semanticImplementationSelectionV2Check;
    hello-native-realization-v2 = nativeRealizationV2Check;
    hello-ascii-to-lower-v6 = asciiToLowerV6Check;
    hello-ascii-to-lower-library-provider = asciiToLowerLibraryProviderCheck;
    hello-ascii-to-lower-v6-candidate =
      candidateTests."gnu-hello-ascii-to-lower-v6-candidate".aggregate;
    hello-startup-callback-v6 = startupCallbackV6Check;
    hello-startup-callback-v6-candidate =
      candidateTests."gnu-hello-startup-callback-v6-candidate".aggregate;
    hello-program-name-selection-v6 = programNameSelectionV6Check;
    hello-program-name-selection-v6-candidate =
      candidateTests."gnu-hello-program-name-selection-v6-candidate".aggregate;
    hello-string-pointer-direct-bisimulation-v6 =
      stringPointerDirectBisimulationCheck;
    hello-string-pointer-v6-linkage = stringPointerV6LinkageCheck;
    hello-string-pointer-v6-candidate =
      candidateTests."gnu-hello-string-pointer-v6-candidate".aggregate;
    hello-candidate-v2 = candidateTests."gnu-hello-default-candidate".aggregate;
    hello-semantic-object-real-scale = semanticObjectRealHelloCheck;
  };
}
