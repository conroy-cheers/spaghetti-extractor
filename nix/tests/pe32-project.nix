# spaghetti-extractor-python-role: developer
{ pkgs, pythonEnv }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  transferPythonEnv = context.transferPythonEnv;
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
  pythonSource = import ../python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.candidate.module_composer"
      "spaghetti_extractor.candidate.project"
      "spaghetti_extractor.roundtrip_fuzz.image_io"
    ];
    name = "spaghetti-extractor-pe32-project-fixture-python-closure";
  };
  fixture = pkgs.runCommand "spaghetti-extractor-pe32-project-fixture" {
    nativeBuildInputs = [ compiler pythonEnv ];
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONPATH=${pythonSource.pythonPath}
    mkdir -p "$out/app" "$out/private"
    cp ${./fixtures/pe32-project-app.c} app.c
    cp ${./fixtures/pe32-project-private.c} private.c
    cp ${./fixtures/pe32-project-private.def} private.def
    # MinGW derives a DLL's default image base from its output pathname. Keep
    # that pathname stable across content-addressed builds, then install it.
    ${compiler}/bin/i686-w64-mingw32-gcc -shared private.c private.def \
      -Wl,--out-implib,libprivate.a -o private.dll
    ${compiler}/bin/i686-w64-mingw32-gcc app.c -L. -lprivate \
      -o app.exe
    cp private.dll "$out/private/private.dll"
    cp app.exe "$out/app/app.exe"
    ${pythonEnv}/bin/python3 - "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.roundtrip_fuzz.image_io import (
        write_spx_load_image_contract,
    )

    root = pathlib.Path(sys.argv[1])
    write_spx_load_image_contract(
        original_pe=root / "app" / "app.exe",
        out=root / "app" / "load-image-contract.json",
    )
    write_spx_load_image_contract(
        original_pe=root / "private" / "private.dll",
        out=root / "private" / "load-image-contract.json",
    )
    PY
  '';
  appInterface = import ../pe32-module-interface.nix {
    inherit pkgs pythonEnv;
    original = "${fixture}/app/app.exe";
    staticExport = "${fixture}/app";
    imageId = "app";
    namePrefix = "spaghetti-extractor-pe32-project-app-fixture";
  };
  privateInterface = import ../pe32-module-interface.nix {
    inherit pkgs pythonEnv;
    original = "${fixture}/private/private.dll";
    staticExport = "${fixture}/private";
    imageId = "private";
    namePrefix = "spaghetti-extractor-pe32-project-private-fixture";
  };
  semanticInputsFor = imageId: original: moduleInterface:
    import ../ca-python-json-phase.nix {
      inherit pkgs pythonEnv;
      name = "spaghetti-extractor-pe32-project-${imageId}-semantic-inputs";
      kind = "pe32-project-semantic-inputs";
      artifactName = "executable-transfer-plan.json";
      expectedFormat = "spaghetti-extractor-executable-transfer-plan-v2";
      allowedStatuses = [ "complete" ];
      pythonModules = [
        "spaghetti_extractor.testkit.project_semantic_fixture"
      ];
      phaseRole = "developer";
      inputs = {
        original_pe = original;
        module_interface = moduleInterface;
      };
      program = ''
        import shutil

        from spaghetti_extractor.testkit.project_semantic_fixture import (
            write_project_semantic_inputs,
        )

        artifacts = write_project_semantic_inputs(
            original_pe=inputs["original_pe"],
            module_interface=inputs["module_interface"],
            out=output.parent,
        )
        shutil.copyfile(artifacts["transfer_plan"], output)
      '';
    };
  appSemanticInputs = semanticInputsFor
    "app" "${fixture}/app/app.exe" "${appInterface}/module-interface.json";
  privateSemanticInputs = semanticInputsFor
    "private" "${fixture}/private/private.dll"
    "${privateInterface}/module-interface.json";
  semanticObjectFor = imageId: semanticInputs: moduleInterface:
    import ../semantic-object.nix {
      inherit pkgs pythonEnv;
      transferPlan = semanticInputs.artifact;
      inherit moduleInterface;
      resolvedExternalEnvironment = semanticInputs.derivation + "/environment";
      namePrefix = "spaghetti-extractor-pe32-project-${imageId}-fixture";
    };
  appSemanticObject = semanticObjectFor
    "app" appSemanticInputs "${appInterface}/module-interface.json";
  privateSemanticObject = semanticObjectFor
    "private" privateSemanticInputs "${privateInterface}/module-interface.json";
  linkedModuleFor = imageId: semanticObject:
    import ../linked-semantic-module.nix {
      inherit pkgs;
      pythonEnv = transferPythonEnv;
      semanticObject = semanticObject.artifact;
      namePrefix = "spaghetti-extractor-pe32-project-${imageId}-fixture";
    };
  appLinkedModule = linkedModuleFor "app" appSemanticObject;
  privateLinkedModule = linkedModuleFor "private" privateSemanticObject;
  intent = pkgs.writeText "spaghetti-extractor-pe32-project-fixture-intent.json"
    (builtins.toJSON {
      format = "spaghetti-extractor-pe32-project-intent-v1";
      project_id = "nix-multi-image-fixture";
      root_image_id = "app";
      target_distribution_roots = [ "bin" ];
      host_environment = {
        id = "fixture-host";
        sha256 = builtins.hashString "sha256" "fixture-host-v1";
      };
      images = [
        {
          image_id = "app";
          filename = "app.exe";
          aliases = [ ];
          ownership = "target";
          implementation = "behavioral_c";
        }
        {
          image_id = "private";
          filename = "private.dll";
          aliases = [ ];
          ownership = "target";
          implementation = "behavioral_c";
        }
        {
          image_id = "kernel32";
          filename = "kernel32.dll";
          aliases = [ "kernelbase.dll" ];
          ownership = "runtime";
          implementation = "native_host";
        }
      ];
    });
  loadPlan = import ../pe32-project-load-plan.nix {
    inherit pkgs pythonEnv intent;
    linkedSemanticModules = {
      app = appLinkedModule.linkedSemanticModule;
      private = privateLinkedModule.linkedSemanticModule;
    };
    namePrefix = "spaghetti-extractor-pe32-project-fixture";
  };
  observation = pkgs.runCommand "spaghetti-extractor-pe32-project-fixture-observation" {
    nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
    __contentAddressed = true;
  } ''
    set -euo pipefail
    app_sha="$(sha256sum ${fixture}/app/app.exe | cut -d' ' -f1)"
    private_sha="$(sha256sum ${fixture}/private/private.dll | cut -d' ' -f1)"
    jq -n \
      --slurpfile plan ${loadPlan}/project-load-plan.json \
      --slurpfile appInterface ${appInterface}/module-interface.json \
      --slurpfile privateInterface ${privateInterface}/module-interface.json \
      --arg appSha "$app_sha" --arg privateSha "$private_sha" '
      {
        format: "spaghetti-extractor-pe32-load-observation-v2",
        project_id: $plan[0].project_id,
        environment_sha256: $plan[0].host_environment.sha256,
        runner_sha256: ("2" * 64),
        trace_sha256: ("3" * 64),
        process_exit_code: 0,
        modules: [
          {
            loader_name: "app.exe", resolved_path: "C:/fixture/app.exe",
            sha256: $appSha, origin: "target_distribution", image_id: "app",
            loaded_base: $appInterface[0].loader.preferred_base
          },
          {
            loader_name: "private.dll", resolved_path: "C:/fixture/private.dll",
            sha256: $privateSha, origin: "target_distribution", image_id: "private",
            loaded_base: $privateInterface[0].loader.preferred_base
          }
        ],
        slots: ($plan[0].edges | map({
          slot_id,
          resolution: (
            if (.resolution.kind | startswith("target_")) then
              {kind: "target_image", provider_image_id: .resolution.provider_image_id}
            else
              {kind: "host_loader", environment_sha256: $plan[0].host_environment.sha256}
            end
          )
        }))
      }
    ' > "$out"
  '';
  observedGraph = import ../pe32-observed-load-graph.nix {
    inherit pkgs pythonEnv loadPlan observation;
    namePrefix = "spaghetti-extractor-pe32-project-fixture";
  };
  realizationFor = imageId: candidate: filename: pkgs.runCommand
    "spaghetti-extractor-pe32-project-${imageId}-realization-fixture" {
      nativeBuildInputs = [ pythonEnv pkgs.coreutils ];
    } ''
      mkdir -p "$out"
      export PYTHONPATH=${pythonSource.pythonPath}
      ${pythonEnv}/bin/python3 - ${candidate} "$out/native-realization.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.util import sha256_file, write_json

      candidate = pathlib.Path(sys.argv[1])
      digest = sha256_file(candidate)
      provider = "fixture.provider"
      symbol = "fixture:entry"
      portable_dispatch_core = {
          "format": "spaghetti-extractor-portable-dispatch-link-receipt-v1",
          "status": "complete",
          "activation_authorized": True,
          "bindings": {
              "implementation_selection_sha256": "2" * 64,
              "payload_sha256": "b" * 64,
              "linker_map_sha256": "c" * 64,
          },
          "registry": None,
          "entries": [],
          "policy": {
              "strong_module_registry_required_when_portable": True,
              "one_strong_implementation_symbol_per_entry": True,
              "exact_selected_object_membership_required": True,
              "contextual_bisimulation_authority_required": True,
              "weak_or_duplicate_fallback_forbidden": True,
              "source_only_authority": False,
          },
          "blockers": [],
      }
      core = {
          "format": "spaghetti-extractor-native-realization-v2",
          "status": "complete",
          "ready_for_observation": True,
          "bindings": {
              "linked_semantic_module_sha256": "1" * 64,
              "implementation_selection_sha256": "2" * 64,
              "qualified_platform_sha256": "3" * 64,
              "original_module_interface_sha256": "4" * 64,
          },
          "providers": [{
              "provider_id": provider,
              "provider_kind": "generated_behavioral_c",
              "qualification_sha256": "5" * 64,
              "artifact_sha256": "6" * 64,
              "semantic_slice_sha256": "7" * 64,
              "tool_sha256s": ["8" * 64],
              "definition_ids": ["definition:entry"],
              "obligation_ids": [],
          }],
          "definitions": [{
              "definition_id": "definition:entry",
              "symbol_id": symbol,
              "provider_id": provider,
              "provider_kind": "generated_behavioral_c",
              "qualification_sha256": "5" * 64,
              "native_symbol": "fixture_entry",
              "address": {"kind": "linked_rva", "rva": 4096},
              "implementation_rva": 4096,
              "bridge_class_id": None,
          }],
          "obligations": [],
          "native_objects": [{
              "object_sha256": "8" * 64,
              "role": "generated_behavioral_c",
              "provider_ids": [provider],
              "definition_ids": ["definition:entry"],
              "obligation_ids": [],
              "section_ids": [".text"],
          }],
          "bridges": [],
          "runtime": {
              "qualification_sha256": "9" * 64,
              "tls_layout_sha256": "a" * 64,
              "private_stack_size": 1048576,
              "support_import_ids": [],
              "required_symbols": [{
                  "symbol": "fixture_entry",
                  "rva": 4096,
                  "role": "entry",
              }],
              "obligation_receipt_sha256s": [],
          },
          "link": {
              "payload_sha256": "b" * 64,
              "linker_map_sha256": "c" * 64,
              "relocation_inventory_sha256": "d" * 64,
              "section_table_sha256": "e" * 64,
              "entry_symbols": ["fixture_entry"],
          },
          "portable_dispatch_link_receipt": {
              **portable_dispatch_core,
              "receipt_sha256": canonical_sha256_v3(portable_dispatch_core),
          },
          "loader_surface": {
              "entry_rva": 4096,
              "exports_sha256": "f" * 64,
              "imports_sha256": "0" * 64,
              "tls_sha256": "1" * 64,
              "base_relocations_sha256": "2" * 64,
              "resources_sha256": None,
              "load_config_sha256": None,
          },
          "candidate": {
              "filename": ${builtins.toJSON filename},
              "sha256": digest,
              "size": candidate.stat().st_size,
              "module_interface_sha256": "3" * 64,
          },
          "pinned_code_layout_requirements": [],
          "blockers": [],
      }
      write_json(pathlib.Path(sys.argv[2]), {
          **core,
          "native_realization_sha256": canonical_sha256_v3(core),
      })
      PY
    '';
  completion = import ../pe32-project-completion.nix {
    inherit pkgs pythonEnv loadPlan;
    nativeRealizations = {
      app = realizationFor "app" "${fixture}/app/app.exe" "app.exe";
      private = realizationFor "private" "${fixture}/private/private.dll" "private.dll";
    };
    observedLoadGraph = "${observedGraph}/observed-load-graph.json";
    namePrefix = "spaghetti-extractor-pe32-project-fixture";
  };
in
pkgs.runCommand "spaghetti-extractor-pe32-project-check" {
  nativeBuildInputs = [
    pkgs.jq
    pkgs.wineWow64Packages.stableFull
    context.tools.headlessWayland
  ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  jq -e '
    .status == "complete" and
    .counts.images == 3 and
    .counts.target_images == 2 and
    .counts.target_edges == 2 and
    .counts.host_edges >= 1 and
    ([.edges[] | select(.resolution.kind == "target_image") |
      .resolution.export.kind] | sort) == ["code", "data"]
  ' ${loadPlan}/project-load-plan.json >/dev/null
  jq -e '.status == "qualified" and (.blockers | length) == 0' \
    ${observedGraph}/observed-load-graph.json >/dev/null
  jq -e '.status == "complete" and (.blockers | length) == 0' \
    ${completion}/project-completion.json >/dev/null
  jq -e '
    .status == "complete" and
    .counts.export_slots == 12 and
    .counts.export_names == 10 and
    .counts.data_exports == 7 and
    .counts.tls_callbacks >= 2 and
    .export_directory.ordinal_base == 3 and
    .export_directory.holes == [
      {ordinal: 5, slot_index: 2}
    ] and
    ([.export_directory.slots[].kind] | index("forwarder")) != null
  ' ${privateInterface}/module-interface.json >/dev/null
  export WINEPREFIX="$TMPDIR/wine"
  export WINEDEBUG=-all
  export WINEDLLOVERRIDES="mscoree,mshtml="
  mkdir -p distribution
  cp ${fixture}/app/app.exe distribution/
  cp ${fixture}/private/private.dll distribution/
  (cd distribution && spaghetti-headless-wayland ${pkgs.bash}/bin/bash -eu -c '
    wineboot -u >/dev/null 2>&1
    set +e
    timeout 60 wine ./app.exe
    status=$?
    set -e
    wineserver -w >/dev/null 2>&1 || true
    exit "$status"
  ')
  touch "$out"
''
