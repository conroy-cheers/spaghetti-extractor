# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv }:

let
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
  pythonSource = import ../python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.candidate.module_composer"
      "spaghetti_extractor.candidate.native_ingress"
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
    export PYTHONPATH=${pythonSource}/src
    mkdir -p "$out/app" "$out/private"
    cp ${./fixtures/pe32-project-app.c} app.c
    cp ${./fixtures/pe32-project-private.c} private.c
    cp ${./fixtures/pe32-project-private.def} private.def
    ${compiler}/bin/i686-w64-mingw32-gcc -shared private.c private.def \
      -Wl,--out-implib,libprivate.a -o "$out/private/private.dll"
    ${compiler}/bin/i686-w64-mingw32-gcc app.c -L. -lprivate \
      -o "$out/app/app.exe"
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
  composedPrivate = pkgs.runCommand
    "spaghetti-extractor-pe32-project-private-composed-fixture" {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      python ${./fixtures/pe32-project-compose.py} \
        ${fixture}/private/private.dll \
        ${privateInterface}/module-interface.json "$out"
    '';
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
    moduleInterfaces = {
      app = appInterface;
      private = privateInterface;
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
      --arg appSha "$app_sha" --arg privateSha "$private_sha" '
      {
        format: "spaghetti-extractor-pe32-load-observation-v1",
        project_id: $plan[0].project_id,
        environment_sha256: $plan[0].host_environment.sha256,
        runner_sha256: ("2" * 64),
        trace_sha256: ("3" * 64),
        process_exit_code: 0,
        modules: [
          {
            loader_name: "app.exe", resolved_path: "C:/fixture/app.exe",
            sha256: $appSha, origin: "target_distribution", image_id: "app"
          },
          {
            loader_name: "private.dll", resolved_path: "C:/fixture/private.dll",
            sha256: $privateSha, origin: "target_distribution", image_id: "private"
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
  deploymentFor = imageId: candidate: pkgs.runCommand
    "spaghetti-extractor-pe32-project-${imageId}-deployment-fixture" {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
    } ''
      mkdir -p "$out"
      hash="$(sha256sum ${candidate} | cut -d' ' -f1)"
      jq -n --arg hash "$hash" '{
        format: "spaghetti-extractor-pe32-module-deployment-v1",
        status: "complete",
        image_id: ${builtins.toJSON imageId},
        module_kind: ${builtins.toJSON (if imageId == "app" then "exe" else "dll")},
        candidate: {
          filename: ${builtins.toJSON (if imageId == "app" then "app.exe" else "private.dll")},
          sha256: $hash,
          decoded_loader_surface_sha256: ("6" * 64)
        },
        bindings: ([
          "original_interface", "behavioral_c_completion", "ingress_plan",
          "link_receipt", "exact_runtime_qualification", "loader_surface",
          "static_assurance", "candidate_interface"
        ] | map({key: ., value: {filename: (. + ".json"), sha256: ("7" * 64)}})
          | from_entries),
        original_identity: {},
        decoded_loader_surface: {
          kind: ${builtins.toJSON (if imageId == "app" then "exe" else "dll")},
          loader: {}, export_directory: {}, tls: null, imports: [], load_config: null
        },
        blockers: [],
        definition_of_complete: "fixture deployment is complete"
      }' > "$out/module-deployment.json"
      digest="$(jq -cS . "$out/module-deployment.json" | tr -d '\n' | sha256sum | cut -d' ' -f1)"
      jq --arg digest "$digest" '. + {deployment_sha256: $digest}' \
        "$out/module-deployment.json" > "$out/module-deployment.closed.json"
      mv "$out/module-deployment.closed.json" "$out/module-deployment.json"
    '';
  completion = import ../pe32-project-completion.nix {
    inherit pkgs pythonEnv loadPlan;
    moduleDeployments = {
      app = deploymentFor "app" "${fixture}/app/app.exe";
      private = deploymentFor "private" "${fixture}/private/private.dll";
    };
    observedLoadGraph = "${observedGraph}/observed-load-graph.json";
    namePrefix = "spaghetti-extractor-pe32-project-fixture";
  };
in
pkgs.runCommand "spaghetti-extractor-pe32-project-check" {
  nativeBuildInputs = [
    pkgs.jq
    pkgs.wineWow64Packages.stableFull
    pkgs.xvfb-run
  ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  jq -e '
    .status == "complete" and
    .counts.images == 3 and
    .counts.target_images == 2 and
    .counts.target_edges >= 1 and
    .counts.host_edges >= 1
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
  cp ${composedPrivate}/composed/private.dll distribution/
  xvfb-run -a wineboot -u >/dev/null 2>&1
  (cd distribution && timeout 60 xvfb-run -a wine ./app.exe)
  wineserver -w >/dev/null 2>&1 || true
  touch "$out"
''
