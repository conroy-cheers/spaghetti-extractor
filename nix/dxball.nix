{ pkgs
, pythonEnv
, sideTool
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  archive = pkgs.fetchurl {
    name = "dxball-1.09-distributable.zip";
    url = "https://archive.org/download/dxball-19/DXBall19.zip";
    hash = "sha256-ARvV4Ge3rNrGxdbEeqIAmpcb07FSayOGbUsz/ZfdUQ0=";
  };
  installerSha256 =
    "2472a555ba5cbda459f6c7b9df9e2aebc37eaca2c730e86d31b46a088d81ae77";
  executableSha256 =
    "191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f";
  wine = pkgs.wineWow64Packages.stableFull;
  wineFontsConf = pkgs.writeText "spaghetti-extractor-dxball-fonts.conf" ''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
    <fontconfig>
      <dir>${pkgs.dejavu_fonts}/share/fonts</dir>
      <cachedir prefix="xdg">fontconfig</cachedir>
      <config><rescan><int>0</int></rescan></config>
    </fontconfig>
  '';
  headlessWineEnvironment = ''
    unset WAYLAND_DISPLAY XDG_BACKEND
    export XDG_SESSION_TYPE=x11
    export HOME="$TMPDIR/home"
    export WINEPREFIX="$TMPDIR/wine"
    export WINEDEBUG=-all
    export WINEDLLOVERRIDES="mscoree,mshtml="
    export XDG_CACHE_HOME="$TMPDIR/cache"
    export FONTCONFIG_FILE=${wineFontsConf}
    mkdir -p "$HOME" "$XDG_CACHE_HOME"
  '';
  opaqueStaticPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/_contract_tools
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/contract_tools.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/opaque_reconstruction.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/binary_inventory.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/relational/reference_contract.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/side_extraction_artifact.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/roundtrip_fuzz/__init__.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
    ];
  };
  machineIrPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/import_abi.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/reconstruction_ir.py
      ../src/spaghetti_extractor/reconstruction_control.py
      ../src/spaghetti_extractor/value_provenance.py
    ];
  };
  rootedStateMachinePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/_contract_tools
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/import_abi.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/recursive_decode.py
      ../src/spaghetti_extractor/reconstruction_ir.py
      ../src/spaghetti_extractor/reconstruction_control.py
      ../src/spaghetti_extractor/rooted_state_machine.py
      ../src/spaghetti_extractor/value_provenance.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x87_profile.py
    ];
  };
in
rec {
  sourceArchive = archive;

  installer = pkgs.runCommand "stage-a-dxball-1.09-installer"
    {
      nativeBuildInputs = [ pkgs.unzip ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      mkdir -p "$out"
      unzip -j ${archive} DXBall19.EXE -d "$out"
      test "$(sha256sum "$out/DXBall19.EXE" | cut -d ' ' -f 1)" = \
        "${installerSha256}"
    '';

  originalRuntime = pkgs.runCommand "stage-a-dxball-1.09-original-runtime"
    {
      nativeBuildInputs = [
        pkgs.findutils
        pkgs.jq
        pkgs.xvfb-run
        wine
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      ${headlessWineEnvironment}
      xvfb-run -a -s '-screen 0 640x480x24' sh -eu -c '
        wineboot -u >/dev/null 2>&1
        wine ${installer}/DXBall19.EXE /s >/dev/null 2>&1
        wineserver -w
      '

      installed="$WINEPREFIX/drive_c/Program Files (x86)/DX-Ball"
      test -d "$installed"
      mkdir -p "$out/runtime"
      find "$installed" -maxdepth 1 -type f \
        \( -iname '*.pcx' -o -iname '*.wav' -o -iname '*.sbk' \
        -o -iname '*.mds' -o -iname '*.bds' -o -iname 'DXBall.exe' \
        -o -iname 'Readme.txt' -o -iname 'score.dat' \) \
        -exec cp '{}' "$out/runtime/" ';'

      test "$(find "$out/runtime" -maxdepth 1 -type f | wc -l)" -eq 48
      test "$(sha256sum "$out/runtime/DXBall.exe" | cut -d ' ' -f 1)" = \
        "${executableSha256}"
      (
        cd "$out/runtime"
        find . -maxdepth 1 -type f -printf '%P\0' | sort -z | \
          xargs -0 sha256sum > "$out/SHA256SUMS"
      )
      jq -n \
        --arg archive_sha256 \
          "011bd5e067b7acdac6c5d6c47aa2009a971bd3b1526b23866d4b33fd97dd510d" \
        --arg installer_sha256 "${installerSha256}" \
        --arg executable_sha256 "${executableSha256}" \
        '{
          format: "spaghetti-extractor-dxball-original-runtime-v1",
          status: "ready",
          version: "1.09",
          provenance: {
            archive_url: "https://archive.org/download/dxball-19/DXBall19.zip",
            archive_sha256: $archive_sha256,
            installer_sha256: $installer_sha256,
            current_publisher_url: "https://dxball.itch.io/dx-ball"
          },
          runtime: {
            executable: "runtime/DXBall.exe",
            executable_sha256: $executable_sha256,
            files: 48,
            asset_policy: "unmodified-freely-distributable-package-payload"
          }
        }' > "$out/manifest.json"
    '';

  originalSmoke = pkgs.runCommand "stage-a-dxball-1.09-original-headless-smoke"
    {
      nativeBuildInputs = [
        pkgs.imagemagick
        pkgs.jq
        pkgs.xdotool
        pkgs.xvfb-run
        wine
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      ${headlessWineEnvironment}
      cp -R ${originalRuntime}/runtime "$TMPDIR/runtime"
      chmod -R u+w "$TMPDIR/runtime"

      xvfb-run -a -s '-screen 0 640x480x24' sh -eu <<'EOF'
      cd "$TMPDIR/runtime"
      wineboot -u >/dev/null 2>&1
      wine ./DXBall.exe >"$TMPDIR/stdout" 2>"$TMPDIR/stderr" &
      game_pid=$!
      cleanup() {
        kill "$game_pid" 2>/dev/null || true
        wineserver -k 2>/dev/null || true
      }
      trap cleanup EXIT

      prompt_window=""
      for _ in $(seq 1 200); do
        prompt_window="$(xdotool search --onlyvisible --name 'DX-Ball' 2>/dev/null | head -n 1 || true)"
        [ -z "$prompt_window" ] || break
        sleep 0.05
      done
      test -n "$prompt_window"
      xdotool key --window "$prompt_window" Return

      window=""
      for _ in $(seq 1 200); do
        for candidate in $(xdotool search --onlyvisible --name 'DX-Ball' 2>/dev/null || true); do
          geometry="$(xdotool getwindowgeometry --shell "$candidate" 2>/dev/null || true)"
          width="$(printf '%s\n' "$geometry" | sed -n 's/^WIDTH=//p')"
          height="$(printf '%s\n' "$geometry" | sed -n 's/^HEIGHT=//p')"
          if [ "''${width:-0}" -ge 600 ] && [ "''${height:-0}" -ge 400 ]; then
            window="$candidate"
            break 2
          fi
        done
        sleep 0.05
      done
      test -n "$window"
      sleep 2
      import -window root "$TMPDIR/intro.png"
      kill "$game_pid" 2>/dev/null || true
      wait "$game_pid" 2>/dev/null || true
      trap - EXIT
      wineserver -k 2>/dev/null || true
      EOF

      test "$(identify -format '%wx%h' "$TMPDIR/intro.png")" = "640x480"
      # DX-Ball renders a deliberately low-colour 640x480 PCX frame.  This
      # threshold rejects the blank desktop and modal prompt without requiring
      # palette expansion from the original renderer.
      test "$(identify -format '%k' "$TMPDIR/intro.png")" -gt 32
      mkdir -p "$out"
      cp "$TMPDIR/intro.png" "$out/intro.png"
      cp "$TMPDIR/stdout" "$TMPDIR/stderr" "$out/"
      jq -n \
        --arg screenshot_sha256 \
          "$(sha256sum "$out/intro.png" | cut -d ' ' -f 1)" \
        '{
          format: "spaghetti-extractor-dxball-original-smoke-v1",
          status: "pass",
          session: "headless-x11-xvfb",
          checks: {
            missing_sound_prompt_acknowledged: true,
            visible_game_window: true,
            intro_frame_nonblank: true,
            process_terminated_after_capture: true
          },
          screenshot: {path: "intro.png", sha256: $screenshot_sha256}
        }' > "$out/report.json"
    '';

  originalInventory = pkgs.runCommand "stage-a-dxball-1.09-original-inventory"
    {
      nativeBuildInputs = [ pkgs.jq sideTool ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      mkdir -p "$out"
      spaghetti-extractor-side inventory-binary \
        --binary ${originalRuntime}/runtime/DXBall.exe \
        --side original \
        --out "$out/inventory.json" \
        > "$out/inventory.stdout"
      jq -e '
        .format == "stage-a-binary-cutpoint-inventory-v1" and
        .status == "pass" and
        .counts.issues == 0 and
        .counts.regions > 0 and
        .counts.extraction_regions >= .counts.regions and
        .counts.padding_waivers > 0
      ' "$out/inventory.json" >/dev/null
    '';

  opaqueStaticExport = pkgs.runCommand "stage-a-dxball-1.09-opaque-static-export"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${opaqueStaticPythonSource}/src
      test ! -e ${opaqueStaticPythonSource}/src/spaghetti_extractor/reconstruction_ir.py
      ${python} - \
        ${lib.escapeShellArg "${originalRuntime}/runtime/DXBall.exe"} \
        ${lib.escapeShellArg "${originalInventory}/inventory.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.opaque_reconstruction import (
          stage_a_export_opaque_reconstruction,
      )

      original, inventory, output = map(pathlib.Path, sys.argv[1:])
      stage_a_export_opaque_reconstruction(
          original=original,
          inventory=inventory,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-a-opaque-static-export-v1" and
        .status == "ready" and
        .counts.regions > 0 and
        .counts.transfers > 0
      ' "$out/opaque-static-export.json" >/dev/null
    '';

  importAbiProfile = pkgs.runCommand "stage-a-dxball-1.09-import-abi-profile"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${machineIrPythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg "${originalRuntime}/runtime/DXBall.exe"} \
        ${lib.escapeShellArg "${../profiles/pe32-win32-system-dll-abi-policy-v1.json}"} \
        "$out/import-abi-profile.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.import_abi import expand_import_abi_policy

      original, policy, output = map(pathlib.Path, sys.argv[1:])
      expand_import_abi_policy(
          original_pe=original,
          policy=policy,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-a-static-machine-import-profile-v1" and
        .status == "complete" and
        .source_binary.sha256 == "${executableSha256}" and
        .counts.imports > 90 and
        .counts.dlls == 6 and
        ([.machine_import_signatures[].abi_template] | unique) ==
          ["pe32-stdcall-v1"]
      ' "$out/import-abi-profile.json" >/dev/null
    '';

  baseMachineIr = pkgs.runCommand "stage-a-dxball-1.09-base-machine-ir"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${machineIrPythonSource}/src
      test ! -e ${machineIrPythonSource}/src/spaghetti_extractor/opaque_reconstruction.py
      ${python} - \
        ${lib.escapeShellArg "${opaqueStaticExport}/state-machine.jsonl"} \
        ${lib.escapeShellArg "${originalRuntime}/runtime/DXBall.exe"} \
        ${lib.escapeShellArg "${opaqueStaticExport}/reference-contract.json"} \
        ${lib.escapeShellArg "${../profiles/pe32-static-cutpoints-and-paired-callables-v1.json}"} \
        ${lib.escapeShellArg "${importAbiProfile}/import-abi-profile.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      state_machine, original, reference, target_profile, import_profile, output = map(
          pathlib.Path, sys.argv[1:]
      )
      export_machine_ir_package(
          state_machine=state_machine,
          original_pe=original,
          reference_contract=reference,
          indirect_target_profile=target_profile,
          machine_import_profiles=[import_profile],
          out=output,
      )
      PY
      # The artifact is useful repair input, but unresolved rooted frontiers
      # must keep this initial export incomplete.
      jq -e '
        .format == "stage-a-machine-ir-v2" and
        .status == "incomplete" and
        .binary.sha256 == "${executableSha256}" and
        .counts.units == 8989 and
        .counts.violated_issues == 0 and
        .counts.incomplete_issues > 0 and
        .coverage.counts.unknown_bytes == 0 and
        .control.counts.roots == 1 and
        .control.counts.exact_reachable_units > 0 and
        .control.counts.potential_reachable_units > 0 and
        .control.reachability.status == "incomplete" and
        .control.counts.rooted_frontiers > 0
      ' "$out/machine-ir-manifest.json" >/dev/null
    '';

  rootedStateMachine = pkgs.runCommand
    "stage-b-dxball-1.09-rooted-state-machine"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${rootedStateMachinePythonSource}/src
      test ! -e ${rootedStateMachinePythonSource}/src/spaghetti_extractor/component_workspace.py
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg "${opaqueStaticExport}/state-machine.jsonl"} \
        ${lib.escapeShellArg "${baseMachineIr}/machine-ir-manifest.json"} \
        ${lib.escapeShellArg "${originalRuntime}/runtime/DXBall.exe"} \
        ${lib.escapeShellArg "${opaqueStaticExport}/reference-contract.json"} \
        ${lib.escapeShellArg "${../profiles/pe32-static-cutpoints-and-paired-callables-v1.json}"} \
        ${lib.escapeShellArg "${importAbiProfile}/import-abi-profile.json"} \
        "$out/state-machine.jsonl" \
        "$out/rooted-view-augmentation.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.rooted_state_machine import (
          augment_state_machine_with_rooted_instruction_views,
      )

      state_machine, manifest, original, reference, target_profile, import_profile, output, report = map(
          pathlib.Path, sys.argv[1:]
      )
      augment_state_machine_with_rooted_instruction_views(
          state_machine=state_machine,
          machine_ir_manifest=manifest,
          original_pe=original,
          reference_contract=reference,
          indirect_target_profile=target_profile,
          machine_import_profiles=[import_profile],
          out=output,
          report=report,
      )
      PY
      jq -e '
        .format == "stage-b-rooted-state-machine-augmentation-v1" and
        .status == "complete" and
        .counts.iterations > 1 and
        .counts.seed_targets > 1 and
        .counts.supplemental_transfers > 15 and
        .counts.output_transfers > 9004 and
        .counts.merge_destinations >= 3 and
        .counts.remaining_rooted_direct_targets == 0 and
        .counts.issues == 0 and
        (.trust.executes_original_binary | not) and
        .trust.recursive_decode_is_proposal_only and
        .trust.exact_pe_binding_required_downstream
      ' "$out/rooted-view-augmentation.json" >/dev/null
    '';

  machineIr = pkgs.runCommand "stage-a-dxball-1.09-machine-ir"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${machineIrPythonSource}/src
      ${python} - \
        ${lib.escapeShellArg "${rootedStateMachine}/state-machine.jsonl"} \
        ${lib.escapeShellArg "${originalRuntime}/runtime/DXBall.exe"} \
        ${lib.escapeShellArg "${opaqueStaticExport}/reference-contract.json"} \
        ${lib.escapeShellArg "${../profiles/pe32-static-cutpoints-and-paired-callables-v1.json}"} \
        ${lib.escapeShellArg "${importAbiProfile}/import-abi-profile.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      state_machine, original, reference, target_profile, import_profile, output = map(
          pathlib.Path, sys.argv[1:]
      )
      export_machine_ir_package(
          state_machine=state_machine,
          original_pe=original,
          reference_contract=reference,
          indirect_target_profile=target_profile,
          machine_import_profiles=[import_profile],
          out=output,
      )
      PY
      jq -e '
        .format == "stage-a-machine-ir-v2" and
        .status == "incomplete" and
        .binary.sha256 == "${executableSha256}" and
        .counts.units > 9004 and
        .counts.violated_issues == 0 and
        .coverage.counts.unknown_bytes == 0 and
        .control.reachability.status == "incomplete" and
        ([.control.reachability.frontiers[] |
          select(.reason == "unresolved_internal_call_target")] | length) == 0 and
        .control.counts.rooted_frontiers > 0
      ' "$out/machine-ir-manifest.json" >/dev/null
    '';

}
