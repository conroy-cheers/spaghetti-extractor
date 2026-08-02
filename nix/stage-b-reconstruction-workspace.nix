{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  interpreterPackage,
  signatureCatalog ? null,
  namePrefix,
  clusters,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";

  plan = pkgs.runCommand
    "${namePrefix}-reconstruction-plan-v1"
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
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        "$out/reconstruction-plan.json" \
        ${if signatureCatalog == null then "-" else toString signatureCatalog} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_workspace import write_reconstruction_plan

      write_reconstruction_plan(
          machine_ir=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
          signature_catalog=(
              None if sys.argv[3] == "-" else pathlib.Path(sys.argv[3])
          ),
      )
      PY
      jq -e '
        .format == "stage-b-reconstruction-plan-v1" and
        (.status == "qualified" or .status == "incomplete") and
        .control_analysis.reachability_status != null and
        (.executes_original_binary | not)
      ' "$out/reconstruction-plan.json" >/dev/null
    '';

  mkWorkspace = cluster:
    pkgs.runCommand
      "${namePrefix}-${cluster.name}-workspace-v1"
      {
        nativeBuildInputs = [ pythonEnv pkgs.stdenv.cc pkgs.jq pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export LC_ALL=C.UTF-8
        export PYTHONPATH=${pythonSource}/src
        ${python} - \
          ${plan}/reconstruction-plan.json \
          ${machineIr} \
          ${interpreterPackage} \
          ${toString cluster.entryRva} \
          "$out" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.reconstruction_workspace import (
            create_reconstruction_workspace,
        )

        create_reconstruction_workspace(
            plan=pathlib.Path(sys.argv[1]),
            machine_ir=pathlib.Path(sys.argv[2]),
            interpreter_package=pathlib.Path(sys.argv[3]),
            entry_rva=int(sys.argv[4]),
            out_dir=pathlib.Path(sys.argv[5]),
        )
        PY
        ${lib.optionalString (cluster ? portableSource) ''
          cp ${cluster.portableSource} "$out/src/implementation.c"
          ${python} - "$out" <<'PY'
          import pathlib
          import sys
          from spaghetti_extractor.reconstruction_workspace import (
              rebind_reconstruction_workspace,
          )

          rebind_reconstruction_workspace(workspace=pathlib.Path(sys.argv[1]))
          PY
        ''}
        jq -e \
          --arg template ${lib.escapeShellArg cluster.template} \
          --argjson entry_rva ${toString cluster.entryRva} '
          .format == "stage-b-reconstruction-workspace-v1" and
          .status == "editable" and (.executes_original_binary | not) and
          .template == $template and
          .portability.portable_logic_uses_machine_state == false and
          .portability.generated_adapter_uses_machine_state == true
        ' "$out/workspace.json" >/dev/null
        jq -e --argjson entry_rva ${toString cluster.entryRva} '
          .cluster.entry_rva == $entry_rva
        ' "$out/region-replacement.json" >/dev/null
        ${pkgs.stdenv.cc}/bin/cc \
          -std=c11 -Wall -Wextra -Werror \
          -I ${interpreterPackage} -I "$out/src" \
          -c "$out/src/implementation.c" \
          -o "$TMPDIR/implementation.o"
        ${pkgs.stdenv.cc}/bin/cc \
          -std=c11 -Wall -Wextra -Werror \
          -I ${interpreterPackage} -I "$out/src" \
          -c "$out/src/replacement.c" \
          -o "$TMPDIR/replacement.o"
      '';

  workspaces = builtins.listToAttrs (map (cluster: {
    name = cluster.name;
    value = mkWorkspace cluster;
  }) clusters);

  checkedClusters = builtins.filter (cluster: cluster.check or true) clusters;

  mkCheck = cluster:
    pkgs.runCommand
      "${namePrefix}-${cluster.name}-workspace-check-v1"
      {
        nativeBuildInputs = [ pythonEnv pkgs.stdenv.cc pkgs.jq pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export LC_ALL=C.UTF-8
        export PYTHONPATH=${pythonSource}/src
        mkdir -p "$out"
        cp -R ${workspaces.${cluster.name}}/. "$out/"
        chmod -R u+w "$out"
        ${python} - \
          "$out" \
          ${interpreterPackage} \
          ${pkgs.stdenv.cc}/bin/cc <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.reconstruction_workspace import (
            run_reconstruction_workspace_check,
        )

        report = run_reconstruction_workspace_check(
            workspace=pathlib.Path(sys.argv[1]),
            interpreter_package=pathlib.Path(sys.argv[2]),
            compiler=sys.argv[3],
            out_dir=pathlib.Path(sys.argv[1]),
        )
        if report["status"] != "qualified":
            raise SystemExit(f"regional check was not qualified: {report['status']}")
        PY
        jq -e --argjson cases ${toString cluster.expectedCases} '
          .format == "stage-b-region-replacement-validation-v1" and
          .status == "qualified" and (.executes_original_binary | not) and
          .counts.compared_cases == $cases and .counts.deltas == 0
        ' "$out/validation-report.json" >/dev/null
      '';

  checks = builtins.listToAttrs (map (cluster: {
    name = cluster.name;
    value = mkCheck cluster;
  }) checkedClusters);

  checkPaths = lib.concatMapStringsSep " "
    (cluster: lib.escapeShellArg (toString checks.${cluster.name}))
    checkedClusters;

  registry = pkgs.runCommand
    "${namePrefix}-reconstruction-registry-v1"
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
      export PYTHONPATH=${pythonSource}/src
      ${python} - \
        ${plan}/reconstruction-plan.json \
        "$out" \
        ${checkPaths} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_workspace import (
          promote_reconstruction_workspaces,
          write_reconstruction_status,
      )

      plan = pathlib.Path(sys.argv[1])
      output = pathlib.Path(sys.argv[2])
      workspaces = [pathlib.Path(value) for value in sys.argv[3:]]
      promote_reconstruction_workspaces(workspaces=workspaces, out_dir=output)
      write_reconstruction_status(
          plan=plan,
          registry=output / "reconstruction-registry.json",
          out=output / "reconstruction-status.json",
      )
      PY
      jq -e --argjson replacements ${toString (builtins.length checkedClusters)} '
        .format == "stage-b-reconstruction-registry-v1" and
        .status == "qualified" and (.executes_original_binary | not) and
        .counts.replacements == $replacements
      ' "$out/reconstruction-registry.json" >/dev/null
      jq -e --argjson replacements ${toString (builtins.length checkedClusters)} '
        .format == "stage-b-reconstruction-status-v1" and
        (.executes_original_binary | not) and
        .counts.promoted_clusters == (.coverage.promoted_cluster_ids | length) and
        .counts.promoted_clusters <= $replacements and
        .counts.remaining_clusters ==
          (.counts.reachable_clusters - .counts.promoted_clusters)
      ' "$out/reconstruction-status.json" >/dev/null
    '';
in
{
  inherit plan workspaces checks registry;
}
