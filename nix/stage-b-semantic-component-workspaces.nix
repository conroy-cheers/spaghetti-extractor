{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  interpreterPackage,
  reconstructionPlan,
  semanticComponentCatalog,
  namePrefix,
  components,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  componentIdArgs = lib.concatMapStringsSep " "
    (component: lib.escapeShellArg component.componentId)
    components;

  componentSlices = pkgs.runCommand
    "${namePrefix}-component-slices-v1"
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
      export PYTHONPATH=${pythonSource}/src
      ${python} - \
        ${semanticComponentCatalog}/semantic-component-catalog.json \
        ${reconstructionPlan}/reconstruction-plan.json \
        ${machineIr} "$out" ${componentIdArgs} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.component_workspace import create_component_slice_package

      create_component_slice_package(
          catalog=pathlib.Path(sys.argv[1]),
          plan=pathlib.Path(sys.argv[2]),
          machine_ir=pathlib.Path(sys.argv[3]),
          out_dir=pathlib.Path(sys.argv[4]),
          component_ids=sys.argv[5:],
      )
      PY
      jq -e --argjson expected ${toString (builtins.length components)} '
        .format == "stage-b-component-slice-package-v1" and
        .status == "checked" and (.executes_original_binary | not) and
        .counts.components == $expected and (.entries | length) == $expected
      ' "$out/component-slice-package.json" >/dev/null
    '';

  mkScaffold = component:
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-scaffold-v1"
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
          ${componentSlices} \
          ${interpreterPackage} \
          ${lib.escapeShellArg component.componentId} \
          ${lib.escapeShellArg component.proofProfile} \
          "$out" <<'PY'
        import pathlib
        import sys
        import json
        from spaghetti_extractor.component_workspace import create_component_workspace

        package = pathlib.Path(sys.argv[1])
        index = json.loads((package / "component-slice-package.json").read_text())
        matches = [row for row in index["entries"] if row["component_id"] == sys.argv[3]]
        if len(matches) != 1:
            raise SystemExit(f"component slice count mismatch: {len(matches)}")
        create_component_workspace(
            catalog=None,
            plan=None,
            machine_ir=None,
            component_slice=package / matches[0]["path"],
            interpreter_package=pathlib.Path(sys.argv[2]),
            component_id=sys.argv[3],
            proof_profile=sys.argv[4],
            out_dir=pathlib.Path(sys.argv[5]),
        )
        PY
        jq -e \
          --arg component ${lib.escapeShellArg component.componentId} \
          --arg profile ${lib.escapeShellArg component.proofProfile} '
          .format == "stage-b-component-workspace-v1" and
          .status == "editable" and (.executes_original_binary | not) and
          .component_id == $component and .proof_profile == $profile and
          .activation.status == "blocked_pending_qualification"
        ' "$out/component-workspace.json" >/dev/null
        cmp "$out/src/replacement.c" "$out/contract/generated-machine-adapter.c"
        ${pkgs.stdenv.cc}/bin/cc \
          -std=c11 -Wall -Wextra -Werror \
          -I ${interpreterPackage} -I "$out/src" \
          -c "$out/src/implementation.c" -o "$TMPDIR/implementation.o"
        ${pkgs.stdenv.cc}/bin/cc \
          -std=c11 -Wall -Wextra -Werror \
          -I ${interpreterPackage} -I "$out/src" \
          -c "$out/src/replacement.c" -o "$TMPDIR/replacement.o"
      '';

  scaffolds = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkScaffold component;
  }) components);

  mkWorkspace = component:
    if !(component ? portableSource) then scaffolds.${component.name} else
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-workspace-v1"
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
        cp -R ${scaffolds.${component.name}}/. "$out/"
        chmod -R u+w "$out"
        cp ${component.portableSource} "$out/src/implementation.c"
        ${python} - "$out" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.component_workspace import rebind_component_workspace

        rebind_component_workspace(workspace=pathlib.Path(sys.argv[1]))
        PY
        cmp "$out/src/replacement.c" "$out/contract/generated-machine-adapter.c"
        ${pkgs.stdenv.cc}/bin/cc \
          -std=c11 -Wall -Wextra -Werror \
          -I ${interpreterPackage} -I "$out/src" \
          -c "$out/src/implementation.c" -o "$TMPDIR/implementation.o"
      '';

  workspaces = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkWorkspace component;
  }) components);

  mkSourceCheck = component:
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-source-proof-v1"
      {
        nativeBuildInputs = [
          pythonEnv
          pkgs.cbmc
          pkgs.stdenv.cc
          pkgs.jq
          pkgs.coreutils
        ];
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
        ${python} - ${workspaces.${component.name}} ${pkgs.cbmc}/bin/cbmc "$out/source-evidence.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.component_workspace import run_component_source_check

        evidence = run_component_source_check(
            workspace=pathlib.Path(sys.argv[1]),
            cbmc=sys.argv[2],
            out=pathlib.Path(sys.argv[3]),
        )
        if evidence["status"] != "satisfied":
            print(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"), file=sys.stderr)
            raise SystemExit(f"component source proof did not close: {evidence['status']}")
        PY
        jq -e '
          .format == "stage-b-component-evidence-v1" and
          .family == "source_behavior" and .provider == "cbmc" and
          .status == "satisfied" and (.executes_original_binary | not) and
          (.counterexamples | length) == 0
        ' "$out/source-evidence.json" >/dev/null
      '';

  sourceChecks = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkSourceCheck component;
  }) components);

  regionalKernel = pkgs.runCommand
    "${namePrefix}-regional-interpreter-kernel-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.stdenv.cc pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${pythonSource}/src
      ${python} - ${interpreterPackage} "$out" ${pkgs.stdenv.cc}/bin/cc <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_workspace import build_reconstruction_regional_kernel

      build_reconstruction_regional_kernel(
          interpreter_package=pathlib.Path(sys.argv[1]),
          out_dir=pathlib.Path(sys.argv[2]),
          compiler=sys.argv[3],
      )
      PY
      jq -e '
        .format == "stage-b-regional-interpreter-kernel-v1" and
        .status == "checked" and (.executes_original_binary | not) and
        (.objects | length) == 2
      ' "$out/regional-kernel.json" >/dev/null
    '';

  mkIntegration = component:
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-integration-v1"
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
        cp -R ${workspaces.${component.name}}/. "$out/"
        chmod -R u+w "$out"
        ${python} - "$out" ${interpreterPackage} ${pkgs.stdenv.cc}/bin/cc ${regionalKernel} <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.reconstruction_workspace import run_reconstruction_workspace_check

        report = run_reconstruction_workspace_check(
            workspace=pathlib.Path(sys.argv[1]),
            interpreter_package=pathlib.Path(sys.argv[2]),
            compiler=sys.argv[3],
            out_dir=pathlib.Path(sys.argv[1]),
            regional_kernel=pathlib.Path(sys.argv[4]),
        )
        if report["status"] != "qualified":
            raise SystemExit(f"component integration did not close: {report['status']}")
        PY
        jq -e \
          --argjson cases ${toString component.expectedCases} '
          .format == "stage-b-region-replacement-validation-v1" and
          .status == "qualified" and (.executes_original_binary | not) and
          .counts.compared_cases == $cases and .counts.deltas == 0
        ' "$out/validation-report.json" >/dev/null
      '';

  integrations = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkIntegration component;
  }) components);

  mkQualification = component:
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-qualification-v1"
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
        cp -R ${integrations.${component.name}}/. "$out/"
        chmod -R u+w "$out"
        ${python} - "$out" ${sourceChecks.${component.name}}/source-evidence.json "$out/component-qualification.json" <<'PY'
        import pathlib
        import sys
        from spaghetti_extractor.component_workspace import qualify_component

        qualification = qualify_component(
            workspace=pathlib.Path(sys.argv[1]),
            source_evidence=pathlib.Path(sys.argv[2]),
            out=pathlib.Path(sys.argv[3]),
        )
        if qualification["status"] != "qualified":
            raise SystemExit(f"component was not qualified: {qualification['status']}")
        PY
        jq -e '
          .format == "stage-b-component-qualification-v1" and
          .status == "qualified" and .activation.authorized and
          (.executes_original_binary | not) and
          .counts.incomplete_or_violated == 0
        ' "$out/component-qualification.json" >/dev/null
      '';

  qualifications = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkQualification component;
  }) components);

  workspacePaths = lib.concatMapStringsSep " "
    (component: lib.escapeShellArg (toString qualifications.${component.name}))
    components;
  qualificationPaths = lib.concatMapStringsSep " "
    (component: lib.escapeShellArg "${qualifications.${component.name}}/component-qualification.json")
    components;

  registry = pkgs.runCommand
    "${namePrefix}-component-registry-v1"
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
      ${python} - "$out" ${toString (builtins.length components)} \
        ${workspacePaths} -- ${qualificationPaths} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.component_workspace import promote_qualified_components

      output = pathlib.Path(sys.argv[1])
      count = int(sys.argv[2])
      separator = sys.argv.index("--")
      workspaces = [pathlib.Path(value) for value in sys.argv[3:separator]]
      qualifications = [pathlib.Path(value) for value in sys.argv[separator + 1:]]
      if len(workspaces) != count or len(qualifications) != count:
          raise SystemExit("component registry input count mismatch")
      promote_qualified_components(
          workspaces=workspaces,
          qualifications=qualifications,
          out_dir=output,
      )
      PY
      jq -e --argjson expected ${toString (builtins.length components)} '
        .format == "stage-b-component-registry-v1" and
        .status == "qualified" and .activation_policy == "qualified_components_only" and
        (.executes_original_binary | not) and .counts.components == $expected and
        (.entries | length) == $expected and
        .whole_program_status == "incomplete" and
        .coverage.qualified_units == 11 and
        .coverage.machine_units == 7861 and .coverage.remaining_units == 7850
      ' "$out/component-registry.json" >/dev/null
    '';
in
{
  inherit componentSlices scaffolds workspaces sourceChecks regionalKernel integrations qualifications registry;
}
