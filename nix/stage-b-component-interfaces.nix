{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  semanticComponentCatalog,
  namePrefix,
  components,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [
      "spaghetti_extractor.artifact_formats"
      "spaghetti_extractor.component_interface"
      "spaghetti_extractor.util"
    ];
    name = "${namePrefix}-component-interface-python-closure";
  };
  componentInterfaceInputs = pkgs.linkFarm
    "${namePrefix}-component-interface-inputs-v1"
    (map (component: {
      name = "${component.name}.json";
      path = component.interfaceSpec;
    }) (builtins.filter (component: component ? interfaceSpec) components));
  componentInterfaceArgs = lib.concatMapStringsSep " "
    (component:
      "${lib.escapeShellArg component.name} "
      + "${lib.escapeShellArg component.componentId} "
      + lib.escapeShellArg (
        if component ? interfaceSpec
        then "${componentInterfaceInputs}/${component.name}.json"
        else "-"
      ))
    components;

  mkComponentInterface = component:
    pkgs.runCommand
      "${namePrefix}-${component.name}-component-interface-v1"
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
        export PYTHONPATH=${phasePythonSource}/src
        ${python} - \
          ${semanticComponentCatalog}/semantic-component-catalog.json \
          ${machineIr} \
          ${lib.escapeShellArg component.componentId} \
          ${lib.escapeShellArg (
            if component ? interfaceSpec
            then "${componentInterfaceInputs}/${component.name}.json"
            else "-"
          )} \
          "$out" <<'PY'
        import json
        import pathlib
        import sys
        from spaghetti_extractor.component_interface import (
            check_component_interface,
            synthesize_component_interface_spec,
        )
        from spaghetti_extractor.util import write_json

        catalog = pathlib.Path(sys.argv[1])
        machine_ir = pathlib.Path(sys.argv[2])
        component_id = sys.argv[3]
        spec_input = sys.argv[4]
        output = pathlib.Path(sys.argv[5])
        output.mkdir(parents=True)
        specification = (
            synthesize_component_interface_spec(
                catalog=catalog,
                machine_ir=machine_ir,
                component_id=component_id,
            )
            if spec_input == "-"
            else json.loads(pathlib.Path(spec_input).read_text(encoding="utf-8"))
        )
        refinement = check_component_interface(
            catalog=catalog,
            machine_ir=machine_ir,
            component_id=component_id,
            interface_spec=specification,
        )
        write_json(output / "specification.json", specification)
        write_json(output / "refinement.json", refinement)
        if refinement["status"] != "checked" or refinement["issues"]:
            raise SystemExit(
                f"component interface did not close for {component_id}: "
                f"{refinement['status']}"
            )
        PY
        jq -e --arg component ${lib.escapeShellArg component.componentId} '
          .format == "stage-b-component-interface-refinement-v1" and
          .status == "checked" and (.executes_original_binary | not) and
          .component.id == $component and (.issues | length) == 0
        ' "$out/refinement.json" >/dev/null
      '';

  byName = builtins.listToAttrs (map (component: {
    name = component.name;
    value = mkComponentInterface component;
  }) components);

  bundle = pkgs.runCommand
    "${namePrefix}-component-interface-bundle-v1"
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
      export PYTHONPATH=${phasePythonSource}/src
      ${python} - \
        ${semanticComponentCatalog}/semantic-component-catalog.json \
        ${machineIr} "$out" ${toString (builtins.length components)} \
        ${componentInterfaceArgs} <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.artifact_formats import COMPONENT_INTERFACE_BUNDLE_FORMAT
      from spaghetti_extractor.component_interface import (
          check_component_interface,
          synthesize_component_interface_spec,
      )
      from spaghetti_extractor.util import sha256_file, write_json

      catalog = pathlib.Path(sys.argv[1])
      machine_ir = pathlib.Path(sys.argv[2])
      output = pathlib.Path(sys.argv[3])
      count = int(sys.argv[4])
      values = sys.argv[5:]
      if len(values) != count * 3:
          raise SystemExit("component interface input count mismatch")
      specs = output / "specifications"
      refinements = output / "refinements"
      specs.mkdir(parents=True)
      refinements.mkdir(parents=True)
      entries = []
      for index in range(count):
          name, component_id, spec_input = values[index * 3:index * 3 + 3]
          if spec_input == "-":
              spec = synthesize_component_interface_spec(
                  catalog=catalog,
                  machine_ir=machine_ir,
                  component_id=component_id,
              )
          else:
              spec = json.loads(pathlib.Path(spec_input).read_text(encoding="utf-8"))
          refinement = check_component_interface(
              catalog=catalog,
              machine_ir=machine_ir,
              component_id=component_id,
              interface_spec=spec,
          )
          spec_path = specs / f"{name}.json"
          refinement_path = refinements / f"{name}.json"
          write_json(spec_path, spec)
          write_json(refinement_path, refinement)
          if refinement["status"] != "checked" or refinement["issues"]:
              print(json.dumps({
                  "component": refinement.get("component"),
                  "status": refinement.get("status"),
                  "coverage": refinement.get("coverage"),
                  "issues": refinement.get("issues"),
              }, indent=2, sort_keys=True), file=sys.stderr)
              raise SystemExit(
                  f"component interface did not close for {component_id}: "
                  f"{refinement['status']}"
              )
          entries.append({
              "name": name,
              "component_id": component_id,
              "specification": f"specifications/{name}.json",
              "specification_sha256": sha256_file(spec_path),
              "refinement": f"refinements/{name}.json",
              "refinement_sha256": refinement["refinement_sha256"],
              "refinement_artifact_sha256": sha256_file(refinement_path),
          })
      write_json(output / "component-interface-bundle.json", {
          "format": COMPONENT_INTERFACE_BUNDLE_FORMAT,
          "status": "checked",
          "executes_original_binary": False,
          "entries": entries,
          "counts": {"components": len(entries), "issues": 0},
      })
      PY
      jq -e --argjson expected ${toString (builtins.length components)} '
        .format == "stage-b-component-interface-bundle-v1" and
        .status == "checked" and (.executes_original_binary | not) and
        .counts.components == $expected and .counts.issues == 0 and
        (.entries | length) == $expected
      ' "$out/component-interface-bundle.json" >/dev/null
    '';
in
{
  inherit bundle byName;
}
