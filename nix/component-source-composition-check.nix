# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, regions, previous ? null, timeoutSeconds ? 60, exactOperation ? null, summaryExport ? null }:
assert builtins.attrNames regions == [ "entry" "loop" "tail" ];
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-component-source-composition-check";
  kind = "component-source-check";
  artifactName = "source-check.json";
  expectedFormat = "spaghetti-extractor-operator-work-status-v2";
  allowedStatuses = [ "incomplete" ];
  pythonModules = [ "spaghetti_extractor.operator.source_composition_check" ];
  phaseRole = "operator";
  extraNativeBuildInputs = [ pkgs.stdenv.cc pkgs.cbmc pkgs.bubblewrap ];
  inputs = regions // pkgs.lib.optionalAttrs (exactOperation != null) { inherit exactOperation; }
    // pkgs.lib.optionalAttrs (previous != null) { inherit previous; }
    // pkgs.lib.optionalAttrs (summaryExport != null) { inherit summaryExport; };
  program = ''
    import json, sys
    from pathlib import Path
    from spaghetti_extractor.operator.source_composition_check import write_component_source_composition_check
    timings = []
    write_component_source_composition_check(
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        regions={name: inputs[name] for name in ['entry', 'loop', 'tail']},
        out=output.parent, workspace=Path('composition-work'),
        goto_cc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/goto-cc"}),
        cbmc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"}),
        previous=${if previous == null then "None" else ''inputs["previous"]''},
        exact_operation=${if exactOperation == null then "None" else ''inputs["exactOperation"]''},
        summary_export=${if summaryExport == null then "None" else ''json.loads(inputs["summaryExport"].read_text())''},
        timeout_seconds=${builtins.toJSON timeoutSeconds}, timings=timings)
    print(json.dumps({"source_composition_timings":timings}), file=sys.stderr)
  '';
}
