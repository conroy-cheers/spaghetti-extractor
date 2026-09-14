# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, sourcePreparation, exactSlice
, contract, previous ? null, unwind ? 16, timeoutSeconds ? 60, solver ? "z3", dependencies ? { }
}:
assert builtins.elem solver [ "z3" "cadical" ];
assert builtins.isInt unwind && unwind >= 2;
assert builtins.isInt timeoutSeconds && timeoutSeconds > 0;
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-component-source-region-check";
  kind = "component-source-check";
  artifactName = "source-check.json";
  expectedFormat = "spaghetti-extractor-operator-work-status-v2";
  allowedStatuses = [ "complete" "incomplete" "violated" ];
  pythonModules = [ "spaghetti_extractor.operator.source_region_check" ];
  phaseRole = "operator";
  extraNativeBuildInputs = [ pkgs.stdenv.cc pkgs.cbmc pkgs.z3 pkgs.bubblewrap ];
  inputs = { preparation = sourcePreparation; exact = exactSlice; inherit contract; }
    // pkgs.lib.mapAttrs' (name: value: pkgs.lib.nameValuePair "dependency_${name}" value) dependencies
    // pkgs.lib.optionalAttrs (previous != null) { inherit previous; };
  program = ''
    import json, sys
    from pathlib import Path
    from spaghetti_extractor.operator.source_region_check import write_component_source_region_check
    timings = []
    write_component_source_region_check(
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        preparation=inputs["preparation"], exact=inputs["exact"],
        contract=json.loads(inputs["contract"].read_text()), out=output.parent,
        workspace=Path('region-work'),
        goto_cc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/goto-cc"}),
        goto_instrument=Path(${builtins.toJSON "${pkgs.cbmc}/bin/goto-instrument"}),
        cbmc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"}),
        host_cc=Path(${builtins.toJSON "${pkgs.stdenv.cc}/bin/cc"}),
        dependencies=${if dependencies == { } then "None" else ''{name: inputs["dependency_"+name] for name in ${builtins.toJSON (builtins.attrNames dependencies)}}''},
        smt_solver=${if solver == "z3" then ''Path(${builtins.toJSON "${pkgs.z3}/bin/z3"})'' else "None"},
        previous=${if previous == null then "None" else ''inputs["previous"]''},
        unwind=${builtins.toJSON unwind}, timeout_seconds=${builtins.toJSON timeoutSeconds}, timings=timings)
    print(json.dumps({"source_region_check_timings":timings}), file=sys.stderr)
  '';
}
