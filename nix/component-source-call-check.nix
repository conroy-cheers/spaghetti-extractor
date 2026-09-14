# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, sourcePreparation, exactSlice
, supplier, contract, previous ? null, unwind ? 16, timeoutSeconds ? 30
, sourcePackage ? null, interfacePackage ? null
}:
assert builtins.isInt unwind && unwind >= 2;
assert builtins.isInt timeoutSeconds && timeoutSeconds > 0;
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-component-source-call-check";
  kind = "component-source-check";
  artifactName = "source-check.json";
  expectedFormat = "spaghetti-extractor-operator-work-status-v2";
  allowedStatuses = [ "complete" "incomplete" "violated" ];
  pythonModules = [ "spaghetti_extractor.operator.source_call_check" ];
  phaseRole = "operator";
  extraNativeBuildInputs = [ pkgs.stdenv.cc pkgs.cbmc pkgs.z3 pkgs.bubblewrap ];
  inputs = { preparation = sourcePreparation; exact = exactSlice; inherit supplier contract; }
    // pkgs.lib.optionalAttrs (sourcePackage != null) { inherit sourcePackage; }
    // pkgs.lib.optionalAttrs (interfacePackage != null) { inherit interfacePackage; }
    // pkgs.lib.optionalAttrs (previous != null) { inherit previous; };
  program = ''
    import json, sys
    from pathlib import Path
    from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
    timings = []
    write_component_source_call_check(
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        preparation=inputs["preparation"], exact=inputs["exact"], supplier=inputs["supplier"],
        contract=json.loads(inputs["contract"].read_text()), out=output.parent,
        workspace=Path('caller-work'),
        goto_cc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/goto-cc"}),
        cbmc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"}),
        smt_solver=Path(${builtins.toJSON "${pkgs.z3}/bin/z3"}),
        source_package=${if sourcePackage == null then "None" else ''inputs["sourcePackage"]''},
        interface_package=${if interfacePackage == null then "None" else ''inputs["interfacePackage"]''},
        previous=${if previous == null then "None" else ''inputs["previous"]''},
        unwind=${builtins.toJSON unwind}, timeout_seconds=${builtins.toJSON timeoutSeconds}, timings=timings)
    print(json.dumps({"source_call_check_timings":timings}), file=sys.stderr)
  '';
}
