# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, interfacePackage, sourcePackage
, baselineInterfacePackage, baselineSourcePackage, boundary
, previousSourceEdit ? null, baselineConditionalPacket ? null, timeoutSeconds ? 30
, baselineConditionalEvidence ? null, baselineObligation ? null, baselineQueryTransport ? false
}:
let
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
in
assert builtins.isInt timeoutSeconds && timeoutSeconds > 0;
assert baselineConditionalEvidence == null || (baselineConditionalPacket == null && builtins.isString baselineObligation && baselineObligation != "");
assert baselineObligation == null || baselineConditionalEvidence != null;
assert builtins.isBool baselineQueryTransport && (!baselineQueryTransport || baselineConditionalEvidence != null);
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-source-edit-check";
  kind = "component-source-edit-check";
  artifactName = "source-edit-check.json";
  expectedFormat = "spaghetti-extractor-operator-work-status-v2";
  allowedStatuses = [ "complete" "incomplete" "violated" ];
  pythonModules = [ "spaghetti_extractor.operator.source_edit" ];
  phaseRole = "operator";
  extraNativeBuildInputs = [ pkgs.stdenv.cc compiler pkgs.cbmc pkgs.bubblewrap ];
  inputs = {
    interface_package = interfacePackage;
    source_package = sourcePackage;
    baseline_interface = baselineInterfacePackage;
    baseline_source = baselineSourcePackage;
    edit_boundary = pkgs.writeText "source-edit-boundary.json" (builtins.toJSON boundary);
  } // pkgs.lib.optionalAttrs (previousSourceEdit != null) { previous_edit = previousSourceEdit; }
    // pkgs.lib.optionalAttrs (baselineConditionalPacket != null) { baseline_packet = baselineConditionalPacket; }
    // pkgs.lib.optionalAttrs (baselineConditionalEvidence != null) { baseline_evidence = baselineConditionalEvidence; };
  program = ''
    from pathlib import Path
    import json, sys
    from spaghetti_extractor.operator.source_edit import write_component_source_edit
    timings = []
    write_component_source_edit(
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        interface_package=inputs["interface_package"], source_package=inputs["source_package"],
        baseline_interface_package=inputs["baseline_interface"], baseline_source_package=inputs["baseline_source"],
        boundary=json.loads(inputs["edit_boundary"].read_text()), workspace=Path("source-edit-work"),
        host_compiler=Path(${builtins.toJSON "${pkgs.stdenv.cc}/bin/cc"}),
        pe32_compiler=Path(${builtins.toJSON "${compiler}/bin/${compiler.targetPrefix}cc"}),
        cbmc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"}),
        previous=inputs.get("previous_edit"), baseline_conditional_packet=inputs.get("baseline_packet"),
        baseline_conditional_evidence=inputs.get("baseline_evidence"), baseline_obligation=${builtins.toJSON baselineObligation},
        baseline_query_transport=${if baselineQueryTransport then "True" else "False"},
        timeout_seconds=${builtins.toJSON timeoutSeconds}, timings=timings, out=output.parent,
    )
    print(json.dumps({"source_edit_timings": timings}), file=sys.stderr)
  '';
}
