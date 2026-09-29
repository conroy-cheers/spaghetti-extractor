# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, interfacePackage, sourcePackage
, localContracts ? false, localContractUnwind ? 16
, localContractTimeoutSeconds ? 30
, localContractDependencies ? [ ]
, previousLocalContract ? null
, sharedContract ? null
, originalComparison ? null
, terminalServices ? null
, sourceCallRegions ? null
, sourceRegionGraphs ? null
, callerComposition ? null
}:
let
  compiler = pkgs.pkgsCross.mingw32.stdenv.cc;
  sharedServiceBindings = if sharedContract == null then null else sharedContract.serviceBindings or null;
  dependencyInputs = builtins.listToAttrs (pkgs.lib.imap0 (index: row: {
    name = "source_dependency_${toString index}"; value = row.package;
  }) localContractDependencies);
  dependencyArguments = pkgs.lib.concatStringsSep ", " (pkgs.lib.imap0 (index: row:
    ''{"package": inputs["source_dependency_${toString index}"], "operation_id": ${builtins.toJSON row.operationId}}''
  ) localContractDependencies);
in
assert builtins.isInt localContractUnwind && localContractUnwind >= 2;
assert builtins.isInt localContractTimeoutSeconds && localContractTimeoutSeconds > 0;
assert localContractDependencies == [ ] || localContracts;
assert previousLocalContract == null || localContracts;
assert sharedContract == null || localContracts;
assert terminalServices == null || (localContracts && sharedContract == null
  && localContractDependencies == [ ] && callerComposition == null);
assert terminalServices == null || originalComparison == null || originalComparison ? serviceBindings;
assert originalComparison == null || (localContracts && localContractDependencies == [ ]
  && (sharedContract == null || sharedServiceBindings != null));
assert callerComposition == null || (localContracts
  && sharedContract == null && originalComparison == null
  && sourceCallRegions == null && sourceRegionGraphs == null
  && localContractDependencies == [ ]);
assert callerComposition == null || (
  builtins.isAttrs callerComposition
  && builtins.attrNames (builtins.removeAttrs callerComposition [ "previous" ])
    == [ "definition" "exactSlice" "supplier" ]
  && (!(callerComposition ? previous) || previousLocalContract == null));
if callerComposition != null then
let
  # Preparation is shared with sourceCheck and independent of boundary or
  # supplier changes. Conditional comparison never becomes qualification.
  preparation = import ./component-source-check.nix {
    inherit pkgs pythonEnv namePrefix targetId componentId interfacePackage sourcePackage;
  };
in import ./component-source-call-check.nix {
  inherit pkgs pythonEnv namePrefix targetId componentId interfacePackage sourcePackage;
  sourcePreparation = preparation.derivation;
  inherit (callerComposition) exactSlice supplier;
  contract = callerComposition.definition;
  previous = callerComposition.previous or previousLocalContract;
  unwind = localContractUnwind;
  timeoutSeconds = localContractTimeoutSeconds;
}
else
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-component-source${if localContracts then "-contract" else ""}-check";
  kind = "component-source-check";
  artifactName = "source-check.json";
  expectedFormat = "spaghetti-extractor-operator-work-status-v2";
  allowedStatuses = [ "complete" "incomplete" "violated" ];
  pythonModules = [ "spaghetti_extractor.operator.source_check" ];
  phaseRole = "operator";
  extraNativeBuildInputs = [ pkgs.stdenv.cc compiler ] ++ pkgs.lib.optional (localContracts || sourceCallRegions != null || sourceRegionGraphs != null) pkgs.cbmc
    ++ pkgs.lib.optional (sourceCallRegions != null || sourceRegionGraphs != null) pkgs.bubblewrap
    ++ pkgs.lib.optional (originalComparison != null) pkgs.z3;
  inputs = { interface_package = interfacePackage; source_package = sourcePackage; } // dependencyInputs
    // pkgs.lib.optionalAttrs (sharedContract != null) { relation_intent = sharedContract.relationIntent; }
    // pkgs.lib.optionalAttrs (sharedServiceBindings != null) { shared_service_bindings = sharedServiceBindings; }
    // pkgs.lib.optionalAttrs (sourceCallRegions != null) { source_call_regions = sourceCallRegions; }
    // pkgs.lib.optionalAttrs (sourceRegionGraphs != null) { source_region_graphs = sourceRegionGraphs; }
    // pkgs.lib.optionalAttrs (previousLocalContract != null) { previous_local_contract = previousLocalContract; }
    // pkgs.lib.optionalAttrs (terminalServices != null) { terminal_services = terminalServices; }
    // pkgs.lib.optionalAttrs (originalComparison != null && originalComparison ? serviceBindings) {
      original_service_bindings = originalComparison.serviceBindings;
    }
    // pkgs.lib.optionalAttrs (originalComparison != null) {
      original_exact_slice = originalComparison.exactSlice;
      original_binding = originalComparison.bindingIntent;
      original_domain = originalComparison.machineDomain;
    };
  program = ''
    from pathlib import Path
    import json, sys
    from spaghetti_extractor.operator.source_check import write_component_source_check
    timings = []
    write_component_source_check(
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        interface_package=inputs["interface_package"], source_package=inputs["source_package"],
        host_compiler=Path(${builtins.toJSON "${pkgs.stdenv.cc}/bin/cc"}),
        pe32_compiler=Path(${builtins.toJSON "${compiler}/bin/${compiler.targetPrefix}cc"}),
        cbmc=${if localContracts then "Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"})" else "None"},
        # GOTO locations retain cwd. Stage outside $out to keep Nix's output
        # self-reference rewrite from changing files after their hashes are bound.
        contract_workspace=${if localContracts then "Path('local-contract-work')" else "None"},
        contract_unwind=${builtins.toJSON localContractUnwind},
        contract_timeout_seconds=${builtins.toJSON localContractTimeoutSeconds},
        local_contract_dependencies=[${dependencyArguments}],
        previous_local_contract=${if previousLocalContract == null then "None" else ''inputs["previous_local_contract"]''},
        shared_contract=${if sharedContract == null then "None" else ''{
            "relation_intent": json.loads(inputs["relation_intent"].read_text()),
            "maximum_calls": ${builtins.toJSON sharedContract.maximumCalls},
            "maximum_memory_events": ${builtins.toJSON sharedContract.maximumMemoryEvents},
        }''},
        shared_service_bindings=${if sharedServiceBindings == null then "None" else ''[
            binding for entry in json.loads(inputs["shared_service_bindings"].read_text())
            for binding in entry["service_bindings"]
        ]''},
        original_comparison=${if originalComparison == null then "None" else ''{
            "exact_c_slice": inputs["original_exact_slice"],
            "binding_intent": json.loads(inputs["original_binding"].read_text()),
            "machine_domain": json.loads(inputs["original_domain"].read_text()),
            ${pkgs.lib.optionalString (originalComparison ? serviceBindings) ''
            "service_bindings": json.loads(inputs["original_service_bindings"].read_text()),
            ''}
        }''},
        terminal_services=${if terminalServices == null then "[]" else ''json.loads(inputs["terminal_services"].read_text())''},
        smt_solver=${if originalComparison == null then "None" else ''Path(${builtins.toJSON "${pkgs.z3}/bin/z3"})''},
        source_call_regions=${if sourceCallRegions == null then "[]" else ''json.loads(inputs["source_call_regions"].read_text())''},
        source_region_graphs=${if sourceRegionGraphs == null then "[]" else ''json.loads(inputs["source_region_graphs"].read_text())''},
        graph_workspace=${if sourceRegionGraphs == null then "None" else ''Path('source-region-graph-work')''},
        region_goto_cc=${if sourceCallRegions == null && sourceRegionGraphs == null then "None" else ''Path(${builtins.toJSON "${pkgs.cbmc}/bin/goto-cc"})''},
        region_workspace=${if sourceCallRegions == null then "None" else ''Path('source-call-region-work')''},
        timings=timings,
        out=output.parent,
    )
    # Measurements belong in the build log, outside content-addressed evidence.
    print(json.dumps({"source_check_timings": timings}), file=sys.stderr)
  '';
}
