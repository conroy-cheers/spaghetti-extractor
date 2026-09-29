# spaghetti-extractor-python-role: operator
{ pkgs, pythonEnv, namePrefix, targetId, componentId, interfacePackage, sourcePackage
, adapterFiles, includeFiles ? { }, linkFiles ? { }, runtimeFiles ? { }
, originalFiles, oracleKind ? "native-original", cases, observationFields
, assumptions, scope, platform ? "pe32", dependencies ? { }, inputDomain ? null, representation ? null, resourceChecks ? null, serviceCatalog ? null, serviceBridge ? null, requirements ? null, recursionGroups ? null, exportAdapters ? null, localSharedContract ? null
, privateHeaders ? null
}:
assert builtins.elem platform [ "host" "pe32" ];
let
  lib = pkgs.lib;
  compiler = if platform == "host" then pkgs.stdenv.cc else pkgs.pkgsCross.mingw32.stdenv.cc;
  wine = pkgs.wineWow64Packages.stableFull;
  inputsFor = role: files: builtins.listToAttrs (lib.imap0 (index: name:
    lib.nameValuePair "${role}_${toString index}" files.${name}) (builtins.attrNames files));
  argumentsFor = role: files: ''{name: inputs[${builtins.toJSON role} + "_" + str(index)] for index, name in enumerate(${builtins.toJSON (builtins.attrNames files)})}'';
  dependencyRows = lib.imap0 (index: id: { inherit id index; spec = dependencies.${id}; }) (builtins.attrNames dependencies);
  dependencyInputs = builtins.foldl' (inputs: row: inputs // {
    "dependency_${toString row.index}" = row.spec.package;
  } // inputsFor "dependency_adapters_${toString row.index}" (row.spec.adapterFiles or { })) { } dependencyRows;
  dependencyArguments = lib.concatMapStringsSep ", " (row: ''{
    "id": ${builtins.toJSON row.id}, "package": inputs["dependency_${toString row.index}"],
    "adapters": ${argumentsFor "dependency_adapters_${toString row.index}" (row.spec.adapterFiles or { })}
  }'') dependencyRows;
in
import ./ca-python-json-phase.nix {
  inherit pkgs pythonEnv;
  name = "${namePrefix}-${componentId}-comparison-package";
  kind = "component-comparison-package";
  artifactName = "comparison-plan.json";
  expectedFormat = "spaghetti-extractor-component-comparison-plan-v1";
  allowedStatuses = [ ];
  pythonModules = [ "spaghetti_extractor.components.comparison_package" ];
  phaseRole = "operator";
  inputs = { interface_package = interfacePackage; source_package = sourcePackage; }
    // inputsFor "adapters" adapterFiles // inputsFor "headers" includeFiles
    // inputsFor "link" linkFiles // inputsFor "runtime" runtimeFiles // dependencyInputs;
  program = ''
    from pathlib import Path
    import json
    from spaghetti_extractor.components.comparison_package import prepare_comparison_package
    prepare_comparison_package(
        interface_package=inputs["interface_package"], source_package=inputs["source_package"],
        target_id=${builtins.toJSON targetId}, component_id=${builtins.toJSON componentId},
        adapter_files=${argumentsFor "adapters" adapterFiles}, include_files=${argumentsFor "headers" includeFiles},
        link_files=${argumentsFor "link" linkFiles}, runtime_files=${argumentsFor "runtime" runtimeFiles},
        original_files=${builtins.toJSON originalFiles}, oracle_kind=${builtins.toJSON oracleKind},
        cases=${builtins.toJSON cases}, observation_fields=${builtins.toJSON observationFields},
        assumptions=${builtins.toJSON assumptions}, scope=${builtins.toJSON scope},
        dependencies=[${dependencyArguments}],
        requirements=json.loads(${builtins.toJSON (builtins.toJSON requirements)}),
        recursion_groups=json.loads(${builtins.toJSON (builtins.toJSON recursionGroups)}),
        export_adapters=json.loads(${builtins.toJSON (builtins.toJSON exportAdapters)}),
        local_shared_contract=json.loads(${builtins.toJSON (builtins.toJSON localSharedContract)}),
        service_bridge=json.loads(${builtins.toJSON (builtins.toJSON serviceBridge)}),
        service_catalog=json.loads(${builtins.toJSON (builtins.toJSON serviceCatalog)}),
        resource_checks=json.loads(${builtins.toJSON (builtins.toJSON resourceChecks)}),
        input_domain=${if inputDomain == null then "None" else builtins.toJSON inputDomain},
        representation=${if representation == null then "None" else builtins.toJSON representation},
        private_headers=${if privateHeaders == null then "None" else builtins.toJSON privateHeaders},
        compiler=Path(${builtins.toJSON "${compiler}/bin/${compiler.targetPrefix}cc"}),
        runner=${if platform == "host" then "None" else "Path(${builtins.toJSON "${wine}/bin/wine"})"},
        server=${if platform == "host" then "None" else "Path(${builtins.toJSON "${wine}/bin/wineserver"})"},
        output=output.parent,
    )
  '';
}
