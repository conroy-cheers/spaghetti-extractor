{
  pkgs,
  pythonEnv,
  pythonSource,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  asJsonPath =
    name: value:
    if builtins.isAttrs value || builtins.isList value then
      builtins.toFile name (builtins.toJSON value)
    else
      value;
  commonEnvironment = ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${pythonSource}/src
    mkdir -p "$out"
  '';

  mkStructural =
    {
      name,
      inventory,
      schedule ? null,
      scheduleBucketCount ? 4,
      resourceClasses,
    }:
    let
      inventoryPath = asJsonPath "${name}-inventory.json" inventory;
      derivation = pkgs.runCommand name (
        {
          nativeBuildInputs = [ pythonEnv ];
          preferLocalBuild = false;
          allowSubstitutes = true;
        }
        // caAttrs
      ) ''
        ${commonEnvironment}
        ${python} -m spaghetti_extractor.authority.planning structural \
          --inventory ${lib.escapeShellArg (toString inventoryPath)} \
          --schedule ${if schedule == null then "-" else lib.escapeShellArg (toString schedule)} \
          --bucket-count ${toString scheduleBucketCount} \
          --resource-classes ${lib.escapeShellArg (builtins.toJSON resourceClasses)} \
          --output "$out"
      '';
    in
    {
      inherit derivation;
      manifest = "${derivation}/schedule.json";
      validation = "${derivation}/validation.json";
      packIndex = "${derivation}/pack-index.json";
      packsDirectory = "${derivation}/packs";
    };

  mkDependency =
    {
      name,
      structuralSchedule,
      recordEdges,
      schedule ? null,
      requireStructuralCoverage ? true,
      scheduleBucketCount ? 4,
    }:
    let
      recordEdgesPath = asJsonPath "${name}-record-edges.json" recordEdges;
      derivation = pkgs.runCommand name (
        {
          nativeBuildInputs = [ pythonEnv ];
          preferLocalBuild = false;
          allowSubstitutes = true;
        }
        // caAttrs
      ) ''
        ${commonEnvironment}
        ${python} -m spaghetti_extractor.authority.planning dependency \
          --structural-schedule ${lib.escapeShellArg (toString structuralSchedule)} \
          --record-edges ${lib.escapeShellArg (toString recordEdgesPath)} \
          --schedule ${if schedule == null then "-" else lib.escapeShellArg (toString schedule)} \
          --bucket-count ${toString scheduleBucketCount} \
          --require-structural-coverage ${if requireStructuralCoverage then "1" else "0"} \
          --output "$out"
      '';
    in
    {
      inherit derivation;
      manifest = "${derivation}/schedule.json";
      validation = "${derivation}/validation.json";
      packIndex = "${derivation}/pack-index.json";
      packsDirectory = "${derivation}/packs";
    };
in
{
  inherit mkDependency mkStructural;
}
