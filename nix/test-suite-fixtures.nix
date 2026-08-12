{
  pkgs,
  fixtures ? { },
  environment ? { },
}:

let
  lib = pkgs.lib;
  normalize = id: value:
    let
      record = if lib.isDerivation value || builtins.isPath value then { path = value; } else value;
    in
    assert builtins.isAttrs record;
    assert record ? path;
    {
      inherit id;
      path = toString record.path;
      nativeBuildInputs = record.nativeBuildInputs or [ ];
      environment = record.environment or { };
      description = record.description or id;
      capabilities = record.capabilities or [ ];
      nixAttribute = record.nixAttribute or "test-fixture-${id}";
    };
  records = lib.mapAttrsToList normalize fixtures;
  duplicateEnvironment =
    lib.foldl'
      (state: record:
        lib.foldlAttrs
          (inner: key: value:
            if builtins.hasAttr key inner && toString inner.${key} != toString value then
              throw "test fixture environment variable ${key} has conflicting values"
            else
              inner // { "${key}" = value; })
          state
          record.environment)
      environment
      records;
  renderedEnvironment = lib.mapAttrs (_: value: toString value) duplicateEnvironment;
  fixturePaths = builtins.listToAttrs (map (record: {
    name = record.id;
    value = record.path;
  }) records);
  manifest = pkgs.writeText "spaghetti-extractor-test-fixtures.json" (builtins.toJSON {
    format = "spaghetti-extractor-test-fixtures-v1";
    fixtures = fixturePaths;
    definitions = builtins.listToAttrs (map (record: {
      name = record.id;
      value = {
        inherit (record) description capabilities;
        nix_attribute = record.nixAttribute;
      };
    }) records);
  });
  byId = builtins.listToAttrs (map (record: {
    name = record.id;
    value = record;
  }) records);
  forIds = ids:
    let
      missing = builtins.filter (id: !(builtins.hasAttr id byId)) ids;
      selected = map (id: byId.${id}) ids;
    in
    if missing != [ ] then
      throw (
        "test shard requires unavailable fixtures: ${lib.concatStringsSep ", " missing}; "
        + "provide them through the fixtures argument to nix/test-suite.nix"
      )
    else let
      selectedPaths = builtins.listToAttrs (map (record: {
        name = record.id;
        value = record.path;
      }) selected);
      selectedDefinitions = builtins.listToAttrs (map (record: {
        name = record.id;
        value = {
          inherit (record) description capabilities;
          nix_attribute = record.nixAttribute;
        };
      }) selected);
    in {
      nativeBuildInputs = lib.unique (lib.concatMap (record: record.nativeBuildInputs) selected);
      manifest = pkgs.writeText "spaghetti-extractor-selected-test-fixtures.json" (builtins.toJSON {
        format = "spaghetti-extractor-test-fixtures-v1";
        fixtures = selectedPaths;
        definitions = selectedDefinitions;
      });
      environment =
        lib.foldl'
          (state: record:
            lib.foldlAttrs
              (inner: key: value:
                if builtins.hasAttr key inner && toString inner.${key} != toString value then
                  throw "selected test fixtures disagree on environment variable ${key}"
                else
                  inner // { "${key}" = value; })
              state
              record.environment)
          environment
          selected;
    };
in
{
  inherit manifest forIds;
  fixtureIds = builtins.sort builtins.lessThan (builtins.attrNames byId);
  environment = renderedEnvironment;
}
