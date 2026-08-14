{ lib, catalogFile ? ../src/spaghetti_extractor/testkit/fixture_catalog.json }:

let
  payload = builtins.fromJSON (builtins.readFile catalogFile);
  exactAttrs = value: names:
    builtins.isAttrs value
    && builtins.attrNames value == builtins.sort builtins.lessThan names;
  normalize = row:
    assert exactAttrs row [ "capabilities" "description" "id" "nix_attribute" ];
    assert builtins.isString row.id && row.id != "";
    assert builtins.isString row.description && row.description != "";
    assert builtins.isList row.capabilities
      && lib.all (value: builtins.isString value && value != "") row.capabilities
      && row.capabilities == builtins.sort builtins.lessThan (lib.unique row.capabilities);
    assert builtins.isString row.nix_attribute
      && row.nix_attribute == "test-fixture-${row.id}";
    row;
  rows = map normalize payload.fixtures;
  ids = map (row: row.id) rows;
  metadata = builtins.listToAttrs (map (row: {
    name = row.id;
    value = row;
  }) rows);
  bind = realizations:
    let
      actual = builtins.sort builtins.lessThan (builtins.attrNames realizations);
      expected = builtins.sort builtins.lessThan ids;
    in
      assert actual == expected;
      lib.mapAttrs (id: realization:
        realization // {
          inherit (metadata.${id}) description capabilities;
          nixAttribute = metadata.${id}.nix_attribute;
        }) realizations;
  packageAttributes = fixtures:
    builtins.listToAttrs (map (id: {
      name = metadata.${id}.nix_attribute;
      value = fixtures.${id}.path;
    }) ids);
in
assert exactAttrs payload [ "fixtures" "format" ];
assert payload.format == "spaghetti-extractor-test-fixture-catalog-v1";
assert builtins.isList payload.fixtures;
assert ids == builtins.sort builtins.lessThan ids;
assert builtins.length ids == builtins.length (lib.unique ids);
{
  inherit bind ids metadata packageAttributes;
}
