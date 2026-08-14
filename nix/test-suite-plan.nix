{
  mode ? "full",
  manifest ? ./test-suite-manifest.json,
}:

let
  payload = builtins.fromJSON (builtins.readFile manifest);
  supportedFormat = "spaghetti-extractor-static-test-manifest-v1";
  modePayload = payload.modes.${mode} or null;
  shardById = builtins.listToAttrs (map (shard: {
    name = shard.id;
    value = shard;
  }) payload.shards);
  selectedShards =
    if modePayload == null then [ ]
    else map (id: shardById.${id}) modePayload.shard_ids;
in
assert payload.format == supportedFormat;
assert modePayload != null;
assert builtins.length selectedShards == builtins.length modePayload.shard_ids;
{
  inherit manifest payload;
  planPayload = {
    format = "spaghetti-extractor-test-suite-plan-v3";
    inherit mode;
    identity = modePayload.identity;
    selected_test_count = modePayload.selected_test_count;
    shards = selectedShards;
  };
}
