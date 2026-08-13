{ pkgs }:
let
  graph = import ./fixture.nix { inherit pkgs; };
  structuralPacks = builtins.attrValues graph.structuralPacks;
  dependencyPacks = builtins.attrValues graph.dependencyPacks;
  transitionShards = map (shard: shard.derivation) (
    builtins.attrValues graph.phases.transition.shards
  );
  sccShards = map (shard: shard.derivation) (builtins.attrValues graph.phases."scc-summarize".shards);
  dependencies =
    (map (pack: pack.derivation) (structuralPacks ++ dependencyPacks)) ++ transitionShards ++ sccShards;
  dependencyLinks = builtins.genList (index: {
    name = "dependency-${toString index}";
    path = builtins.elemAt dependencies index;
  }) (builtins.length dependencies);
in
graph.pkgs.linkFarm "authority-graph-v3-focused-check" (
  [
    {
      name = "metadata.json";
      path = graph.metadata;
    }
    {
      name = "composition";
      path = graph.phases.composition.derivation;
    }
  ]
  ++ dependencyLinks
)
