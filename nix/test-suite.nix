{
  pkgs,
  pythonEnv,
  repositoryRoot ? ../.,
  mode ? "full",
  target ? null,
  changedPaths ? [ ],
  shardCount ? 32,
  strictPolicy ? true,
  fixtures ? { },
  environment ? { },
}:

let
  lib = pkgs.lib;
  fixtureSet = import ./test-suite-fixtures.nix {
    inherit pkgs fixtures environment;
  };
  plan = import ./test-suite-plan.nix {
    inherit
      pkgs
      pythonEnv
      repositoryRoot
      mode
      target
      changedPaths
      shardCount
      strictPolicy
      ;
  };
  planPayload = builtins.fromJSON (
    builtins.unsafeDiscardStringContext (builtins.readFile "${plan}/suite-plan.json")
  );
  shards = builtins.listToAttrs (map
    (shard: {
      name = shard.id;
      value = import ./test-suite-shard.nix {
        inherit pkgs pythonEnv repositoryRoot shard fixtureSet;
      };
    })
    planPayload.shards);
  shardRows = lib.mapAttrsToList (id: path: {
    inherit id;
    path = toString path;
  }) shards;
  aggregate = pkgs.runCommand "spaghetti-extractor-test-suite-${mode}" {
    nativeBuildInputs = [ pkgs.python3 ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    mkdir -p "$out"
    python - "$out/test-suite-report.json" \
      ${lib.escapeShellArg (builtins.toJSON shardRows)} \
      ${lib.escapeShellArg planPayload.identity} <<'PY'
    import json
    import pathlib
    import sys

    output = pathlib.Path(sys.argv[1])
    shards = json.loads(sys.argv[2])
    for row in shards:
        report = pathlib.Path(row["path"]) / "test-shard-report.json"
        payload = json.loads(report.read_text(encoding="utf-8"))
        if payload.get("status") != "pass" or payload.get("shard_id") != row["id"]:
            raise SystemExit(f"invalid or failed shard report: {row['id']}")
    output.write_text(
        json.dumps({
            "format": "spaghetti-extractor-test-suite-report-v1",
            "status": "pass",
            "plan_identity": sys.argv[3],
            "shards": [row["id"] for row in shards],
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY
  '';
in
{
  inherit aggregate fixtureSet plan planPayload shards;
  index = "${plan}/impact-index.json";
  suitePlan = "${plan}/suite-plan.json";
}
