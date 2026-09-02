{
  pkgs,
  pythonEnv,
  repositoryRoot ? ../.,
  mode ? "full",
  manifest ? ./generated/test-suite-manifest.json,
  planPayload ? null,
  # Reviewed post-semantic-module clean-cut inventory. Lower it only when a
  # change deliberately removes or consolidates tests for retired behavior.
  minimumTests ? if mode == "full" then 1196 else if mode == "affected" then 0 else 1,
  fixtures ? { },
  environment ? { },
}:

let
  lib = pkgs.lib;
  fixtureSet = import ./test-suite-fixtures.nix {
    inherit pkgs fixtures environment;
  };
  staticPlan = import ./test-suite-plan.nix { inherit mode manifest; };
  selectedPlan = if planPayload == null then staticPlan.planPayload else planPayload;
  shards = builtins.listToAttrs (map
    (shard: {
      name = shard.id;
      value = import ./test-suite-shard.nix {
        inherit pkgs pythonEnv repositoryRoot shard fixtureSet;
      };
    })
    selectedPlan.shards);
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
      ${lib.escapeShellArg selectedPlan.identity} <<'PY'
    import json
    import pathlib
    import sys

    output = pathlib.Path(sys.argv[1])
    shards = json.loads(sys.argv[2])
    tests_run = 0
    skipped = 0
    for row in shards:
        report = pathlib.Path(row["path"]) / "test-shard-report.json"
        payload = json.loads(report.read_text(encoding="utf-8"))
        if payload.get("status") != "pass" or payload.get("shard_id") != row["id"]:
            raise SystemExit(f"invalid or failed shard report: {row['id']}")
        tests_run += payload.get("tests_run", 0)
        skipped += payload.get("skipped", 0)
    minimum = ${toString minimumTests}
    if tests_run < minimum:
        raise SystemExit(f"test inventory regressed: expected at least {minimum}, observed {tests_run}")
    output.write_text(
        json.dumps({
            "format": "spaghetti-extractor-test-suite-report-v1",
            "status": "pass",
            "plan_identity": sys.argv[3],
            "shards": [row["id"] for row in shards],
            "tests_run": tests_run,
            "skipped": skipped,
            "minimum_tests": minimum,
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY
  '';
in
{
  inherit aggregate fixtureSet shards;
  plan = staticPlan;
  planPayload = selectedPlan;
  index = manifest;
  suitePlan = manifest;
}
