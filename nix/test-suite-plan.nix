{
  pkgs,
  pythonEnv ? pkgs.python3,
  repositoryRoot ? ../.,
  mode ? "full",
  target ? null,
  changedPaths ? [ ],
  shardCount ? 32,
  strictPolicy ? true,
}:

let
  lib = pkgs.lib;
  planningSource = lib.fileset.toSource {
    root = repositoryRoot;
    fileset = lib.fileset.unions [
      (repositoryRoot + "/README.md")
      (repositoryRoot + "/REPOSITORY_MAP.md")
      (repositoryRoot + "/docs")
      (repositoryRoot + "/src")
      (repositoryRoot + "/tests")
      (repositoryRoot + "/fixtures")
      (repositoryRoot + "/isa-catalogs")
      (repositoryRoot + "/nix")
      (repositoryRoot + "/profiles")
      (repositoryRoot + "/targets")
      (repositoryRoot + "/flake.nix")
      (repositoryRoot + "/pyproject.toml")
      (repositoryRoot + "/tools")
    ];
  };
  changedArguments = lib.concatMapStringsSep " "
    (path: "--changed ${lib.escapeShellArg path}")
    changedPaths;
  targetArgument = lib.optionalString (target != null) "--target ${lib.escapeShellArg target}";
  policyArgument = lib.optionalString (!strictPolicy) "--allow-legacy-policy";
in
assert builtins.elem mode [ "affected" "benchmark" "full" "smoke" "target" ];
assert builtins.isInt shardCount && shardCount >= 1 && shardCount <= 256;
pkgs.runCommand "spaghetti-extractor-test-suite-plan-${mode}" {
  nativeBuildInputs = [ pythonEnv ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${planningSource}/src
  mkdir -p "$out"
  python -m spaghetti_extractor.testkit \
    --repository ${planningSource} \
    index --shards ${toString shardCount} ${policyArgument} \
    --out "$out/impact-index.json"
  python -m spaghetti_extractor.testkit \
    --repository ${planningSource} \
    plan ${mode} --index "$out/impact-index.json" \
    ${targetArgument} ${changedArguments} \
    --out "$out/suite-plan.json"
''
