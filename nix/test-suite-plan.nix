{
  pkgs,
  pythonEnv ? pkgs.python3,
  repositoryRoot ? ../.,
  mode ? "full",
  changedPaths ? [ ],
  shardCount ? 32,
}:

let
  lib = pkgs.lib;
  planningSource = lib.fileset.toSource {
    root = repositoryRoot;
    fileset = lib.fileset.unions ((if mode == "smoke" then [
      (repositoryRoot + "/src")
      (repositoryRoot + "/tests/smoke")
      (repositoryRoot + "/flake.nix")
    ] else [
      (repositoryRoot + "/README.md")
      (repositoryRoot + "/REPOSITORY_MAP.md")
      (repositoryRoot + "/docs")
      (repositoryRoot + "/src")
      (repositoryRoot + "/tests")
      (lib.fileset.maybeMissing (repositoryRoot + "/fixtures"))
      (repositoryRoot + "/isa-catalogs")
      (repositoryRoot + "/nix")
      (repositoryRoot + "/profiles")
      (repositoryRoot + "/flake.nix")
      (repositoryRoot + "/flake.lock")
      (repositoryRoot + "/pyproject.toml")
      (repositoryRoot + "/tools")
    ]));
  };
  changedArguments = lib.concatMapStringsSep " "
    (path: "--changed ${lib.escapeShellArg path}")
    changedPaths;
in
assert builtins.elem mode [ "affected" "benchmark" "catalog" "full" "smoke" ];
assert builtins.isInt shardCount && shardCount >= 1 && shardCount <= 256;
pkgs.runCommand "spaghetti-extractor-test-suite-plan-${mode}" {
  nativeBuildInputs = [ pythonEnv ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  # This is the IFD bootstrap node: test-suite.nix reads suite-plan.json while
  # instantiating the shard DAG. Its output path must therefore be known before
  # realization. The generated shards and aggregate remain CA derivations.
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${planningSource}/src
  mkdir -p "$out"
  python -m spaghetti_extractor.testkit \
    --repository ${planningSource} \
    index --shards ${toString shardCount} \
    --out "$out/impact-index.json"
  ${if mode == "catalog" then ''
    python - "$out/impact-index.json" "$out/suite-plan.json" <<'PY'
    import sys
    from pathlib import Path

    from spaghetti_extractor.testkit.io import load_index, write_manifest
    from spaghetti_extractor.testkit.planning import build_suite_plan

    write_manifest(Path(sys.argv[2]), build_suite_plan(load_index(Path(sys.argv[1])), mode="catalog"))
    PY
  '' else ''
    python -m spaghetti_extractor.testkit \
      --repository ${planningSource} \
      plan ${mode} --index "$out/impact-index.json" \
      ${changedArguments} \
      --out "$out/suite-plan.json"
  ''}
''
