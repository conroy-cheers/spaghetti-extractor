{
  pkgs,
  pythonEnv,
  repositoryRoot,
  shard,
  fixtureSet,
}:

let
  lib = pkgs.lib;
  sanitize = value: lib.replaceStrings [ "." "_" "/" ] [ "-" "-" "-" ] value;
  fixtureInputs = fixtureSet.forIds shard.fixtures;
  invalidEnvironmentKeys = builtins.filter (
    key: builtins.match "[A-Za-z_][A-Za-z0-9_]*" key == null
  ) (builtins.attrNames fixtureInputs.environment);
  environmentExports = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      key: value: "export ${key}=${lib.escapeShellArg (toString value)}"
    ) fixtureInputs.environment
  );
  fileRows = map (relative: {
    path = relative;
    source = toString (
      builtins.path {
        path = repositoryRoot + "/${relative}";
        name = "spaghetti-test-input-${sanitize relative}";
      }
    );
  }) shard.files;
  fileRowsJson = builtins.toJSON fileRows;
  testPathsJson = builtins.toJSON shard.test_paths;
in
assert invalidEnvironmentKeys == [ ];
pkgs.runCommand "spaghetti-extractor-test-${sanitize shard.id}"
  {
    nativeBuildInputs = [ pythonEnv ] ++ fixtureInputs.nativeBuildInputs;
    preferLocalBuild = shard.resource_class != "small";
    allowSubstitutes = true;
    __contentAddressed = true;
    sourceFileRows = fileRowsJson;
    passAsFile = [ "sourceFileRows" ];
  }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export SPAGHETTI_TEST_FIXTURES=${fixtureInputs.manifest}
    ${environmentExports}
    work="$TMPDIR/test-source"
    mkdir -p "$work"
    # Large smoke closures can exceed Linux's per-argument size limit. Keep
    # the complete bound inventory in a Nix-provided file instead of argv.
    python - "$work" "$sourceFileRowsPath" <<'PY'
    import json
    import pathlib
    import shutil
    import sys

    root = pathlib.Path(sys.argv[1])
    rows = sorted(json.loads(pathlib.Path(sys.argv[2]).read_text()), key=lambda row: (row["path"].count("/"), row["path"]))
    for row in rows:
        destination = root / row["path"]
        source = pathlib.Path(row["source"])
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    PY
    export PYTHONPATH="$work/src:$work/tests:$work"
    cd "$work"
    mkdir -p "$out"
    python - ${lib.escapeShellArg testPathsJson} "$out/test-shard-report.json" <<'PY'
    import json
    import pathlib
    import sys
    import unittest

    paths = json.loads(sys.argv[1])
    loader = unittest.TestLoader()
    modules = [path.removesuffix(".py").replace("/", ".") for path in paths]
    suite = loader.loadTestsFromNames(modules)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    status_rows = pathlib.Path("/proc/self/status").read_text(encoding="ascii").splitlines()
    peak_rss_kib = int(next(row.split()[1] for row in status_rows if row.startswith("VmHWM:")))
    # Measurements vary between identical builds. Keep them in the build log,
    # outside the content-addressed correctness report.
    print(json.dumps({
        "shard_id": ${builtins.toJSON shard.id},
        "peak_rss_kib": peak_rss_kib,
    }, sort_keys=True), file=sys.stderr)
    report = {
        "format": "spaghetti-extractor-test-shard-report-v1",
        "status": "pass" if result.wasSuccessful() else "fail",
        "shard_id": ${builtins.toJSON shard.id},
        "input_sha256": ${builtins.toJSON shard.input_sha256},
        "test_modules": len(paths),
        "tests_run": result.testsRun,
        "skipped": len(result.skipped),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "resource_class": ${builtins.toJSON shard.resource_class},
    }
    pathlib.Path(sys.argv[2]).write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    if not result.wasSuccessful():
        raise SystemExit(1)
    PY
  ''
