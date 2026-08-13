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
  invalidEnvironmentKeys = builtins.filter
    (key: builtins.match "[A-Za-z_][A-Za-z0-9_]*" key == null)
    (builtins.attrNames fixtureInputs.environment);
  environmentExports = lib.concatStringsSep "\n" (
    lib.mapAttrsToList
      (key: value: "export ${key}=${lib.escapeShellArg (toString value)}")
      fixtureInputs.environment
  );
  fileRows = map
    (relative: {
      path = relative;
      source = toString (builtins.path {
        path = repositoryRoot + "/${relative}";
        name = "spaghetti-test-input-${sanitize relative}";
      });
    })
    shard.files;
  fileRowsJson = builtins.toJSON fileRows;
  testPathsJson = builtins.toJSON shard.test_paths;
  memoryMiB =
    if shard.resource_class == "oracle" then 8192
    else if shard.resource_class == "large" then 3968
    else 1920;
in
assert invalidEnvironmentKeys == [ ];
pkgs.runCommand "spaghetti-extractor-test-${sanitize shard.id}" {
  nativeBuildInputs = [ pythonEnv ] ++ fixtureInputs.nativeBuildInputs;
  preferLocalBuild = shard.resource_class != "small";
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export SPAGHETTI_TEST_FIXTURES=${fixtureInputs.manifest}
  export SPAGHETTI_TEST_MEMORY_LIMIT_MIB=${toString memoryMiB}
  ${environmentExports}
  work="$TMPDIR/test-source"
  mkdir -p "$work"
  python - "$work" ${lib.escapeShellArg fileRowsJson} <<'PY'
  import json
  import pathlib
  import shutil
  import sys

  root = pathlib.Path(sys.argv[1])
  rows = sorted(json.loads(sys.argv[2]), key=lambda row: (row["path"].count("/"), row["path"]))
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
  import time
  import unittest

  paths = json.loads(sys.argv[1])
  loader = unittest.TestLoader()
  modules = [path.removesuffix(".py").replace("/", ".") for path in paths]
  suite = loader.loadTestsFromNames(modules)
  started = time.monotonic()
  result = unittest.TextTestRunner(verbosity=1).run(suite)
  elapsed_seconds = time.monotonic() - started
  status_rows = pathlib.Path("/proc/self/status").read_text(encoding="ascii").splitlines()
  peak_rss_kib = int(next(row.split()[1] for row in status_rows if row.startswith("VmHWM:")))
  memory_limit_mib = int(${builtins.toJSON (toString memoryMiB)})
  within_memory_limit = peak_rss_kib < memory_limit_mib * 1024
  report = {
      "format": "spaghetti-extractor-test-shard-report-v1",
      "status": "pass" if result.wasSuccessful() and within_memory_limit else "fail",
      "shard_id": ${builtins.toJSON shard.id},
      "input_sha256": ${builtins.toJSON shard.input_sha256},
      "test_modules": len(paths),
      "tests_run": result.testsRun,
      "skipped": len(result.skipped),
      "failures": len(result.failures),
      "errors": len(result.errors),
      "elapsed_seconds": round(elapsed_seconds, 6),
      "peak_rss_kib": peak_rss_kib,
      "memory_limit_mib": memory_limit_mib,
      "resource_class": ${builtins.toJSON shard.resource_class},
      "within_memory_limit": within_memory_limit,
  }
  pathlib.Path(sys.argv[2]).write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
  if not result.wasSuccessful() or not within_memory_limit:
      raise SystemExit(1)
  PY
''
